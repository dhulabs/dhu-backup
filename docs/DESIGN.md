# Design and threat model

This is the reasoning behind the mechanism. The operator's guide is
[`../src/README.md`](../src/README.md); the recorded execution evidence is
[`PROOFS.md`](PROOFS.md); the ceiling is [`LIMITS.md`](LIMITS.md).

## The adversary

**An LLM agent running as the owner.** Same uid, same groups, same filesystem
reach. Not malicious — incompetent at scale, and demonstrably willing to edit
its own guard and then run the edited version. The failure this project exists
for was exactly that shape: an agent mutation-testing its own code unguarded a
recursive delete and destroyed the git worktree it was running in.

Two consequences the first draft of this design did not account for.

**The adversary runs as the owner, so anything the owner can delete, it can
delete.** That includes filesystem snapshots and any user-domain scheduled job.
It was verified by execution rather than assumed: creating *and* deleting an
APFS local snapshot both succeed as an ordinary admin account, with no sudo and
no prompt, and the OS thins those snapshots at roughly 24 hours rather than
holding them for a month. Sources claiming the delete needs sudo are wrong for
an admin account.

**Write confinement is not read confinement.** Where an agent runs inside a
sandbox at all, the sandbox typically limits where it can *write* while allowing
broad reads. So any store that is readable is readable by every lane, and the
confidentiality burden cannot be carried by permissions on the store. It has to
be carried by what the daemon admits into the store in the first place.

**What is defended:** deletion, truncation and overwrite of uncommitted files by
an agent, in the locations agents write.

**What is not defended,** each a deliberate boundary: root, the human owner, the
installer as a one-time trust transfer, and anything whose whole lifetime is
shorter than the capture latency. [`LIMITS.md`](LIMITS.md) is the full list.

## Why a second principal is required

Unix permissions cannot distinguish you from an agent running as you. That is
not a gap in any particular product; it is the shape of the problem. Every
existing net — hourly backup software, filesystem snapshots, editor local
history, cloud-sync version history — authenticates the *account*, and the agent
holds the account.

So the copy has to belong to someone else. The only other principal available
without inventing a service account is root, and reaching root requires one
deliberate, human, one-time install. Everything else in this design follows from
that single decision:

- The store is root-owned. Directories are 0755 and files 0444, so an agent can
  **read** it with no sudo and no human step. Unlink and rename need write
  permission on the *parent* directory, which no agent has at any level, so the
  kernel refuses every delete without the daemon checking anything.
- The daemon **pulls**. Agents never push, so there is no write path into the
  store that could be revoked, misused or forgotten.
- The service is a system-domain job — a LaunchDaemon on macOS, a systemd
  *system* unit on Linux. A user LaunchAgent's plist lives in a world-writable
  directory the adversary owns, and the job runs as the adversary. A
  `systemd --user` unit has the same defect. Both were considered and both are
  a direct failure of the guarantee.
- Nothing in the protected tree is on the protection path. An earlier draft
  proposed triggering capture from a process inside the repo being protected;
  an agent editing that file silently disables the protection, unreported.

## The walk

A root process reading a directory the adversary writes is a confused deputy by
default. The design removes the deputy's discretion rather than teaching it
rules.

The walk descends with **directory file descriptors**. Each directory is opened
`O_RDONLY|O_DIRECTORY|O_NOFOLLOW` relative to its parent's fd. Each file is
opened by **basename only**, relative to its directory's fd, with `O_NOFOLLOW`
and `O_NONBLOCK` — the second because a FIFO in the tree would otherwise hang
the open forever, which was found by running it, not by reading it. Every
admission decision is then made on the `fstat` of the **open fd**, never on a
path.

No path string is ever re-resolved, so there is no window in which the adversary
can swap a checked name for a symlink or a hard link. "Resolve, then check" is
the race; this design never resolves.

### Per-file admission

`classify_entry` is a pure function of a stat-like object, a relative path and a
limits tuple. A file is copied only if it is:

| condition | why |
|---|---|
| a regular file | a device, socket or FIFO is not work in progress |
| `st_nlink == 1` | see below |
| `st_uid == <configured owner>` | see below |
| not setuid and not setgid | never propagate a privilege bit into the mirror |
| at most 1 MiB | the population is text; a large file is a build artifact |
| outside the excluded directories and extensions | matched *before* descending |

Everything else is a refusal carrying a reason, counted in the heartbeat under
that reason and logged once per file per reason per process. Logging every
refusal every cycle produced tens of megabytes of root-owned log a day on the
volume whose free space is what stops the daemon.

**`st_nlink == 1` and `st_uid == owner` are independently load-bearing**, and
both are tested separately. On macOS, `ln /etc/sudoers ./notes.md` **succeeds**
as an unprivileged user — an innocent name over a root-owned inode the user
cannot read but a root daemon can. With a readable store that is the difference
between a mirror and a file-disclosure oracle. The owner check refuses it
because root owns the inode; the link check refuses it because a hard link in a
source tree is anomalous. Neither subsumes the other: the owner check alone
would admit a link to another of the owner's own files, and the link check alone
would admit a root-owned file that happened to have one link.

Linux sets `fs.protected_hardlinks` to 1 by default, which blocks the primitive
before the daemon sees it. macOS has no such control, and the daemon's own guard
is proven separately there and against a link the Linux kernel does permit.

### The watch list

The watched roots come from one root-owned file, written by the installer from
its `--watch` arguments, and from nowhere else. Never from a database row, an
environment variable, or anything an agent writes.

A draft proposed sourcing them from a task record's persisted scratch
directory. Agents write those records. A path chosen by the adversary and read
by a root process that copies what it finds is a general exfiltration primitive:
point it at `~/.ssh`, or at `/`, and read the result out of the mirror. The
record is authoritative about where a task *ran*, not about what root should
*read*.

Every component of every watch root is `lstat`ed on every scan and must be a
real directory owned by root or the configured owner. A refused root is loud,
counted, and — if it leaves no usable root at all — reported as `unprotected`
rather than `ok`.

## The version key is the daemon's own clock

`version_key` takes the daemon's `time.time_ns()` at copy time and the content
hash. It takes **no mtime parameter**, and that signature is the proof rather
than a comment about it.

Source mtime is change-detection input only, never authority over anything the
daemon deletes. `touch -t 197001020304 f` backdates a file by twenty thousand
days in one command. If either the version tag or a retention decision derived
from the source file's mtime, an agent wanting a version gone would set the
mtime to 1970, wait for the copy, and let the next prune pass delete it as
ancient — a delete path into the mirror, driven entirely from a tree the agent
writes, using a coreutil.

Ordering within the rolling version window uses the same capture clock, so
backdating cannot choose which version the window discards either.

Change detection is keyed on the **relative path**, not on `(size, mtime)`
alone. `mv` preserves mtime, so a poller keyed on mtime treats a file moved into
the tree as already-seen and never copies it. A path with no index record is
hashed and copied unconditionally, whatever its age.

## Store layout, and why the basename is the leaf

```
<tree>/<root-id>/<slug>/<relpath-dir>/@<capture_ns>-<sha256[:12]>/<ORIGINAL BASENAME>
```

**The version is a DIRECTORY and the original basename is the LEAF.** This is
the single most consequential layout decision in the project.

The draft put the source filename in a *directory* segment and a hash in the
*basename*. Name-based read guards — the kind agents already run under — match
on the basename. Executed against a real one, the draft layout returned `null`
for a mirrored `.env.local`, for `id_rsa` and for `server.pem`: the mirror
laundered every one of them past the guard that was supposed to stop an agent
reading them. Under this layout the same guard returns the correct refusal for
each, and still returns `null` for ordinary source files.

So every existing name-based guard works on a mirror path **unchanged**, with no
new denylist for anyone to maintain and no second place for the two lists to
drift apart.

`<slug>` is the expanded watch root's basename plus a hash of its full path. A
glob root expands to many directories, and two of them both holding `lib/x.ts`
would otherwise share one version history. The absolute path for each slug lives
in `var/roots/`, outside the mirrored trees, so no captured filename can collide
with a marker.

Nothing is ever overwritten. A version is created with `os.link()`, which fails
`EEXIST` rather than clobbering. Append-only is enforced by the kernel.

One consequence of this layout is easy to get wrong, and the first two releases
did: the version directories of **every file in one source directory are
siblings** under the same `<relpath-dir>`, and only the leaf says which file a
version belongs to. A rule that lists a `<relpath-dir>` without asking about the
leaf is a rule about the directory, not the path. The rolling window and the
age prune both did that in v0.1.0 and v0.2.0 — the window rolled the only
versions of a busy file's siblings, and the prune would have kept one version
per directory ([PROOFS §6](PROOFS.md#6-the-independent-review-of-2026-09-11)).
Every retention decision is now keyed on `(relpath-dir, leaf)`, and the daemon
forgets any indexed path the store no longer holds a version of, so it is
captured again on the next scan.

The walk also refuses two shapes at the source, before they can reach the
store: an entry whose **name parses as a version key**, which would otherwise
sit in the store's own namespace and be listed by the reader and the retention
plans as a version of its siblings; and a name that is **not valid UTF-8**,
which neither the sqlite index nor the log can take — one such name, handed
over surrogate-escaped by the OS, aborted every scan of its whole root until it
was removed. Both are ordinary refusals now, counted under their own reasons.

## The split store and the credential predicate

`store/` is 0755 and agent-readable. `vault/` is 0700 and root-only. One
predicate, evaluated at copy time on the **original** relative path, decides
which half a file goes to.

Both halves are captured, so a deleted `.env.local` is still recoverable by the
owner with sudo. It simply never becomes agent-readable. An earlier build
refused credential files outright, which chose "no agent can read it" by making
it unrecoverable for anyone.

The predicate's source of truth is `src/credential_patterns.py`: one declarative
table of 36 rules in five kinds, each carrying a one-line rationale, at least two
example paths it must **refuse**, and at least one it must **admit**. The
admitted example is the half that bounds strictness — without it, "refuse
everything" would satisfy every other test in the suite.

The population that proves the rules is derived from the rules' own regexes by
`src/tools/derive-own-fixture.py`, which expands each pattern into every string
it can match and probes each in four shapes. The expander **raises** on any
construct it cannot model; a silent "could not expand" would shrink the
population back to whatever happened to be expressible, and the tests would
still print OK.

**The predicate is name-based and stays that way.** The daemon must never read a
file's content to decide where it goes. A content heuristic that guesses "this
is not a secret" puts the file in the agent-readable half, which is precisely
the laundering the split store exists to prevent. The failure directions are not
symmetric: a work file wrongly vaulted costs one `sudo`, and a secret wrongly
placed in `store/` is unrecoverable.

`etc/vault-extra.conf` lets an operator add basename globs. It can only **add**
refusals, and that is the type rather than a convention — the routing function
ORs the extension into the base predicate, so no value of that file can make a
path readable which the patterns refuse. A malformed line is refused, logged and
counted, never dropped silently: an operator who believes a glob is in force and
is wrong has a false sense of protection.

## The five budgets

Two of them stop the whole daemon. Three of them skip one entry. The split is
the point: a per-file condition must never be able to switch the protection off.

| limit | default | on hit |
|---|---|---|
| `max_store_bytes` | 5 GiB | **DEGRADED** — capture stops, everything held is kept |
| `min_free_bytes` | 10 GiB | **DEGRADED** — stop before the volume dies, not just the store |
| `max_file_bytes` | 1 MiB | skip this file, count it |
| `max_versions_per_path` | 200 | **roll the window** — drop that path's oldest, write the new one |
| `max_new_files_per_scan` | 2000 | throttle; the rest wait for the next scan |

Plus `max_watch_roots` (64), with a logged refusal when it binds. A silently
dropped root is a silently unprotected agent, which an agent discovers only when
its recovery comes back empty.

An adversary does not need a delete path into the store to hurt it. It needs a
write path into the watched tree, and it has one by construction. Event-driven
capture makes that worse, not better: a loop rewriting one file produces a
version per save. The budgets are the answer, and the failure shape matters more
than the exact numbers.

### A warning is a STATE, not an annotation on `ok`

The two store-wide budgets end capture. That is the design, and DEGRADED never
self-healing is the guarantee rather than a defect. Capture ending with no
notice is the defect, and it was live: the volume this was written on sat at
14.1 GiB free against a 10 GiB floor, reporting `ok`, and would have reported
`ok` until the cycle that stopped it and `degraded` for ever after.

The fix could have been a field — `ok` plus a `close_to_budget: true` flag. It
is a state instead, for the reason the rest of this design keeps reaching for:
a reader that has to remember to check a second field is a reader that reports
`ok`. `ok` now means "capturing, comfortably" and `warning` means "capturing,
but about to stop", and no code path can produce one while meaning the other.

`budget_warning` is a pure function beside `budget_decision`, and the
relationship between them is structural rather than arithmetic. It asks
`budget_decision` whether this store size and free space are ALREADY a stop and
returns None if they are, so the two can never describe the same condition
twice. Keeping two sets of thresholds in sync by hand would be a rule someone
has to remember every time one of them moves; deferring to the real decision
function is a property, and the property is asserted over a fabricated grid.

It is not a gate. Nothing consults it to decide whether to write, and it returns
a record or None rather than any of the verdict types, so it cannot be dropped
into a decision site by accident. It is a REPORT, which is the half of the
guarantee this project keeps finding it had underbuilt.

Two consequences worth stating. An unrecognised heartbeat label is
`unreadable-heartbeat` and never `ok`, which is what made adding a fifth state
safe: an old helper reading a new daemon fails loudly rather than reporting
health it cannot interpret. And the installer ACCEPTS `warning` rather than
exiting 1 on it, because a fresh install on a nearly-full volume is working, and
refusing to finish an install that works teaches people to ignore the exit code
— but it prints the warning in place of the OK line, never beside it.

### DEGRADED never self-heals

"Store full, prune the oldest to make room" is the tempting behaviour and it is
forbidden. It silently converts a retention guarantee into a best-effort cache
whose only symptom is a file that is not there when you need it. On a store-wide
budget the daemon stops capturing, logs an ERROR every cycle, writes `degraded`
plus the reason and the counts to the heartbeat, keeps everything already held,
and stays degraded across restarts. Recovery is a human decision: free space or
raise the budget, remove the state file, restart the daemon.

The decision type has no "prune to make room" case, so the code cannot express
it. That is deliberate — this is a place where a comment would have decayed.

An earlier build degraded on the *first* failure to measure free space, under a
fabricated reason. A one-off measurement failure now costs a cycle and says so;
three consecutive failures degrade it.

### Why the version window rolls rather than skips

`max_versions_per_path` was first implemented as a skip: at the cap, stop
writing new versions of that path. That inverted the guarantee for exactly the
file the founding incident lost. At a 15-second interval an actively edited file
reaches 200 versions in under an hour, and from that moment its **newest**
content was the one thing not in the store — reported only as a counter nobody
reads mid-session.

It now rolls: the daemon prunes that path's oldest versions down to `cap - 1`
and writes the new one, through the same executor as age pruning, so retention
stays daemon-only. The newest version of a path is never in either plan —
and "path" means the file, `(relpath-dir, leaf)`, not the directory its versions
share with its siblings' (see the layout section above).

The accepted cost is that an agent can push its own older versions of **one**
file out of the store by rewriting it 200 times. That is worse than nothing and
much better than dropping the newest content of the busiest file. The disk bound
is unchanged: a path is still bounded at `max_versions_per_path x
max_file_bytes`.

Age pruning has the same asymmetry and the same answer. Naive age-pruning
deletes the only copy of a stable file — one written 31 days ago and never
touched has exactly one version — so the guarantee would invert for precisely
the files most worth keeping. **The newest version of a path is never pruned.**

## Why an exclusion list is acceptable and a "make this readable" file is not

`EXCLUDED_DIR_NAMES` is a literal, for the reason above: running `git` as root
inside an agent-writable repo executes agent-controllable hooks. But an operator
with their own multi-gigabyte directory inside a watch root had no way to skip
it, and the answer to that is `etc/exclude.conf` — one directory-name glob per
line, matched on the basename during the walk.

This is the first config in the tree that can only REMOVE protection, and it
needs its own argument rather than inheriting `vault-extra.conf`'s. That file
ORs into a predicate and can only ADD refusals; the type cannot express
"un-vault this", so no value of it makes a path readable which the patterns
refuse. `exclude.conf` has no such comfort: every line in it is protection
switched off.

What makes it acceptable is not that the operator asked for it. It is that the
file is root-owned 0644 in the same `etc/` as `watchlist.conf`, which already
decides what is protected AT ALL. Anything that could write `exclude.conf` could
rewrite the watch list and un-protect everything in one line, so the new file
adds no reach an adversary did not already have — and neither is writable by the
owner's account, which is the account the adversary holds. The reach is
unchanged; only the ergonomics are new.

The same argument is what REFUSES the file people ask for next. A "make this
path readable" file — an un-vault list, a rule that moves a credential-class
path from `vault/` to `store/` — would add reach that no existing root-owned
file has. Nothing an operator can write today can make a secret agent-readable,
and the split store's whole value is that the failure directions are not
symmetric: a work file wrongly vaulted costs one `sudo`, a secret wrongly placed
in `store/` is unrecoverable. "The operator asked for it" does not close that
gap, because the operator is not the adversary the file would arm.

Three details follow from "only ever removes". The match is CASE-SENSITIVE,
deliberately the opposite of the vault extension's, because a loose match there
protects more and a loose match here protects less. It lives in the WALK and not
in `classify_entry`, because saving the descent is the entire point and because
a path reaching admission from anywhere else should be admitted rather than
excluded. And a wildcard-only line is refused: `*` names no directory in
particular, it is "stop protecting everything" spelled as a rule about names,
and an operator who wants that removes the watch root in the file that says what
is protected.

Directories skipped by an operator glob are counted under
`walk-excluded-dir-operator`, distinct from the built-in `walk-excluded-dir`.
Merged, an operator could not tell "my rule is working" from "my rule never
matched" — and this project's recurring failure is exactly that shape, a status
that cannot distinguish reported from missing.

## Reporting is part of the guarantee

`var/state.json` carries counts and states and **never a path**, so it is safe
to read anywhere. `state` is one of five:

- **ok** — capturing, comfortably
- **warning** — capturing normally, and close to a store-wide budget that will
  stop it. Never merged into `ok`, and ordered below the three failures below:
  a daemon that has stopped is not "about to stop"
- **degraded** — a store-wide budget stopped capture
- **unprotected** — the daemon is healthy and has no usable watch root, so
  nothing is being protected
- **scan-failed** — the daemon is running and every scan is throwing

The helper's `health` verdict uses these five plus three of its own for what the
daemon cannot say about itself — `stale` (no scan for five minutes),
`no-heartbeat` and `unreadable-heartbeat` — which is the eight-verdict
vocabulary the README counts. The daemon never writes those three.

The first build collapsed the last two into `ok` with a zero file count, and a
boot banner then announced that uncommitted work was protected over an empty
store. Three fields report the machinery rather than the capture: `trigger`
(`kqueue`, `inotify` or `poll-only` — a chosen trigger that failed to start
reports `poll-only`, never its own name), `trigger_watch_failures`, and
`interpreter_root_owned`.

The unprivileged helper prints that verdict before every answer, so "no
versions" is never mistaken for "capture stopped two days ago". In `--json` mode
it becomes a `health` field of the object rather than a prose banner, because a
banner ahead of JSON would make every answer unparseable and callers would learn
to suppress it.

The self-announcing lookup has six statuses, and `store-unavailable` is
deliberately **not** a kind of `not-held`. "I looked and there is nothing" and
"I could not look" are opposite claims with different exit codes, and an agent
that collapses them abandons work sitting on disk.

## What the recovery side must never become

The helper runs **as the agent**. It is unprivileged, reads a world-readable
store, and writes only where the caller could already write. It therefore cannot
be a write or delete path into the mirror, and the kernel enforces that rather
than the helper's code.

The corollary is worth stating plainly: **nothing about the guarantee depends on
the helper.** An agent can bypass it entirely with `ls` and `cp`, and that is
fine. It exists for ergonomics, so it should never contain a check that matters.

Three "improvements" would each rebuild a privileged path the agent can steer,
and all three are forbidden:

1. **No setuid-root helper.** The agent chooses the arguments; a setuid binary
   taking agent-chosen paths is an arbitrary root write.
2. **No `sudoers` NOPASSWD entry.** The same defect spelled differently, and it
   hands over passwordless root besides.
3. **No command channel into the daemon** — no request file, no FIFO, no socket
   it polls. Any of those turns the one process the agent cannot touch into a
   proxy it can steer. The daemon reads its root-owned config and the watched
   trees, and nothing else, ever.

`restore` and `restore-dir` refuse root outright, whatever opt-in variable is
set. A file they wrote under sudo would be root-owned at the origin, the daemon
would refuse it on the next scan as `wrong-owner-uid`, and the recovery would
un-protect the very file it recovered. Recovering a vaulted file is therefore a
`cat` and a shell redirect, so the recovered file belongs to the invoking user.
