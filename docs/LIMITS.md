# Honest limits

Every item here is a named boundary, decided deliberately, not a to-do. If one
of them is a problem for your situation, this tool is the wrong tool for that
part of it — which is better to know now than at recovery time.

## 1. Platforms

**macOS and Linux only.** There is no Windows port and none is planned. The
mechanism is a root-owned store plus a system-domain service, and both halves
would need rebuilding on a different security model.

Anything that is neither macOS nor Linux falls back to `PollOnlyTrigger`, which
never wakes early, logs an ERROR at startup naming the platform, and reports
`"trigger": "poll-only"` in the heartbeat for as long as it runs. Capture still
works; only latency changes.

## 2. No userspace watcher can promise that nothing is missed

This is the ceiling, and it is worth stating before anything else. A file whose
entire lifetime is shorter than the notice-to-read latency is never seen.

The only mechanisms that literally cannot miss a write are atomic at the
filesystem layer — a snapshot, or write-path interposition through an
EndpointSecurity client or a FUSE layer. A snapshot is precisely the thing the
adversary can delete, which is why this design does not use one. The other two
are a different product: an Apple-signed entitlement, or a filesystem you own.

So the guarantee here is a floor sweep every 15 seconds with an event trigger
accelerating it, and the residual window is named rather than argued away.

## 3. Files created and deleted inside one interval are missed

The direct consequence of the above. The window is 15 seconds and the gap is
real and unbounded for short-lived files. The work the founding incident lost
had lived about an hour, which is three orders of magnitude inside protection —
but a file written and removed by a build step within one sweep is never
captured, and nothing in the heartbeat will tell you it existed.

Mirror lag has the same shape at the other end: the last few seconds before a
catastrophic delete may hold the second-newest version rather than the newest
keystroke.

## 4. Root and the human owner are not defended against

Anything running as root can remove the store, replace the daemon, and rewrite
the config. This is a protection against agents, not against the machine's
owner, and there is no way to build it otherwise — the whole mechanism is "root
owns the copy the agent cannot touch".

Recovery over a deliberate human change is a related, smaller point: an agent
can restore an old version over a file you intentionally edited. That is within
the agent's own privilege, since it could have edited the file directly, but it
is newly *easy*. Every restore is logged with old and new hashes, and
credential-class files are not in the readable store at all, so the worst case
is a code revert rather than a secret revival.

## 5. A hard link un-protects a file

`st_nlink == 1` is a property of the **inode**, not of a name. So `ln notes.md
x` stops **both** names being mirrored until the link is removed, and an agent
can switch protection off for one file that way.

This is kept as specified because the alternative is a root reader that follows
hard links, and that is a file-disclosure oracle: on macOS an unprivileged user
can `ln /etc/sudoers ./notes.md`, and a root daemon that copied it into a
world-readable store would have published a file the user cannot read.

Versions already stored survive, the refusal is logged and counted in the
heartbeat, and protection resumes on the next scan after the link goes.

A second, smaller hard-link effect runs the other way: an agent can `ln` a 0444
store file into its own workspace, because linking needs write permission only
on the destination. Pruning then unlinks the store's name and frees nothing,
because the agent's link keeps the inode alive. That is disk consumption, not
corruption. The free-space floor is the control that bounds it, and the prune
pass reports every version it unlinked whose link count was above one.

## 6. The credential predicate is name-based

It cannot see content. An agent that renames `.env.local` to `docs/notes.md`
puts the bytes at an admitted path, and they land in the agent-readable store.

**Content-based detection is refused, not merely unbuilt.** The failure
directions are not symmetric. A daemon deciding from a file's contents can be
wrong in two ways: a wrong "this is a secret" sends a work file to the vault and
costs the operator one `sudo`, while a wrong "this is not a secret" puts the
file in the agent-readable half — which is exactly the laundering the split
store exists to prevent, and it is unrecoverable, because once an agent has read
the bytes there is no putting them back.

A name-based rule that is too broad is a nuisance. A content guess in the
readable direction is a breach. So the rule that is too broad is the one this
project takes.

The predicate's boundary is also "whatever an existing guard already covers"
rather than "the threat". Its derived population contains admitted rows of
shapes that look uncomfortably close to the refused ones — a credential basename
used as a *directory* segment, for instance. Generalising that is a real
argument in both directions, since `credentials/` is a common and legitimate
directory name, and it is deliberately not taken here. `etc/vault-extra.conf`
exists for operators who want to be stricter locally; it can only add refusals.

## 7. The budget binds before the window does

Thirty days is the retention **policy**. Five gigabytes is the retention
**reality**. A full store goes degraded and stops, which is loud, rather than
silently discarding recent versions.

Two related bounds are accepted rather than closed. A very actively edited file
keeps only its most recent 200 versions, so an agent can push its own older
versions of one file out of the store by rewriting it 200 times. And a
store-wide budget hit stops capture entirely until a human intervenes: DEGRADED
never self-heals, deliberately, because "prune to make room" converts a
guarantee into a best-effort cache whose only symptom is a missing file.

The daemon now says so on the way down rather than only at the bottom. Inside
1.5x the free-space floor, or above 80% of the store ceiling, `state` is
`warning` and capture continues normally. That is notice, not a reprieve: the
stop still comes, and it still needs a human.

## 7a. An operator can switch protection off for a named directory

`etc/exclude.conf` is optional, root-owned 0644, and every line in it removes
protection from directories matching one name glob. A directory named there is
not walked and nothing inside it is captured, reported only as the counter
`walk-excluded-dir-operator` and the `exclude_globs` count in the heartbeat.

This is a boundary rather than a hole: the file sits beside `watchlist.conf`,
which already decides what is protected at all, and anything able to write
either could un-protect everything in one line. Neither is writable by the
account an agent runs as. But an operator who writes a glob more broadly than
they meant has removed protection they still believe they have, and the only
signal is a counter.

## 8. The installer is a one-time trust transfer

`install.sh` ships from a directory an agent can write, and it runs under sudo.
An agent could edit it before you run it. There is no way around this for a root
daemon.

The mitigations are real but partial: the script is short enough to actually
read, it prints the owner, mode and sha256 of everything it installs, and after
installation nothing in this repo is on the trust path. Read it once.

## 9. What this is not

Not a git replacement. Not a database backup. Not a sandbox, and it narrows or
widens no agent's permissions. "Commit often" remains the first line of defence,
and this covers the window between *written* and *committed* for files in
agent-writable locations — which is precisely where the founding incident's
losses were.

Deferred on purpose, and absent rather than half-built: cross-machine
replication, and encryption at rest beyond whatever full-disk encryption the
host already provides.
