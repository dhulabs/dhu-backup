# DHU Backup — the operator's guide

An append-only mirror of the files agents can delete, written by a root daemon
that no agent lane can touch, readable by any agent that needs its work back.

Design and threat model: [`docs/DESIGN.md`](../docs/DESIGN.md). Recorded
execution evidence: [`docs/PROOFS.md`](../docs/PROOFS.md). The honest ceiling:
[`docs/LIMITS.md`](../docs/LIMITS.md).

## Install (once, by a human)

```bash
sudo bash src/install.sh --watch repo=/Users/you/Projects/my-repo
```

Read `install.sh` first. It is kept short deliberately: running it with sudo is a
one-time transfer of trust from you to code that was delivered from an
agent-writable repo. It prints the owner, mode and sha256 of everything it
installs, so the state it establishes is asserted rather than assumed.

**See the whole plan before you type sudo.** `--dry-run` needs no privilege, and
prints the rendered watchlist, every directory with its mode, and every file with
its mode, source and destination:

```bash
bash src/install.sh --dry-run --watch repo=/Users/you/Projects/my-repo
```

**A real run asks before it writes.** It prints the plan, then requires the word
`yes` — not a keypress, and not a default — before the first file is installed.
The rule is one pure function over three facts, so every path is asserted
without a terminal:

| stdin | flags | what happens |
|---|---|---|
| anything | `--dry-run` | `skip-dry-run`: nothing is written, so there is nothing to confirm |
| anything | `--yes` | `yes-flag`: proceeds, saying that the prompt was skipped |
| a terminal | neither | `prompt`: type `yes`, or it aborts with nothing changed |
| not a terminal | neither | `no-tty`: proceeds, and **says** the plan was not confirmed by a human |

The last row is the one worth arguing about. Prompting would hang CI and every
pipe, and a `yes` read off a pipe is a confirmation from whatever wrote the
pipe, which is not a human — so it proceeds, and the transcript records that
nobody confirmed. That fact is exactly what someone reading the transcript later
needs.

This is not a security control: anyone typing `sudo bash install.sh` has already
made the decision, and nothing here makes handing over root any harder. It makes
the plan something the operator confronts rather than something that scrolls
past.

**The refusal for want of `--watch` also suggests.** With no roots given and none
installed, the installer still refuses before touching anything — a default
watchlist stays forbidden, for the reason below — but it also prints
ready-to-paste flags derived from this machine: git working trees at most two
levels under the invoking user's home (`$SUDO_UID`'s, never root's), ordered
most-recently-modified first, capped at eight, skipping anything the built-in
exclusion list already drops, with the id derived from the directory basename
and every path single-quoted. Symlinks are not followed, so a link inside the
home directory cannot lead the search into another account's tree. If it finds
nothing it says so rather than printing an empty command. It runs on the refusal
path and under `--dry-run`, and nowhere else: a real install already knows what
it is protecting, and a suggestion printed beside a plan about to be executed
reads like part of it.

**The install ROOT is fixed per platform** — `/Library/DHU/backup` on macOS,
`/opt/dhu-backup` on Linux. That is the product's identity on each, and it is not
configurable. What you choose is which directories are WATCHED:

| flag | meaning |
|---|---|
| `--watch <id>=<abs-path>` | one directory to protect. Repeatable. |
| `--watchlist <file>` | the same, from a file in watchlist format. Repeatable, and combinable with `--watch`. |
| `--owner-uid <n>` | the uid whose files are protected. Defaults to `$SUDO_UID`. |
| `--yes` | proceed without the confirmation prompt. For automation. |
| `--dry-run` | print the plan, change nothing, exit 0. Runs unprivileged. |
| `--platform darwin\|linux` | print the OTHER platform's plan. **`--dry-run` only** — it changes the install root, the service manager and the service file, so a real run under it would install the wrong platform's daemon. Refused at parse time otherwise. |
| `--no-service` | install the files and register no service. Linux only, and only where no systemd manager is running. See **Linux** below. |

`<id>` matches `^[a-z][a-z0-9-]*$`; `<abs-path>` is absolute, and a single
trailing `*` on the LAST component is the only glob permitted. Those checks are a
strict subset of what `parse_watchlist` in `dhu_backup_core.py` accepts, which
stays the authority: a root the installer takes can never be one the daemon then
drops. An invalid root refuses the whole install, naming the line — the
alternative is an installer that prints OK while protecting one directory fewer
than you asked for. Start from `src/watchlist.conf.example`.

**There is no default watchlist, on purpose.** A default names directories that do
not exist on this machine; the daemon would come up healthy, protect nothing, and
the installer would print OK over an empty store. With no roots given and none
already installed, `install.sh` refuses before touching anything.

**Re-running it.** A re-run replaces `bin/` and the plist and re-asserts every
post-condition. What happens to the watchlist depends only on the flags:

| you pass | the installed `etc/watchlist.conf` |
|---|---|
| `--watch` / `--watchlist` | replaced by what you passed; the previous one is kept as `watchlist.conf.prev` if it differed |
| nothing, and one exists | kept as it is |
| nothing, and none exists | refused, before anything is changed |

That last-but-one row is what lets a wrapper script re-run the installer with no
arguments after every code change. `etc/dhu-backupd.conf` is likewise never
overwritten — a raised `max_store_bytes` is how you recover from DEGRADED, and
the repo's copy is left alongside as `.dist` to diff.

## Uninstall

```bash
sudo bash src/uninstall.sh --dry-run     # the plan, unprivileged, changes nothing
sudo bash src/uninstall.sh               # boot out and remove the daemon
```

It stops the service (a failed stop is fatal, the same policy as the installer:
code is never deleted underneath a running root daemon), removes the service
file, and removes `bin/` and `etc/`. Then it asserts each of those — the service
gone from the manager, the file gone, the directories gone. On macOS that is
`launchctl bootout system/com.dhulabs.backup` and the plist; on Linux it is
`systemctl disable --now dhu-backupd` — `disable` as well as `stop`, because a
merely stopped unit comes back at the next boot and the post-condition would be
true today and false tomorrow — then the unit file and a `daemon-reload`.
`--platform` prints the other platform's plan and is `--dry-run` only, exactly as
on the installer.

**`store/`, `vault/` and `var/` are KEPT**, and their sizes printed. They are the
captured history, and an uninstaller that deletes them because you wanted to stop
a daemon has destroyed the thing it was protecting. `--purge` deletes them, and
only together with `--yes`; `--purge` alone prints what it would delete, with
sizes, and exits 2.

Two steps it deliberately does not take, because they live in your files and root
must not rewrite them: removing the `PostToolUseFailure` hook entry from
`~/.claude/settings.json`, and `claude mcp remove -s user dhu-backup`. It prints
both.

## Linux

The port is one daemon and one installer, not a second copy of either. What
differs is named in exactly three places: `DEFAULT_INSTALL_ROOTS` in
`dhu_backup_core.py`, the trigger class the daemon picks at startup, and the
`set_platform` / `service_*` functions in `install.sh` and `uninstall.sh`. The
pure decision core, the openat walk, the admission guards, the credential
predicate, the budgets and the recovery CLI are byte-identical on both.

| | macOS | Linux |
|---|---|---|
| install root | `/Library/DHU/backup` | `/opt/dhu-backup` |
| service | LaunchDaemon `com.dhulabs.backup` | systemd system unit `dhu-backupd.service` |
| service file | `/Library/LaunchDaemons/com.dhulabs.backup.plist` | `/etc/systemd/system/dhu-backupd.service` |
| trigger | kqueue `EVFILT_VNODE` | inotify |
| stop it | `sudo launchctl bootout system/com.dhulabs.backup` | `sudo systemctl disable --now dhu-backupd` |

```bash
sudo bash src/install.sh --watch repo=/home/you/proj      # on the Linux host
bash src/install.sh --dry-run --platform linux --owner-uid 1000 --watch repo=/home/you/proj
```

`--platform` prints the other platform's plan from either machine and is
accepted **only** with `--dry-run`. It changes the install root, the service
manager and the service file, so a real run under it would install the wrong
platform's daemon; without `--dry-run` it exits 2 before anything is read.

### The unit, and why each hardening key is there

`src/dhu-backupd.service` is a SYSTEM unit, for the same reason macOS uses a
LaunchDaemon and not a LaunchAgent (review C3). A `systemd --user` unit's file
lives under the adversary's own home and the job runs as the adversary. A system
unit's file is root-owned 0644 in a root-owned directory, and the two refusals
that make it untouchable are the Linux form of the macOS proof:

```
$ systemctl stop dhu-backupd          # as a non-root user
==== AUTHENTICATING FOR org.freedesktop.systemd1.manage-units ===   (polkit)
$ kill <pid>
-bash: kill: (…) - Operation not permitted
```

| key | why |
|---|---|
| `Type=simple`, `Restart=always`, `RestartSec=2` | the daemon must come back; the macOS `KeepAlive` equivalent |
| `Nice=10` | it is a background scanner, `ProcessType=Background` on macOS |
| `LimitNOFILE=65536` | one fd per watched directory for the trigger, plus the walk's per-depth fds |
| `NoNewPrivileges=yes` | it never needs to gain any |
| `ProtectSystem=strict` + `ReadWritePaths=/opt/dhu-backup` | the whole filesystem is read-only to this unit except its own install root. It only ever writes there |
| `ProtectHome=read-only` | **not `yes`.** The daemon must READ home directories — that is where the watched trees are. `ProtectHome=yes` gives it an empty tmpfs, every watch root is refused, and it reports `unprotected`: healthy, protecting nothing |
| `PrivateTmp=yes` | it cannot see or be steered by another process's temp files. **If a watch root is under `/tmp`, change this to `PrivateTmp=no`** — otherwise the daemon watches its own private empty `/tmp` and reports a refused root |
| `StandardOutput`/`StandardError` = `append:…/var/dhu-backupd.log` | the same file at the same mode as macOS. `append:`, not `file:`, so a restart does not truncate the record |

None of the hardening keys is load-bearing for the product's guarantee. That is
the kernel refusing an agent's write to a root-owned directory, and it holds with
all of them switched off. They narrow what this root process can do to the HOST,
which is worth having in a process that reads agent-written trees.

### The interpreter

`/usr/bin/python3` from the distro package (`apt-get install python3`),
root-owned. On Ubuntu it is a root-owned symlink to a root-owned
`python3.NN` (3.12 on 24.04, 3.14 on 26.04), and both halves are checked: `install.sh` refuses to write the unit
unless the link AND its resolved target are root-owned, and the daemon re-runs
the same check on its own interpreter at every start, reporting
`interpreter_root_owned` in the heartbeat. Never pyenv, conda, homebrew or node —
a user-owned binary executed by root is a root shell for any agent (review H2).
The rule is one pure function, `dhu_backup_core.interpreter_verdict`, and both
callers use it rather than each spelling it out.

### The shebang, which had to change

`#!/usr/bin/python3 -E -s -S` works on macOS and **does not work on Linux**:
Linux passes the whole tail of a shebang line as ONE argument, so python receives
the single option `-E -s -S` and exits with `Unknown option: -`. Measured in the
container: every direct `dhu-backup` invocation failed that way. The four helper
scripts now start `#!/usr/bin/env -S /usr/bin/python3 -E -s -S`, which splits the
tail itself, exists root-owned on both platforms, and keeps the interpreter path
absolute so no `PATH` lookup is introduced.

### inotify: the difference, and the limits

A directory watch is added with
`IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO|IN_CLOSE_WRITE|IN_ATTRIB|IN_DELETE_SELF|IN_MOVE_SELF|IN_ONLYDIR|IN_DONT_FOLLOW`,
through `ctypes` against libc — the stdlib has no inotify binding and the daemon
may import nothing outside the stdlib and its own root-owned directory (H3). The
mask values are kernel ABI and are pinned by a test, because a wrong bit is a
watch that never fires and the floor sweep hides that perfectly.

`IN_CLOSE_WRITE` is the one that makes Linux differ: a directory watch reports it
for a file written inside the directory, so `echo x > f` is captured in 0.57 s
instead of waiting for the 15 s floor. `IN_ONLYDIR` and `IN_DONT_FOLLOW` are C7
restated for the trigger — it refuses to watch a non-directory and never resolves
a symlink at the final component.

**The limits are real and are REPORTED.** `inotify_add_watch` fails with `ENOSPC`
at the per-user `max_user_watches` ceiling and `EMFILE` at the instance limit; a
tree of a few hundred thousand directories reaches the first on a stock host. The
daemon logs `max_user_watches` at startup beside the directory count, counts
every failure into `trigger_watch_failures` in the heartbeat, logs each failing
directory once, and says once per cycle when it is watching fewer directories
than it walked. Those directories fall back to the floor sweep, which is the
guarantee. Raise the ceiling with `sudo sysctl -w fs.inotify.max_user_watches=…`.

An unsupported platform gets `PollOnlyTrigger`, which never wakes early, an
ERROR line at startup naming the platform, and `"trigger": "poll-only"` in the
heartbeat for as long as it runs. Capture is unaffected; latency is.

### Hard links are already harder on Linux

Linux's `fs.protected_hardlinks` (1 by default) stops an unprivileged user from
linking a file they can neither read nor write, so the C6 primitive is blocked
before the daemon sees it. Executed in the container:

```
$ ln /etc/shadow ~/proj/shadow-link.md        # as the unprivileged user
ln: failed to create hard link '…/shadow-link.md' => '/etc/shadow': Operation not permitted
```

macOS has no such control — `ln /etc/sudoers ./notes.md` succeeds there. The
daemon's own guards are unchanged and are proven separately against a link the
Linux kernel does allow (a root-owned 0666 file inside the watched tree): the
capture is refused `admission-hardlink-nlink`, the content appears nowhere in the
readable store, and the refusal is in the log and the heartbeat.

### What was proven, and where

`src/tools/linux-smoke.sh` runs the whole thing non-interactively in a container
and exits non-zero if anything fails. It is developer tooling: not installed, not
on the trust path.

```bash
docker run --rm -v "$PWD:/src:ro" ubuntu:24.04 bash /src/src/tools/linux-smoke.sh
```

The repo is mounted read-only and copied inside; nothing else from the host is
mounted. Proven there on 2026-09-02 (Ubuntu 24.04.4, aarch64, Python 3.12.3):
the installer's plan and its refusals, the real install, the config rewritten to
the Linux root, the inotify trigger and both latencies, the hard-link refusal,
`.env.local` reaching `vault/` and not `store/`, the kernel refusing the
unprivileged user every write to the mirror and `kill` on the daemon, the whole
recovery CLI with no sudo, `uninstall.sh` for real — removing `bin/`, `etc/` and
the unit file while KEEPING every captured version — and the whole suite green
under Python 3.12, every check passing.

**What a container cannot prove** — there is no systemd manager in one — was
taken to a real systemd host afterwards: the unit actually loading, polkit's
refusal of a non-root `systemctl stop`, and `ProtectSystem` / `ProtectHome` /
`PrivateTmp` taking effect are all recorded in `docs/PROOFS.md` §4, on Ubuntu
26.04 with Python 3.14. Survival across a reboot is the one item still open.

`--no-service` exists for exactly that gap: it installs the files and registers
nothing, so the daemon can be started by hand in a container. Its gate is a fact
about the machine rather than a promise from the caller — the absence of
`/run/systemd/system` — so on a real booted host it refuses. An unregistered root
process does not survive a reboot, and none of the installer's post-conditions
would describe what is actually running.

## How it works

A LaunchDaemon (`/Library/LaunchDaemons/com.dhulabs.backup.plist`, root:wheel)
runs `/usr/bin/python3 -E -s -S /Library/DHU/backup/bin/dhu-backupd` as root,
forever. On Linux the same line is a systemd system unit; see **Linux** above.
It walks the roots named in `etc/watchlist.conf` and copies changed files into
`store/` or `vault/`.

**Capture timing, measured rather than claimed** — the dated table below. A
watch on every watched DIRECTORY wakes the daemon — `kqueue` `EVFILT_VNODE` on
macOS, inotify on Linux — and a 15 s floor sweep runs underneath it as the
guarantee.

A directory watch does not fire for an in-place rewrite — that is a measurement,
not an assumption. Editors that write-then-rename are caught immediately; a
shell redirect waits for the sweep. Watching every FILE would close the gap at
the cost of a file descriptor per watched file and much more state in the one
process that must never die; not taken.

**Linux is faster on the second row and identical on the first**, because a
directory inotify watch reports `IN_CLOSE_WRITE` for files written inside it and
a directory kqueue has no equivalent. Both measured the same way, 2026-09-02:

| change | macOS (kqueue) | Linux (inotify) |
|---|---|---|
| a new file | 0.55 s | 0.55 s |
| an in-place rewrite | 29.97 s — the floor | **0.57 s** |

The floor sweep is unchanged at 15 s on both, and it remains the guarantee. The
trigger is an accelerator on either platform: it is not on the trust path, and a
spoofed or missing event costs one sweep and nothing else.

**The honest ceiling:** no userspace watcher can promise that nothing is missed.
A file whose entire lifetime is shorter than the notice-to-read latency is never
seen. The incident this exists for lost work that had lived an hour.

Three properties carry the whole design, and each is a syscall rather than a
rule the code has to remember:

- **The agent cannot write the store.** Everything under
  `/Library/DHU/backup/` is root-owned. The daemon PULLS; agents never
  push. There is no write path to revoke.
- **The agent CAN read `store/`.** Directories are 0755 and files 0444, so
  recovery needs no sudo and no human. Unlink and rename need write permission
  on the PARENT directory, which no agent has at any level.
- **Credential-class files go to `vault/` (0700), not `store/`.** They are still
  captured — a deleted `.env.local` is recoverable by the owner with sudo — but never
  become agent-readable. One predicate, evaluated at copy time on the original
  path, decides which half. A vaulted path is REPORTED as vaulted by `dhu-backup`, never
  silently absent.
- **Nothing is ever overwritten.** A new version is created with `os.link()`,
  which fails `EEXIST` instead of clobbering. Append-only is enforced by the
  kernel.

The walk descends with directory file descriptors (`openat`), opens every file
`O_NOFOLLOW` by basename relative to its directory's fd, and `fstat`s the open
fd. No path string is ever re-resolved, so there is no window in which a checked
name can be swapped for a symlink or a hard link.

Two of those fd-level checks are independently load-bearing, and both are tested
separately: `st_nlink == 1` and `st_uid == <owner>`. `ln /etc/sudoers ./notes.md`
succeeds as an unprivileged user (executed, nlink went to 3) — an innocent name
over a root-owned inode. The owner check refuses it because root owns the inode;
the link-count check refuses it because a hard link in a source tree is
anomalous. Neither is redundant: the owner check alone would admit a link to
another of the owner's own files, and the link check alone would admit a
root-owned file that somehow had one link.

A file is copied only if it is a regular file with `st_nlink == 1`, owned by the
configured uid, not setuid/setgid, at most 1 MiB, outside the excluded
directories and extensions, and **not matching the credential predicate**. Every
other outcome is a refusal with a reason, counted in `state.json` under that
reason. Refusals are also logged, once per file per reason per process — a
refusal is re-evaluated every 15 s, and logging each one every time produced
~36 MB of root-owned log a day on the volume whose free space stops the daemon.

## Layout

The same layout on both platforms; only the root differs
(`/opt/dhu-backup` on Linux, where the group is `root` rather than `wheel`).

```
/Library/DHU/backup/
  bin/dhu-backupd         0755 root:wheel   the daemon
  bin/dhu_backup_core.py  0644 root:wheel   the pure decision functions
  bin/credential_patterns.py 0644 root:wheel the credential predicate's patterns
  bin/dhu-backup          0755 root:wheel   recovery (runs UNPRIVILEGED, as the agent)
  bin/dhu_backup_announce.py 0644 root:wheel the self-announcing lookup (Property 4)
  bin/dhu-backup-mcp      0755 root:wheel   MCP server over stdio (UNPRIVILEGED)
  bin/dhu-backup-hook     0755 root:wheel   Claude Code PostToolUseFailure hook
  etc/dhu-backupd.conf    0644 root:wheel   budgets, interval, owner uid
  etc/watchlist.conf      0644 root:wheel   the ONLY source of watched roots,
                                            written from install.sh's --watch flags
  etc/vault-extra.conf    0644 root:wheel   OPTIONAL, operator-created: extra
                                            basename globs that ADD to the vault
  etc/exclude.conf        0644 root:wheel   OPTIONAL, operator-created: directory
                                            -name globs that REMOVE protection
  store/                  0755 root:wheel   AGENT-READABLE — guard-clean files
  vault/                  0700 root:wheel   root-only — credential-class files
  var/roots/              0755 root:wheel   which absolute path each root-id/slug is
  var/index.sqlite3       0644 root:wheel   change detection only (a cache: a
                                            corrupted one is moved aside and rebuilt)
  var/state.json          0644 root:wheel   heartbeat: counts and state, no paths
  var/dhu-backupd.log     0644 root:wheel   decisions and paths, never content
  var/tmp/                0700 root:wheel   staging for atomic writes; swept at start
```

Version layout, in both trees:

```
<tree>/<root-id>/<slug>/<relpath-dir>/@<capture_ns>-<sha256[:12]>/<ORIGINAL BASENAME>
```

**The version is a DIRECTORY and the original basename is the LEAF.** That is
what makes every existing name-based guard work on a mirror path unchanged, with
no new denylist to maintain. Executed against a real basename-matching read
guard of the kind agents already run under:

| mirrored file | draft layout (hash leaf) | this layout |
|---|---|---|
| `.env.local` | `null` | `".env.local" matches a secret-file pattern` |
| `deploy/keys/id_rsa` | `null` | `"id_rsa" is key material` |
| `certs/server.pem` | `null` | `"server.pem" is key material` |
| `lib/router.ts` | `null` | `null` |

**`@<capture_ns>` is the daemon's own clock at copy time, never the source
file's mtime.** `touch -t 197001020304 f` backdates a file 20,000 days in one
command, so a version tag or a retention decision derived from source mtime is
an agent-driven delete into the mirror. `version_key`'s signature has no mtime
parameter, which is the proof rather than a comment about it.

`<slug>` is the expanded watch root's basename plus a hash of its full path. It
exists because a glob root such as `worktrees` expands to many directories, and two
worktrees both holding `lib/x.ts` would otherwise share one version history. The
absolute path lives in `var/roots/`, outside the mirrored trees, so no captured
filename can collide with a marker.

**The version directories of every file in one source directory are siblings**
under `<relpath-dir>`, and the leaf is the only thing that says which file a
version belongs to. Every retention decision is keyed on `(relpath-dir, leaf)`
for that reason; v0.1.0 and v0.2.0 keyed both the rolling window and the age
prune on the directory alone, which is why a reinstall over either is
recommended (see `docs/LIMITS.md` §7 and `docs/PROOFS.md` §6). The walk refuses
a source entry whose name parses as a version key (`walk-version-key-shaped`)
so nothing an agent names can enter that namespace, and a name that is not
valid UTF-8 (`walk-name-not-utf8`), which the index and the log cannot hold.

## The five budgets

Two of them stop the whole daemon. Three of them skip one entry. The split is
the point — a per-file condition must not be able to switch the protection off.

| limit | default | on hit |
|---|---|---|
| `max_store_bytes` | 5 GiB | **DEGRADED** — capture stops, everything held is kept |
| `min_free_bytes` | 10 GiB | **DEGRADED** — stop before the volume dies, not just the store |
| `max_file_bytes` | 1 MiB | skip this file, count it |
| `max_versions_per_path` | 200 | **roll the window**: drop that path's oldest versions, then write the new one |
| `max_new_files_per_scan` | 2000 | throttle: the rest wait for the next scan |

Plus `max_watch_roots` (64) on the watchlist, with a logged refusal when it
binds — a silently dropped root is a silently unprotected agent.

**Why `max_versions_per_path` rolls rather than skips.** As a skip it inverted
the guarantee for exactly the file the incident lost: at a 15 s interval an
actively edited file reaches 200 versions in under an hour, and from that moment
its NEWEST content was the one thing not in the store, reported only as a
counter nobody reads mid-session. The daemon now prunes that path's oldest
versions down to `cap - 1` and writes the new one, using the same executor as
age pruning — retention stays daemon-only, and the newest version is never in
either plan. Ordering is by the capture clock in the version key, so `touch -t`
cannot choose which version the window discards.

The disk argument is unchanged by this: a path is still bounded at
`max_versions_per_path x max_file_bytes` (200 MiB worst case, and kilobytes in
practice), and the store ceiling plus the free-space floor remain the store-wide
stops. Rolling changes WHICH versions a busy path keeps, not how many.

**The warning band, before the stop.** The two store-wide budgets get a state of
their own on the way down. While free space is inside `1.5 x min_free_bytes`, or
the store is above 80% of `max_store_bytes`, the daemon writes `state: warning`
and keeps capturing exactly as before. Both thresholds are named constants in
`dhu_backup_core.py` (`FREE_SPACE_WARNING_MULTIPLIER`, `STORE_WARNING_FRACTION`),
and both triggers are reported together when both are true.

This exists because capture ENDING is designed for and capture ending with no
notice is not. On the volume this was written on, 14.1 GiB free against a 10 GiB
floor read `ok` right up to the cycle that would have stopped it. The heartbeat
now carries `warning_reason` (a list) and `warning_detail` (a sentence), and the
warning is logged when it ARRIVES and when it clears, not every cycle — one line
per 15 s scan is 5,760 a day into a root-owned log on the volume the warning is
about.

**DEGRADED never self-heals.** "Store full, prune the oldest to make room" would
quietly convert a 30-day guarantee into a best-effort cache whose only symptom is
a file that is not there when you need it. The daemon stops, says so every
cycle, and waits for a human. It stays degraded across restarts.

To recover from degraded: free space or raise the budget in
`etc/dhu-backupd.conf`, delete `var/state.json`, then
`sudo launchctl kickstart -k system/com.dhulabs.backup`.

## `etc/exclude.conf` — the operator's directory exclusions

Optional and never shipped: the installer prints how to create it and installs
nothing. One DIRECTORY-NAME glob per line, `#` comments, `fnmatch` on the
directory's basename during the walk and never against a path.

```
# /Library/DHU/backup/etc/exclude.conf
fixtures
snapshots-*
```

**Read the asymmetry before you use it.** `vault-extra.conf` can only ADD
protection; its worst outcome is a work file you have to `sudo cat` back.
`exclude.conf` can only REMOVE protection; its worst outcome is a directory
nobody is protecting, discovered when a recovery comes back empty. Those are not
the same risk, and this file is not justified by the same argument.

It is acceptable for exactly one reason: it is root-owned 0644 in the same
`etc/` as `watchlist.conf`, which already decides what is protected at all.
Anything that could write this file could rewrite the watch list and un-protect
everything in one line, so it adds no reach an adversary did not already have,
and neither file is writable by the owner's account — the account the agent
holds. A file that could make the daemon protect MORE than the watch list says,
or make a vaulted path readable, would need a different argument and there is
not one.

Three details that follow from "only ever removes":

* **It is matched CASE-SENSITIVELY**, deliberately the opposite of
  `vault-extra.conf`. There, a loose match vaults a file that need not have
  been and costs one `sudo`. Here, a loose match un-protects a directory nobody
  named. `Fixtures` is not `fixtures`.
* **It is a WALK rule, not an admission rule.** The whole value of it is that a
  33 GB directory costs one `scandir` entry instead of a descent. `classify_entry`
  keeps its own copy of the BUILT-IN list and does not know about this one; a
  path reaching admission from anywhere else is admitted rather than excluded,
  which is the direction that protects more.
* **It cannot switch a built-in exclusion off.** There is no syntax for "walk
  `node_modules` after all". The built-in list is checked first.

A line containing `/`, `..`, a NUL byte, nothing but wildcards, or more than 256
globs is REFUSED, logged as an ERROR, and counted. A wildcard-only line such as
`*` is refused rather than obeyed: it names no directory in particular, it is
"stop protecting everything" spelled as a rule about names, and an operator who
wants that removes the watch root in the file that says what is protected. An
unreadable file is a REFUSAL, not an empty list — "I could not read your rules"
and "you have no rules" are different facts.

The daemon reads it at startup from the same root-owned `etc/` as its other
config; restart the daemon after editing it. Three heartbeat numbers report it,
and the third is the one that says the rule is doing something:

```
"exclude_globs": 2, "exclude_refused": 1,
"refusals_by_reason": { "walk-excluded-dir-operator": 4, "walk-excluded-dir": 11 }
```

`walk-excluded-dir-operator` is deliberately distinct from the built-in
`walk-excluded-dir`. Merged, an operator could not tell "my rule is working"
from "my rule never matched", and the second is the one that costs them the disk
they were trying to save.

## Reading state.json

```bash
cat /Library/DHU/backup/var/state.json
```

```json
{
  "state": "ok",
  "last_scan_iso": "2026-09-01T20:41:07Z",
  "last_scan_epoch": 1788295267,
  "files_scanned": 6253,
  "versions_written": 12,
  "bytes_written": 204800,
  "content_already_held": 3,
  "versions_rolled": 0,
  "files_deferred_by_throttle": 0,
  "refusals_by_reason": { "walk-symlink": 2, "admission-excluded-extension": 43 },
  "store_bytes": 91234567,
  "free_bytes": 30064771072,
  "max_store_bytes": 5368709120,
  "min_free_bytes": 10737418240,
  "watch_roots": 3,
  "watch_roots_refused": 0,
  "directories_watched": 797,
  "trigger": "kqueue",
  "trigger_watch_failures": 0,
  "interpreter_root_owned": true,
  "interval_seconds": 15,
  "retention_days": 30,
  "exclude_globs": 0,
  "exclude_refused": 0,
  "vault_extra_globs": 0,
  "vault_extra_refused": 0,
  "vaulted": 0,
  "prune_last_removed": 0,
  "prune_last_failed": 0,
  "index_reconciled": 0
}
```

Every count except `store_bytes`, `free_bytes` and the `*_last_*` ones is for
the LAST SCAN, not cumulative. `versions_rolled` is how many versions the
per-path window discarded in that scan; `content_already_held` how many files
were re-hashed and found unchanged against their newest version; `vaulted` how
many of the versions written went to `vault/`. Under `degraded` the heartbeat
also carries `degraded_reason` and `degraded_since_epoch`; under `scan-failed`,
`scan_error`.

Three fields are about the machinery rather than the capture.
`trigger` is the name of the trigger actually running — `kqueue`, `inotify` or
`poll-only`; a chosen trigger that failed to start reports `poll-only`, never its
own name. `trigger_watch_failures` above zero means some directories lost their
accelerator and fall back to the floor sweep. `interpreter_root_owned` false
means the bytes this root daemon executes are replaceable by the owner's own
account, which is the threat model inverted (review H2).

`state` is one of five: **ok** (capturing comfortably), **warning** (capturing
NORMALLY, and close to a store-wide budget that will stop it), **degraded** (a
store-wide budget stopped it), **unprotected** (the daemon is healthy and has NO
usable watch root, so nothing is being protected — an unreadable watchlist, a
refused root, or an `owner_uid` that does not match yours), and **scan-failed**
(the daemon is running and every scan is throwing, with `scan_error` naming it).
The first version wrote `ok` for `unprotected` and `scan-failed`, with a zero
file count, and a status banner reading it then said "protecting uncommitted
work" over an empty store.

`warning` is never merged into `ok`, and it is ordered BELOW the three failures:
a daemon that has stopped is not "about to stop". Under `warning` the heartbeat
also carries `warning_reason` (always a LIST, because both triggers can be true
at once) and `warning_detail` (the sentence a human reads). `min_free_bytes` and
`max_store_bytes` are in every heartbeat, warning or not, because "14.1 GiB
free" is not actionable without the floor it is heading for.

An unrecognised label is `unreadable-heartbeat` and never `ok`. That is what
makes adding a state safe in the only direction that matters: an old helper
reading a newer daemon says "heartbeat state is 'warning', which this version
does not understand" and fails loudly.

`index_reconciled` is how many indexed paths the daemon found no version of in
the store at its last start or prune, and therefore forgot, so that the next
scan captures them again. It is non-zero once after upgrading from v0.1.0 or
v0.2.0 and zero from then on; a non-zero value on an ordinary day means
something removed versions from the store, which only root can do.

`files_deferred_by_throttle` is the throttle's backlog: how many admitted files the last scan deferred to the next one. On a cold start a working
tree of a few thousand files leaves most of them without a copy for the first
minute, and `files_scanned` alone reads as though they were all protected.

No paths ever appear in the file, so it is safe to read anywhere. A tool that
reads it at start-up can distinguish six faults from it: degraded, unprotected,
scan-failed, stale (no scan for 5 minutes), no-heartbeat (no heartbeat file at
all), and unreadable-heartbeat. Those, with `ok` and `warning`, are the helper's
eight `HEALTH_VERDICTS`: the five states the daemon writes plus the three
things the daemon cannot say about itself.

## Recovery — no sudo, no human, one command

```bash
dhu-backup status                        # is this working? and if not, what to type
dhu-backup ls   <path-substring>         # which protected paths have versions
dhu-backup log  <path>                   # versions of one path: time, size, hash
dhu-backup cat  <path> --asof 20m        # print one version to stdout
dhu-backup restore     <path> [--asof 20m] [--into DIR]
dhu-backup restore-dir <dir>  [--asof 20m]   # a deleted directory back in one command
dhu-backup missing <ABSOLUTE path>       # what the store holds for a path that is GONE
```

`dhu-backup` is `/Library/DHU/backup/bin/dhu-backup` on macOS and
`/opt/dhu-backup/bin/dhu-backup` on Linux. `--asof` takes an ISO timestamp or a
relative age (`20m`, `2h`, `3d`) and resolves to the newest version at or before
it — and returns **nothing** rather than the newest version if none qualifies.

`restore` derives its destination from the stored relpath plus the watch root.
`--into` names an alternative base DIRECTORY; the caller never names the file.
Nothing is silently clobbered: if the target exists with different content,
`dhu-backup` writes `<name>.restored-<tag>` beside it, says exactly what it did, and exits
non-zero. `--overwrite` opts into the in-place write.

Every invocation prints the daemon's health first, so "no versions" is never
mistaken for "capture has been stopped for two days". The banner's verdict is
`health_verdict`'s and its words are `health_sentence`'s — the same line
`status` prints — so every command says the same thing about the same
heartbeat; a heartbeat this version cannot interpret is `!! HEARTBEAT
UNREADABLE` on `ls` exactly as it is on `status`, never a traceback or silence.

An `--into` that cannot be written — a regular file, a read-only volume, a
directory you may not write — is `ERROR could not write <dest>: <reason>` and
exit 2. The store was readable; the message says which side failed.

**Recovering a vaulted (credential-class) file** is the owner's to do, deliberately,
with sudo — and it is a READ, never a `restore`:

```bash
sudo DHU_BACKUP_ALLOW_ROOT=1 dhu-backup log <path>          # which versions exist
sudo DHU_BACKUP_ALLOW_ROOT=1 dhu-backup cat <path> > <origin>   # write it back as YOU
```

`DHU_BACKUP_ALLOW_ROOT` does two things at once: it gets past the root refusal,
and it is what makes `dhu-backup` read `vault/` at all. Without it the helper
walks `store/` only, and a vault entry is invisible however it is invoked. Under
root with it set, `ls` and `log` mark vault entries `[vault]` so you can see
which half of the mirror an answer came from. `restore` and `restore-dir` refuse
root whatever the variable says: a file they wrote would be root-owned at the
origin, which the daemon refuses as `wrong-owner-uid`, so the recovery would
silently un-protect the very file it recovered.

### `dhu-backup status` — is this working?

```bash
dhu-backup status            # unprivileged; writes nothing
dhu-backup status --json
```

Everything it reports was always in `var/state.json`, and reading JSON at the
moment your work has vanished is not a recovery procedure. It prints:

* the health verdict and what it means, in the SAME words a failed read uses —
  `dhu_backup_announce.health_sentence` is the one vocabulary, and `ok` is the
  only verdict whose sentence is not in the `_HEALTH_NOTE` table the hot path
  shouts from;
* when the last capture was;
* the watch roots **in force**, read from `etc/watchlist.conf` rather than from
  `var/roots/` — those manifests are written per expanded root and are never
  removed, so a machine whose watchlist changed last month still has manifests
  for directories nothing watches now. Beside each root is the count of PATHS
  the store holds under it, and beside the list is the daemon's own count of
  expanded roots, because one `--watch worktrees=/…/worktrees/*` line becomes
  one root per directory and the two numbers are not substitutes;
* a note naming any store subtree whose id the watchlist no longer mentions:
  that history is KEPT and nothing is being added to it, which is the difference
  between believing an old repo is still protected and knowing it is not;
* the store size and the free space against **the daemon's own** budgets — read
  from the heartbeat, not from the compiled-in defaults, because raising
  `max_store_bytes` is the documented way out of `degraded` and a status that
  ignored that would print the wrong number on exactly the machine where
  somebody acted on the last one;
* the operator's exclusion and vault-extra glob counts, when there are any —
  including zero globs with refusals, which means every line the operator wrote
  was thrown out;
* when something is wrong, the ONE command that addresses it.

The count of paths is a **path** count, not a version count: a file with 200
versions counts once, because the number is read as "how much of my work is in
there" and versions-per-path is a retention setting. Getting it exactly needs
one directory open per version directory — a path's versions are siblings, so
the only way to learn a path's name is to look inside one — so the walk has a
budget of 20,000 opens shared across the roots, each root taking an equal share
of what is left and handing back what it does not spend. A root whose share runs
out reports **"at least N"** rather than a number that is quietly wrong.
Measured on a real store of 33,000 paths and 37,425 version directories: 1.2 s
of opens on top of a 0.6 s tree walk if uncapped, about half a second with the
budget in force.

#### Exit codes

| code | meaning | verdicts |
|---|---|---|
| 0 | capturing | `ok`, `warning` |
| 1 | not capturing; a human has to act | `degraded`, `unprotected`, `scan-failed`, `stale` |
| 2 | the status could not be determined | `no-heartbeat`, `unreadable-heartbeat` |

Three codes, not two, for the reason `announce_exit_code` has three: "capture
has stopped" and "I could not find out whether capture has stopped" are opposite
claims, and a monitor that collapses them either pages for a machine that is
fine or stays quiet about one that is not. `warning` exits 0 because capture IS
running — failing on it would fail over something that has not happened, and the
operator would learn to ignore the code before the day it meant `degraded`. The
three sets partition `HEALTH_VERDICTS`, a test asserts that they do, and a
verdict in none of them makes `status_exit_code` raise rather than default to 0.

The exit code is the DAEMON's, never the command's. `status` succeeding while
capture has stopped is a report somebody would write a green monitor against.

#### The JSON shape

`--json` prints one object with these keys, and every key is present whatever
happened — a missing field never stands in for a failure:

```json
{
  "install_root": "/Library/DHU/backup",
  "health": {"verdict": "ok", "detail": "the last capture was 3s ago",
             "sentence": "OK — capture is running and the store is being written"},
  "capturing": true,
  "exit_code": 0,
  "last_capture": {"epoch": 1789156046, "iso": "2026-09-11T15:47:26", "age_seconds": 3},
  "watch_roots": {
    "error": null, "store_error": null,
    "configured": [{"root_id": "repo", "pattern": "/Users/you/Projects/x",
                    "paths_held": 412, "paths_held_capped": false, "error": null}],
    "refused_lines": [], "expanded": 35, "expanded_refused": 0,
    "unwatched_root_ids": []
  },
  "store": {"bytes": 769, "human": "769 bytes", "ceiling_bytes": 5368709120,
            "ceiling_human": "5.0 GiB", "headroom_bytes": 5368708351,
            "headroom_human": "5.0 GiB"},
  "free_space": {"bytes": 49123995648, "human": "45.7 GiB",
                 "floor_bytes": 10737418240, "floor_human": "10.0 GiB",
                 "headroom_bytes": 38386577408, "headroom_human": "35.7 GiB"},
  "warning": null,
  "exclusions": {"globs": 1, "refused": 0},
  "vault_extra": null,
  "files_deferred_by_throttle": 0,
  "next_step": {"sentence": null, "command": null}
}
```

`watch_roots.error` non-null means the watchlist could not be READ, and
`configured` is then empty — which is why the error field exists rather than an
empty list standing for "nothing is watched". `free_space` is null when the
daemon did not measure it this cycle, never `0`: a failed `statvfs` that became
`free_bytes = 0` once printed a permanent "the volume is full" beside a
heartbeat reporting 30 GB free. `exclusions` and `vault_extra` are null when the
operator has added no rules of that kind. `warning` carries `reasons` (a list,
because both triggers can fire at once) and `detail` only under the `warning`
verdict. `files_deferred_by_throttle` is the daemon's own count of admitted
files whose copy the per-scan throttle pushed to a later scan — "not up to
date", not "not protected" — and null when the heartbeat does not carry it;
the text output prints a `backlog` line only when it is non-zero.

The same payload is the MCP tool `dhu_backup_status`, annotated read-only, with
the rendered text beside it in a `text` field. A stopped daemon comes back as an
ANSWER with `isError: false` — it is the answer the caller most needs, and a
protocol error is something a client may retry or drop. Only exit code 2, "could
not determine", is an error there.

## Self-announcing recovery (Property 4)

The other four commands answer a question an agent has to know to ask. This one
turns the ERROR into the answer: when a read fails with "no such file", the
failure itself can say that the mirror holds three versions of that path and
print the command that reads them back. It is what reaches an agent that never
read this file.

```bash
dhu-backup missing /Users/you/Projects/x/lib/gone.ts          # text, for an agent to read
dhu-backup missing /Users/you/Projects/x/lib/gone.ts --json   # machine-readable
```

```python
import sys; sys.path.insert(0, "/Library/DHU/backup/bin")
from dhu_backup_announce import announce, format_text, to_json

result = announce("/Users/you/Projects/x/lib/gone.ts")   # never raises
if result.status == "held":
    print(format_text(result))
```

It takes an ABSOLUTE path — the one whose read failed — rather than the
substring the other subcommands take, because the caller is an error handler
that has an exact path and no idea what the store calls it. Mapping that path to
a store key is the whole job.

### The status vocabulary

Six values, and they are the reason this is worth having rather than a `test -e`.

| `status` | means | exit |
|---|---|---|
| `held` | the store holds versions of this exact path: keys, capture times, sizes, hashes, store paths, and the `cat`/`restore`/`log` commands | 0 |
| `held-directory` | the path is a directory prefix under which the store holds N paths — the incident's shape — with the `restore-dir` command | 0 |
| `vaulted` | the path is credential-class, so it can only be in the root-only vault | 1 |
| `not-held` | inside a watch root, the store WAS read, and it holds no version of this path; a path the filesystem cannot name (a component past `NAME_MAX`, a symlink loop) is this too, with `reason` set to `unnameable-path: …`, because a path the daemon could not have written cannot have been captured | 1 |
| `outside-watch-roots` | no watch root contains this path, so it was never protected; the watch roots are named | 1 |
| `store-unavailable` | the store, the root manifests or the heartbeat could not be read; the reason is carried verbatim | 2 |

**`store-unavailable` is not a kind of `not-held`.** They are opposite claims —
"I looked and there is nothing" against "I could not look" — and an agent that
collapses them abandons work that is sitting on disk. They have different exit
codes for that reason, and the text output says so in a line of its own.

**`vaulted` never claims the file IS in the vault.** `vault/` is 0700 root-only
and this code runs unprivileged, so it has not looked and cannot look. The claim
it is entitled to make is about the PREDICATE — the same pure function the
daemon evaluated at copy time on the same relpath — so it says the file "would
be held in the vault, which is unreadable without sudo".

Its two recovery commands are `log` and `cat`, under sudo with the opt-in
variable, and the second one uses a SHELL REDIRECT rather than `restore`:

```bash
sudo DHU_BACKUP_ALLOW_ROOT=1 /Library/DHU/backup/bin/dhu-backup --root-id repo log .env.local
sudo DHU_BACKUP_ALLOW_ROOT=1 /Library/DHU/backup/bin/dhu-backup --root-id repo cat .env.local > /path/to/.env.local
```

Both halves of that are deliberate. `DHU_BACKUP_ALLOW_ROOT` is what gets past
`refuse_root` **and** what makes `load_entries` walk `vault/` at all
(`trees_to_read`) — before this, the documented advice was
`sudo … dhu-backup restore <path>`, and it did not work, because the helper
joined the install root with `store` and nothing else. And the redirect is the
shell's, so the recovered file belongs to the invoking user. `restore` under
sudo would write it root-owned, the daemon would refuse it on the next scan as
`wrong-owner-uid`, and the file would stop being protected at the moment it was
recovered — so `restore` and `restore-dir` refuse root outright
(`restore_permitted`), opt-in or not.

Every non-`held` result also carries the daemon's health verdict — one of `ok`,
`degraded`, `unprotected`, `scan-failed`, `stale`, `no-heartbeat`,
`unreadable-heartbeat` — so `not-held` while capture has been dead for a day
reads as what it is. An unrecognised state label becomes `unreadable-heartbeat`
rather than `ok`: a newer daemon's status this version cannot interpret is a
thing to report, not to round down to healthy.

### Why it is cheap

It sits on the hot path of every failed read an agent tool makes, so it must not
cost what `dhu-backup ls` costs. `load_entries` walks the whole store — about
6,000 paths here — to answer anything at all, and nothing in the announce path
calls it. The store layout makes a direct lookup possible: a path's versions
live at exactly `store/<root-id>/<slug>/<relpath-dir>/@<capture>-<sha>/<basename>`,
so the one directory to list is computable from the path. Measured on this
machine against the live store:

| call | cost |
|---|---|
| `announce()` on a file, as a library call | **a few milliseconds** — 2–3 ms cold, under 1 ms warm |
| a directory query | **tens of milliseconds** |
| a directory query over an ENTIRE watch root | **~250 ms** |
| the whole `dhu-backup missing` process, held | **~75 ms**, mostly interpreter start |

A file lookup is one `listdir` plus one `lstat` per version directory found. A
not-held file costs two `stat`s and stops. The bounded walk happens only when
the path names a directory the store actually holds, and it stops at 10,000
paths and reports "at least N" rather than walking forever.

A HELD result pays a little more: one `listdir` of each matching version
directory and of each directory component, to learn the spelling the store
actually holds. On APFS the `lstat` above succeeds for `readme.md` against a
version of `README.md`, and `cat`/`restore`/`log` select by exact bytes — so
the result reports the store's spelling in `relpath` and `origin`, builds the
commands from it, and says so in `reason`. The path as given stays in `path`.

### Why it never raises

A recovery hint that throws inside an error handler turns a recoverable ENOENT
into a crash in the tool that was trying to help. Every `OSError` becomes a
`store-unavailable` result carrying the errno text — except the ones that ARE
answers: `ENOENT`/`ENOTDIR` (nothing here) and `ENAMETOOLONG`/`ELOOP` (a path
the filesystem cannot name, reported `not-held` with the reason) — and the outermost handler
catches everything else for the same reason — a contract that holds only for the
exceptions we thought of is not a contract. It is asserted directly against
hostile inputs (a NUL byte, an empty string, a relative path, `..`, `None`,
bytes) rather than assumed from reading the code.

The path is normalised but **never resolved through symlinks**. `realpath` is
absent deliberately: C7/C8 in the adversarial review is that resolve-then-check
is the race, and here it would be worse than a race, because the path comes from
the agent's own tree — one symlink there would aim the lookup at any watch root
on the machine and report its contents back.

### The MCP server

```bash
claude mcp add dhu-backup -- /usr/bin/python3 -E -s -S /Library/DHU/backup/bin/dhu-backup-mcp
```

Stdlib-only JSON-RPC 2.0 over newline-delimited stdio, MCP `2025-06-18`, seven
tools: `dhu_backup_status`, `dhu_backup_missing`, `dhu_backup_ls`,
`dhu_backup_log`, `dhu_backup_cat`, `dhu_backup_restore`,
`dhu_backup_restore_dir`. Each returns a JSON text block
plus `structuredContent`, and every result carries the daemon's health verdict —
including the catch-all for a tool that throws, which reports `kind:
internal-error` rather than blaming the store.
`dhu_backup_cat` returns UTF-8 when the content decodes and base64 otherwise,
with an `encoding` field saying which.

Arguments are checked against their declared types and a wrong type is a
`-32602` error, never a coercion: `overwrite` in particular must be a JSON
boolean, because `bool("false")` is true and that flag gates the one
destructive write. `dhu_backup_ls` returns at most 500 matches — a result is
one JSON frame handed to a model, and an unfiltered call against a real store
was 35 MB — with `match_count`, `truncated` and a `hint` to narrow the
substring when the cap binds. The two writers carry a `kind` beside
`exit_code`: `restored`, `unchanged`, `beside`, `no-match`, `ambiguous`,
`vaulted`, `no-version`, `bad-asof`, `refused-target`, `store-unavailable` or
`destination-unwritable`; only the last two and `refused` are `isError`.

At the transport, a frame that is not valid UTF-8, or is nested too deeply to
parse, is a `-32700` on that frame and the session continues. A message with
no `id` member is a notification and is not answered, whatever its method;
an `id` that is present and null is a request and is answered with null.

It adds **no privilege and no new write path**: it is the same unprivileged
helper behind a different transport, reading the world-readable store as the
caller and writing only where the caller could already write. It is stdio only —
no socket, no port, no listener — and it refuses to run as root, because under
sudo the caller-supplied `into` would become an arbitrary root write. It is
emphatically not a command channel into the daemon (anti-pattern 3 below):
nothing in it talks to the daemon, and the daemon has no input surface to talk
to.

### The Claude Code hook

Everything above waits to be asked. This is the piece that speaks first, and it
is what closes Property 4: no tool has to know `dhu-backup` exists, and no agent
has to have read this file.

Claude Code fires a `PostToolUseFailure` hook after a tool call fails
([hooks reference](https://code.claude.com/docs/en/hooks)). Register it in
`~/.claude/settings.json` (user-wide) or a project's `.claude/settings.json`:

```json
{"hooks": {"PostToolUseFailure": [{"matcher": "Read|Edit|Bash",
  "hooks": [{"type": "command",
             "command": "/usr/bin/python3 -E -s -S /Library/DHU/backup/bin/dhu-backup-hook"}]}]}}
```

The installer prints that snippet and does **not** apply it. The hook lives in
the user's own settings file, and a root installer that rewrote it would be
editing something the user owns; turning it on is yours to ratify, once per
machine.

The contract, as the hook implements it:

| | |
|---|---|
| stdin | one JSON object: `session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`, `tool_name`, `tool_input`, `tool_use_id`, `error`, `tool_response`, `is_interrupt` |
| paths | `tool_input.file_path` for Read and Edit; for Bash, path-like tokens from the command, the error and the response |
| stdout | `{"hookSpecificOutput": {"hookEventName": "PostToolUseFailure", "additionalContext": "…"}}`, or nothing at all |
| exit | always 0. Exit 2 would show stderr to Claude; this hook has no opinion worth that, and it cannot block a tool call in any case |

Two properties carry it, and both are negative:

**It is silent unless it has something to say.** `held`, `held-directory`,
`vaulted` and `store-unavailable` produce context. `not-held` and
`outside-watch-roots` produce nothing — a missing file that was never protected
is an ordinary error, and a hook that comments on every one of them is noise
that gets switched off. It also stays silent when the path still EXISTS, which
is what keeps it off every failure that is not a deletion: a permission denial
is not something the mirror can help with. `store-unavailable` is in the
announced set deliberately, because a protection that cannot be read is a
finding rather than a non-event.

**It never raises and never blocks.** It runs on the failure path of a tool an
agent is already recovering from, so an exception there would turn a recoverable
error into a broken hook. Malformed stdin, an unknown tool, a non-dict
`tool_input`, an interrupt: all silent, all exit 0. The one thing that reaches
stderr is an internal error it could not classify, and even that exits 0.

Bash token extraction is a pure function over strings and is tested as one. A
token counts as a path if it contains a `/` or ends in a file-ish suffix; a URL
never does, because it has slashes and would otherwise be joined to `cwd` and
looked up. Candidates are de-duplicated, capped at eight, and absolutised with
`normpath` — never `realpath`, for the same C7/C8 reason as the rest of the
announce path.

**What it echoes is rendered, not repeated.** The path in a Bash failure is
text from the OUTPUT of whatever the agent just ran, and the hook speaks with
the product's voice. In the prose lines every path-derived value goes through
`display_path`: control characters, `DEL`, the Unicode line separators, the
zero-width characters and the byte-order mark become their escapes (`\x0a`,
`\x1b`, `\u200b`) rather than vanishing, and anything past 512 characters
is replaced by a count. A newline in a path can no longer forge a second
`dhu-backup:` line, and an escape sequence no longer reaches a terminal. The
command lines keep the exact path for the shell, but a path carrying a control
character is quoted in bash's `$'...'` form with each such character as an
escape, so a command line is always one line too.

Live, against the real install, on a file that was deleted a session earlier. The
run happened on the author's own machine on 2026-09-02 and is recorded in
[`docs/PROOFS.md`](../docs/PROOFS.md); only the home-directory path is
generalised here:

```
$ echo '{"tool_name":"Read","cwd":"…/my-repo",
         "tool_input":{"file_path":"…/tm-live-probe-15354.md"},
         "error":"File does not exist."}' | dhu-backup-hook
dhu-backup: the file you just failed to read is held by the root-owned mirror —
dhu-backup: HELD — 2 version(s) of tm-live-probe-15354.md
  origin  /Users/you/Projects/my-repo/tm-live-probe-15354.md
  newest  2026-09-01T19:40:45  (15 bytes, sha 01b8d3b5b181)
  daemon  ok (the last capture was 10s ago)
    /Library/DHU/backup/bin/dhu-backup --root-id repo cat tm-live-probe-15354.md
    /Library/DHU/backup/bin/dhu-backup --root-id repo restore tm-live-probe-15354.md
    /Library/DHU/backup/bin/dhu-backup --root-id repo log tm-live-probe-15354.md
```

### `--json` on `ls` and `log`

```bash
dhu-backup ls  <substring> --json
dhu-backup log <path>      --json
```

The health banner is a line of prose, and printing it ahead of a JSON object
would make every answer unparseable — so callers would learn to pass `--quiet`
and would then never see that capture had stopped. In JSON mode the same verdict
becomes a `health` field of the object instead, carried rather than droppable.
Text output without `--json` is byte-identical to what it was before these
options existed, and a golden captured from the previous build asserts it.

### What this helper deliberately is not

The helper holds **no privilege the agent lacks**, and nothing about the
guarantee depends on it — an agent can bypass it entirely with `ls` and `cp`.
The kernel is the guarantee; `dhu-backup` is ergonomics. Three ways of "improving" it
would each rebuild a privileged path the agent could steer, and all three are
forbidden:

1. **No setuid-root helper.** The agent chooses the arguments; a setuid binary
   taking agent-chosen paths is an arbitrary root write.
2. **No `sudoers` NOPASSWD entry** for `dhu-backup` or for `tmutil`. Same defect,
   spelled differently, and it hands over passwordless root besides.
3. **No command channel into the daemon** — no request file, no FIFO, no socket
   it polls for "please restore/prune/forget X". Any of those turns the one
   process the agent cannot touch into a proxy it can steer. The daemon reads
   its root-owned config and the watched trees, and nothing else, ever.

Restores are logged to `~/.dhu-backup-restores.log`, which is agent-writable and
therefore **advisory only** — a courtesy trail for the owner, not a tamper-evident
record. The daemon's own capture log is the authoritative one.

## Tests

```bash
/usr/bin/python3 -m py_compile src/dhu-backupd.py src/dhu_backup_core.py \
    src/dhu-backup.py src/dhu_backup_announce.py src/dhu-backup-mcp.py \
    src/dhu-backup-hook.py
/usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'
```

720 tests, green on macOS under Python 3.9 and on Ubuntu under Python 3.14. The suite is
platform-aware rather than platform-specific: it asserts THIS platform's install
surface, and asserts the other platform's through `--dry-run --platform`, which
is what that flag exists for. Three tests that assert the scripts refuse without
root now SKIP when the suite runs as root — as root they did not assert a
refusal, they performed a real install and a real uninstall, which is what they
did the first time the suite was run inside a container.

`tests/test_platform_port.py` holds the port's own decisions as pure functions:
trigger selection for every platform string, the inotify mask constants pinned
against the kernel ABI, both install-root entries and the installer's shell copy
of them, the interpreter rule, the systemd unit parsed key by key, and the
shebang. Each of those catches a SILENT failure — a wrong mask bit, a
poll-only fallback, an install root the two halves disagree about, all still
capture files and all still report `ok`.

An agent can also `ln` a 0444 store file into its own workspace — linking needs
write permission only on the destination — which pins the inode so a later prune
frees nothing. Not corruption, a disk-consumption vector: the free-space floor is
the control that bounds it, and the prune reports every version it unlinked whose
link count was above one.

Every guarantee **in `dhu_backup_core.py`** is tested as a pure function over
fabricated inputs. `prune_plan` returns a plan; the executor that unlinks is in the daemon
and is never called by a test — this repo does not fire a destructive sink to
prove its guard. `dhu-backupd.py` itself has no unit tests: its properties (the openat
walk, `O_NOFOLLOW`, the `os.link` EEXIST append, the degraded stop) are proven by
a staging run instead, recorded in the build report in docs/PROOFS.md.

The credential predicate's population is DERIVED from its own patterns, never
written by hand. See **Credential predicate** below for what it proves and how
to regenerate it.

## Credential predicate

One predicate decides whether a captured file goes to the agent-readable
`store/` or the root-only `vault/`. It runs at copy time on the ORIGINAL
relpath, so a credential file never enters the readable half and no reader guard
is load-bearing (review C4).

**The source of truth is `src/credential_patterns.py`** — a data table, no
logic. `dhu_backup_core.credential_match` is the matcher that reads it, and
`is_credential_path` is that matcher's answer. The table holds 36 rules in five
kinds:

| kind | matched against | example |
|---|---|---|
| `dir-segment` | every segment, or every NON-FINAL segment | `.ssh`, and `.env` used as a directory |
| `config-dir` | a segment whose parent is `.config`, at any depth | `.config/gcloud/legacy_credentials/…` |
| `path-tail` | `<parent>/<name>` | `.git/config` |
| `basename-regex` | the basename — key material, NEVER excused by a template suffix | `id_rsa.example` is still a private key |
| `template-suffix-exempt` | the basename, unless it ends in `.example`/`.sample`/`.template`/`.defaults`/`.dist` | `.env` is a secret, `.env.example` is a committed template |

Every rule carries a one-line rationale, at least two example paths it must
REFUSE, and at least one it must ADMIT. The admitted example is the half that
bounds strictness: without it, "refuse everything" would satisfy every other
test in the suite.

### The derived fixture, and what it proves

`tests/credential_fixture_own.json` — 285 rows, generated by
`src/tools/derive-own-fixture.py` from the rules' OWN regexes. Every regex is
expanded into every string it can match (the expander RAISES on any construct it
does not model — a silent "could not expand" would shrink the population back to
whatever happened to be expressible), then probed in four shapes: bare, nested,
as a directory holding a file, and under `.config/`. Each row records which rule
GENERATED it and which rule FIRED, so a rule that never fires on its own probes
is detectable rather than invisible. That is what proves the rules are live and
do what they say, rather than merely present.

The population is DERIVED from the patterns, never written by hand and never
derived from the tests. An earlier fixture in this predicate's history was built
from a guard's TEST LITERALS instead of its patterns: that population exercised
about a third of the rules, and twelve mutations of real patterns left the suite
green. A fixture derived from tests is a claim about the tests.

Regenerate it with:

```bash
/usr/bin/python3 src/tools/derive-own-fixture.py
```

### Mutation check (executed by hand, in a scratch copy, never automated)

Each of the 36 rules was deleted in turn from a COPY of the repo and the full
suite re-run. **Every deletion turned at least one test red; there were no
survivors.** Neutering the template-suffix constant did too. This is run by
hand and recorded, not wired into the suite: a test that edits source is a test
that can leave the tree mutated when it fails.

The rules are caught by the routing fuzz and by the derived fixture's
`test_every_recorded_verdict_still_holds`. One row is asymmetric and is a real
finding rather than a gap: `.git/credentials` is already refused by the
`^credentials$` basename rule, so deleting the `path-tail` rule for it changes
the REASON reported and no verdict. Only a population that records WHICH RULE
FIRED can see that. That is what a rule-level fixture buys over a verdict-level
one.

### `etc/vault-extra.conf` — the operator's additive extension

Optional and never shipped: the installer prints how to create it and installs
nothing. One basename glob per line, `#` comments, `fnmatch` on the BASENAME
only and case-insensitively.

```
# /Library/DHU/backup/etc/vault-extra.conf
*.secret
payroll-*.csv
```

**It can only ADD refusals, and that is the type rather than a convention.**
`destination_for` ORs the extension into the base predicate, so there is no
value of this file that makes a path readable which the patterns refuse. A line
containing `/`, `..`, a NUL byte, or more than 256 globs is REFUSED, logged, and
counted — never dropped silently, because an operator who believes a glob is in
force and is wrong has a false sense of protection. A path-shaped line is
refused rather than reinterpreted: it would look like it constrained a directory
and would constrain nothing.

The daemon reads it at startup from the same root-owned `etc/` as its other
config; kick the daemon after editing it. Two heartbeat fields report it:

```
"vault_extra_globs": 2, "vault_extra_refused": 2
```

The unprivileged side reads the same 0644 file, so `dhu-backup missing` on a
file matching an extra glob answers `vaulted` with the glob named, rather than
`not-held`.

### What this predicate still is not

It is NAME-BASED, and stays that way deliberately. The daemon must never read a
file's CONTENT to decide where it goes: a content heuristic that guesses "this
is not a secret" puts the file in the agent-readable half, and that is exactly
the C4 laundering the split store exists to prevent. A name-based rule that is
too broad costs the operator one `sudo`; a content guess in the readable
direction is unrecoverable.
