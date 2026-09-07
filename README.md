# DHU Backup

An append-only mirror of the files a coding agent can delete, written by a root
daemon that agent cannot touch, readable by the agent that needs its work back.

## The problem

A coding agent runs as you. It is fast, tireless, and occasionally wrong at a
scale a human never manages — and it will edit its own safety guard and then run
the edited version. The failure that started this project was one of those: an
agent mutation-testing its own code unguarded a recursive delete and destroyed
the git worktree it was running in. The committed work survived, because git's
object store is append-only once you commit. Roughly an hour of uncommitted
tests did not, because they existed nowhere but the directory the agent deleted.

Every existing safety net trusts your account, so none of them helps. Time
Machine, APFS local snapshots, editor local history and cloud-sync version
history are all deletable by the owner's own processes, and an agent running as
you *is* the owner's own process — deleting a local snapshot takes one command
and no sudo. Vendor checkpoints cover only the edits made through that vendor's
own tools, so a shell `rm -rf` is invisible to them. Git covers committed state,
and agents do not commit mid-task.

What is missing is a copy the owner's own processes cannot touch. That needs a
second principal, which means root, which means one deliberate install.

## Four properties

1. **Continuous.** About a second for a new file on both platforms. An in-place
   rewrite is under a second on Linux and waits for the 15-second floor sweep on
   macOS, because a directory watch there does not fire for a rewrite in place.
2. **Agent-accessible recovery.** `ls`, `log`, `cat`, `restore`, `restore-dir`,
   `missing`, all with `--json`. No app, no human step, no sudo.
3. **Agent-untouchable.** The store is root-owned, directories 0755 and files
   0444. The kernel refuses the write. The daemon is a LaunchDaemon or a systemd
   system unit, so the owner's account cannot stop or kill it either.
4. **Self-announcing.** When a read fails with "no such file" on a path the
   mirror holds, the error itself names the versions and prints the command that
   reads them back. That is what reaches an agent which never read this file.

## Install

One sudo, once, by a human. The install root is fixed per platform; what you
choose is which directories are watched.

```bash
# macOS  ->  /Library/DHU/backup
sudo bash src/install.sh --watch repo=/Users/you/Projects/my-repo

# Linux  ->  /opt/dhu-backup
sudo bash src/install.sh --watch repo=/home/you/proj
```

`--watch <id>=<abs-path>` is repeatable, and `--watchlist <file>` reads the same
pairs from a file. There is deliberately **no default watchlist**: a default
would name directories that do not exist on your machine, and the installer
would print OK over a store protecting nothing. With no roots given and none
already installed, it refuses before touching anything.

See the whole plan before you type sudo. `--dry-run` needs no privilege and
prints the rendered watchlist and every directory and file with its mode,
source and destination:

```bash
bash src/install.sh --dry-run --watch repo=/Users/you/Projects/my-repo
```

**Read `install.sh` before running it.** Running it with sudo is a one-time
transfer of trust to code delivered from a directory an agent can write. There
is no way around that for a root daemon. The mitigations are that the script is
short enough to read, it prints the owner, mode and sha256 of everything it
installs, and after installation nothing in this repo is on the trust path.

Uninstall keeps the captured history:

```bash
sudo bash src/uninstall.sh --dry-run   # the plan, unprivileged, changes nothing
sudo bash src/uninstall.sh             # stop and remove the daemon
sudo bash src/uninstall.sh --purge --yes   # ... and delete store/, vault/, var/
```

`store/`, `vault/` and `var/` survive an ordinary uninstall, and their sizes are
printed. An uninstaller that deletes them because you wanted to stop a daemon
has destroyed the thing it was protecting.

## Recover

```bash
dhu-backup ls   <path-substring>              # which protected paths have versions
dhu-backup log  <path>                        # versions of one path: time, size, hash
dhu-backup cat  <path> --asof 20m             # print one version to stdout
dhu-backup restore     <path> [--asof 20m] [--into DIR]
dhu-backup restore-dir <dir>  [--asof 20m]    # a deleted directory back in one command
dhu-backup missing <ABSOLUTE path>            # what the store holds for a path that is GONE
```

`ls`, `log` and `missing` also take `--json`.

`dhu-backup` is `/Library/DHU/backup/bin/dhu-backup` on macOS and
`/opt/dhu-backup/bin/dhu-backup` on Linux. Call it by its full path, or put that
directory on your `PATH`. The installer creates no symlink into `/usr/local/bin`
and that is deliberate: on both platforms that directory is writable by the
account the agent runs as, so a convenience symlink there is a command an agent
could replace with its own. The real binary sits where the kernel protects it.

`--asof` takes an ISO timestamp or a relative age (`20m`, `2h`, `3d`) and
resolves to the newest version at or before it. If none qualifies it returns
nothing, rather than quietly handing back the newest version.

`restore` derives its destination from the stored path plus the watch root; the
caller never names the target file. Nothing is silently clobbered — if the
target exists with different content it writes `<name>.restored-<tag>` beside
it, says so, and exits non-zero. `--overwrite` opts into the in-place write.

Every invocation prints the daemon's health first, so "no versions" is never
mistaken for "capture stopped two days ago". In `--json` mode that verdict
becomes a `health` field of the object, so it is carried rather than droppable.

A credential-class file is in the root-only vault, and recovering it is yours to
do with sudo. It is a read and a shell redirect, never a `restore`:

```bash
sudo DHU_BACKUP_ALLOW_ROOT=1 dhu-backup log .env.local
sudo DHU_BACKUP_ALLOW_ROOT=1 dhu-backup cat .env.local > /path/to/.env.local
```

The redirect belongs to your shell, so the recovered file belongs to you.
`restore` under sudo would write it root-owned, and the daemon would then refuse
it as `wrong-owner-uid` — un-protecting the file at the moment of recovery. That
is why `restore` and `restore-dir` refuse root outright.

## Self-announcing

Everything above waits to be asked. These two registrations make the mirror
speak first.

A Claude Code `PostToolUseFailure` hook, in `~/.claude/settings.json` or a
project's `.claude/settings.json`:

```json
{"hooks": {"PostToolUseFailure": [{"matcher": "Read|Edit|Bash",
  "hooks": [{"type": "command",
             "command": "/usr/bin/python3 -E -s -S /Library/DHU/backup/bin/dhu-backup-hook"}]}]}}
```

An MCP server, for any agent framework that speaks MCP:

```bash
claude mcp add dhu-backup -- /usr/bin/python3 -E -s -S /Library/DHU/backup/bin/dhu-backup-mcp
```

The installer **prints** both and applies neither. They live in files you own,
and a root installer that rewrote them would be editing something that is yours
to ratify.

The hook is silent unless it has something to say. A file that was never
protected produces no output at all, and the hook always exits 0. It never
blocks a tool call and never raises.

## How it works

A root LaunchDaemon on macOS, a systemd system unit on Linux, running the system
`python3` with `-E -s -S` from a root-owned directory. It walks the watched
roots and copies changed files into `store/` or `vault/`.

- **The agent cannot write the store.** Everything under the install root is
  root-owned. The daemon pulls; agents never push, so there is no write path to
  revoke.
- **The agent can read `store/`.** Directories 0755, files 0444, so recovery
  needs no sudo. Unlink and rename require write permission on the *parent*
  directory, which no agent has at any level.
- **Nothing is ever overwritten.** A version is created with `os.link()`, which
  fails `EEXIST` rather than clobbering. Append-only is a syscall property here,
  not a rule the daemon remembers.
- **Credential-class files go to `vault/` (0700, root-only).** They are still
  captured, so a deleted `.env.local` is recoverable by you with sudo, but they
  never become agent-readable.

Capture is event-driven with a poll underneath it. A watch on each watched
directory wakes the daemon — kqueue `EVFILT_VNODE` on macOS, inotify on Linux —
and a 15-second floor sweep runs beneath it as the guarantee. The trigger is an
accelerator, never on the trust path: a missing or spoofed event costs one
sweep and nothing else.

| change | macOS (kqueue) | Linux (inotify) |
|---|---|---|
| a new file | ~1 s | ~1 s |
| an in-place rewrite (`echo x > f`) | the 15 s floor sweep | under 1 s |

Linux is faster on the second row because a directory inotify watch reports
`IN_CLOSE_WRITE` for files written inside it and a directory kqueue has no
equivalent. That is a measurement on both platforms, not an inference.

The walk descends with directory file descriptors. Each directory is opened
`O_RDONLY|O_DIRECTORY|O_NOFOLLOW` relative to its parent's fd, each file by
basename relative to its directory's fd, and every admission decision is made on
the `fstat` of the *open* fd: regular file, `st_nlink == 1`, owned by the
configured uid, not setuid or setgid, at most 1 MiB, outside the excluded
directories and extensions. No path string is ever re-resolved, so there is no
window in which a checked name can be swapped for a symlink or a hard link.

## What it deliberately is not

Three ways of making recovery more convenient would each rebuild a privileged
path an agent could steer. All three are forbidden, and the reason is the same
each time: the agent chooses the arguments.

1. **No setuid-root helper.** A setuid binary taking agent-chosen paths is an
   arbitrary root write.
2. **No `sudoers` NOPASSWD entry.** The same defect spelled differently, and it
   hands over passwordless root besides.
3. **No command channel into the daemon.** No request file, no FIFO, no socket
   it polls for "please restore or prune X". Any of those turns the one process
   the agent cannot touch into a proxy it can steer. The daemon reads its
   root-owned config and the watched trees, and nothing else, ever.

The recovery helper holds no privilege the agent lacks, and nothing about the
guarantee depends on it. An agent can bypass it with `ls` and `cp`. The kernel
is the guarantee; the helper is ergonomics.

## Honest limits

Stated here rather than in an FAQ, because each one is a boundary someone will
otherwise discover at the worst moment. [`docs/LIMITS.md`](docs/LIMITS.md) has
the full page.

- **macOS and Linux only.** There is no Windows port and none is planned.
- **No userspace watcher can promise that nothing is missed.** A file whose
  entire lifetime is shorter than the notice-to-read latency is never seen. True
  no-miss capture needs write-path interposition — an EndpointSecurity client or
  a FUSE layer — and neither is what this is.
- **Files created and deleted inside one interval are missed.** The window is 15
  seconds. The work the founding incident lost had lived an hour.
- **Root and the human owner are not defended against.** Anything with root can
  remove the store. This protects work from agents, not from you.
- **A hard link un-protects a file.** `st_nlink == 1` is a property of the
  *inode*, so `ln notes.md x` stops both names being mirrored until the link
  goes. Versions already captured survive, the refusal is logged and counted,
  and protection resumes on the next scan. Kept as specified, because the
  alternative is a root reader that follows hard links.
- **The credential predicate is name-based, not content-based.** An agent that
  renames `.env.local` to `docs/notes.md` puts the bytes at an admitted path.
  Content-based detection is refused rather than unbuilt: a daemon deciding from
  a file's contents can only fail in the readable direction, and a wrong "this
  is not a secret" puts the file in the agent-readable half, which is exactly
  the laundering the split store exists to prevent. A name-based rule that is
  too broad costs one `sudo`; a content guess in the readable direction is
  unrecoverable.
- **Not a git replacement, not a database backup.** "Commit often" is still the
  first line of defence.

## Tests

```bash
/usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'
```

413 tests, green on macOS under Python 3.9 and on Ubuntu under Python 3.14. CI
runs the same suite on `macos-latest` and `ubuntu-latest`, which is the standing
proof that it passes on a clean machine with nothing from a developer's own.

Further reading: [`src/README.md`](src/README.md) is the operator's guide,
[`docs/DESIGN.md`](docs/DESIGN.md) is the design and threat model,
[`docs/PROOFS.md`](docs/PROOFS.md) is the recorded execution evidence, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) is the short list of rules this codebase is
held to.

## Licence

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
