# Execution evidence

**These are recorded runs on the author's own machines, not a CI result.** They
were transcribed from the terminal at the time, not reproduced for this
document. Home directories have been generalised to `/Users/you` and
`/home/you`; nothing else in the observed output is edited. The machines are not
identified.

What CI does prove, on every push, is that the 522-test suite passes on a clean
`macos-latest` and `ubuntu-latest` runner with nothing from a developer's own
machine. What CI cannot prove is anything that needs a root daemon actually
installed, which is everything below.

Two things follow from that. Every "MUST FAIL" line here is a claim about the
kernel refusing an unprivileged process, and you can re-run all of them yourself
after installing. And every latency figure is one measurement on one machine,
not a benchmark.

---

## 1. macOS — the root-only guarantees

Run as the owner's own account, with **no sudo**, after `sudo bash
src/install.sh`. The first three must succeed; every line after them must fail.

| command | observed |
|---|---|
| `ls /Library/DHU/backup/store` | the watch-root directories — OK |
| `cat /Library/DHU/backup/var/state.json` | counts and states, no paths — OK |
| `dhu-backup ls heartbeat.ts` | `7 version(s)` — OK, no sudo |

```
touch /Library/DHU/backup/store/x                          -> Permission denied
rm -rf /Library/DHU/backup/store                           -> Permission denied (every
                                                              entry; store still present)
echo x > /Library/DHU/backup/bin/dhu-backupd               -> permission denied
echo x > /Library/LaunchDaemons/com.dhulabs.backup.plist   -> permission denied
ls /Library/DHU/backup/vault                               -> Permission denied
launchctl bootout system/com.dhulabs.backup                -> Boot-out failed: 1:
                                                              Operation not permitted
pkill -f dhu-backupd; pgrep -fl dhu-backupd                -> Operation not permitted;
                                                              still running
```

`launchctl print system/com.dhulabs.backup` reported `state = running` with a
root pid throughout.

## 2. macOS — capture, admission and recovery

In a watched root, all as the owner, no sudo.

| step | observed |
|---|---|
| a new file written | 1 version, captured 8 seconds later by the kqueue trigger |
| `ln README.md hardlink-probe` | daemon log: `refused repo/hardlink-probe: hardlink-nlink=2` |
| an in-place rewrite | a 2nd version, captured by the floor sweep |
| `rm` both files | `dhu-backup cat <path>` printed the second version's contents |
| `dhu-backup restore <path>` | the file back at its origin, content matching version two |

A first scan of a real working tree: 6,259 files, 77 MB, 1,506 directories,
`state: ok`. A `.env.local` in that tree went to `vault/`, with no copy under
`store/`.

## 3. macOS — the self-announcing hook, end to end

The hook was registered in the user's own settings file as a
`PostToolUseFailure` hook with matcher `Read|Edit|Bash`, and the MCP server
added user-wide (`claude mcp add --scope user dhu-backup …`, status
`Connected`). A coding-agent session's own Read tool was then pointed at a file
that had been deleted the night before.

The Read failed with "File does not exist", and the failure carried, injected by
the hook:

```
dhu-backup: the file you just failed to read is held by the root-owned mirror —
dhu-backup: HELD — 2 version(s) of probe.md
  origin  /Users/you/Projects/my-repo/probe.md
  newest  2026-09-01T19:40:45  (15 bytes, sha 01b8d3b5b181)
  daemon  ok (the last capture was 10s ago)
    /Library/DHU/backup/bin/dhu-backup --root-id repo cat probe.md
    /Library/DHU/backup/bin/dhu-backup --root-id repo restore probe.md
    /Library/DHU/backup/bin/dhu-backup --root-id repo log probe.md
```

No tool called `dhu-backup`, and no instructions file was read. That is the
whole point of property 4.

## 4. Linux — a real systemd host

Ubuntu 26.04.1 LTS, aarch64, kernel 7.0.0-28, **systemd booted**, polkit
installed, in a virtual machine with host filesystem mounts **disabled** so the
root daemon could not see the host at all. Python there is **3.14** — the code
targets 3.9 syntax, so this run doubles as a forward-compatibility check.

An earlier container run had proven the installer, the inotify latencies, the
admission guards and the whole recovery CLI, but a container has no systemd, so
the unit loading, polkit, and the unit's hardening were all unexercised. This
run closes that gap.

Installed with `sudo bash src/install.sh --watch proj=/home/you/proj`:

```
OK — the daemon is running and protecting the roots above (1 active, 0 refused)
```

`systemctl show` reported `ActiveState=active` and
`FragmentPath=/etc/systemd/system/dhu-backupd.service`; the process was
`root … /usr/bin/python3 -E -s -S /opt/dhu-backup/bin/dhu-backupd`.

### The root-only guarantees, as the owner, no sudo

```
systemctl stop dhu-backupd.service  -> Failed to stop: Access denied as the requested
                                       operation requires interactive authentication.
kill -9 <mainpid>                   -> Operation not permitted
touch /opt/dhu-backup/store/x       -> Permission denied
rm -rf /opt/dhu-backup/store        -> Permission denied (every entry; store intact)
echo x > .../bin/dhu-backupd        -> Permission denied
echo x > /etc/systemd/system/dhu-backupd.service -> Permission denied
ls /opt/dhu-backup/vault            -> Permission denied
                                    -> service still active, pid still running
```

The polkit refusal is the Linux form of the launchd `Operation not permitted`
proof, and it is the one thing no container could establish.

### Capture, measured on both platforms

| change | Linux (inotify) | macOS (kqueue) |
|---|---|---|
| a new file | **1 s** (`IN_CREATE`) | ~1 s |
| an in-place rewrite (`echo x > f`) | **under 1 s** (`IN_CLOSE_WRITE`) | the 15 s floor sweep |

A directory watch on Linux reports writes to files inside it; on macOS it does
not. That is a measurement on both platforms, not an inference. A separate pair
of measurements taken the same way on an earlier date gave 0.55 s for a new file
on both platforms, and 0.57 s against 29.97 s for the in-place rewrite.

### Admission and the split store

`ln /etc/shadow ~/proj/lib/innocent.md` was refused by the **kernel**
(`fs.protected_hardlinks`) before the daemon saw it, so the daemon's own guard
was exercised separately with a link the kernel permits — a link to one of the
owner's own files, which the uid check alone would admit:

```
ln ~/proj/lib/notes.md ~/proj/lib/linked.md   -> succeeded, nlink=2
daemon log: refused proj/lib/linked.md: hardlink-nlink=2
in store: 0
```

A `.env.local` containing `NEXTAUTH_SECRET=hunter2`: **0** copies under
`store/`, `grep -rl hunter2 /opt/dhu-backup/store` returned **0 files**, and the
version was in `vault/proj/proj-<slug>/@…/.env.local`, unreadable without sudo.

Heartbeat at that point: `trigger=inotify`, `trigger_watch_failures=0`,
`interpreter_root_owned=true`, `vaulted=1`, `state=ok`.

### Recovery and self-announcement, unprivileged

`rm -rf ~/proj/lib` — the founding incident's shape — then, as the owner:

- `dhu-backup missing …/lib/probe.md` reported `HELD — 2 version(s)` with the
  three recovery commands.
- `restore-dir lib` returned `2 restored, 0 skipped, 0 failed`, content correct
  and **owned by the user, not root**.
- The `PostToolUseFailure` hook, fed a Bash failure payload, returned the HELD
  block as `additionalContext`. Fed a missing path that was never protected, it
  printed nothing and exited 0.

### The unit's hardening, confirmed by systemd itself

`systemd-analyze security` reported `NoNewPrivileges=` ✓, `ProtectSystem=` ✓
(strict, read-only OS hierarchy), and `PrivateTmp=` ✓. `ProtectHome=` scores ✗
at weight 0.1 because it is `read-only` rather than absent — deliberate, since
the daemon must **read** home directories to mirror them, and `ProtectHome=yes`
would give it an empty tmpfs, refuse every watch root, and report `unprotected`:
healthy, protecting nothing.

Overall exposure was **7.8, "EXPOSED"**, which is systemd's expected score for
any service that runs as root and reads the filesystem. It is recorded here
rather than omitted. None of the hardening keys is load-bearing for the
product's guarantee — that is the kernel refusing an agent's write to a
root-owned directory, and it holds with all of them switched off. They narrow
what this root process can do to the host, which is worth having in a process
that reads agent-written trees.

### Uninstall, for real

`sudo bash src/uninstall.sh` stopped and disabled the service, removed the unit,
`bin/` and `etc/`, and **kept** `store/`, `vault/` and `var/`: 6 captured files
before, 6 after. A reinstall then showed the full history intact.

### One finding, from running it

`uninstall.sh` removes `etc/`, which holds `watchlist.conf`. A reinstall with no
`--watch` therefore refuses with "no watch roots" — correct, and surprising: the
history was kept while the list of directories it belongs to was not.

Nothing is lost that the operator cannot retype, and the refusal is loud rather
than silent, so the uninstaller now **prints** the watch roots it is about to
remove, as ready-to-paste flags, single-quoted (a root may end in the one
permitted trailing `*`, and an unquoted paste would let the pasting shell expand
it into something else). An absent or unreadable watchlist is reported rather
than passed over. Verified on the same host:

```
the watch roots you are about to lose (etc/ is removed; store/ is not):
  re-create them with:
    sudo bash install.sh --watch 'proj=/home/you/proj'
```

## 5. What is still unproven

- **Survival across a reboot** on either platform. The service files declare it
  (`KeepAlive` on macOS, `Restart=always` plus `enable` on Linux) and the
  installer asserts the service is registered, but no run here has rebooted the
  machine and re-checked.
- **The daemon's own module has no unit tests.** Its properties — the openat
  walk, `O_NOFOLLOW`, the `os.link` EEXIST append, the degraded stop — are
  proven by the staging runs above rather than by the suite. Every guarantee in
  the pure decision core is unit-tested; `prune_plan` returns a plan and the
  executor that unlinks is never called by a test.
- **The mutation check on the credential rules is run by hand**, in a scratch
  copy, and recorded. Each of the 36 rules was deleted in turn and the full
  suite re-run; every deletion turned at least one test red, with no survivors,
  and neutering the template-suffix constant did too. It is not wired into the
  suite on purpose: a test that edits source is a test that can leave the tree
  mutated when it fails.
