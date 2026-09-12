# Execution evidence

**These are recorded runs on the author's own machines, not a CI result.** They
were transcribed from the terminal at the time, not reproduced for this
document. Home directories have been generalised to `/Users/you` and
`/home/you`; nothing else in the observed output is edited. The machines are not
identified.

What CI does prove, on every push, is that the 716-test suite passes on a clean
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

## 6. The independent review of 2026-09-11

A review with no hand in the code, briefed to attack the claims by execution,
on the same two machines. What it found is recorded here for the same reason
everything above is: it was run, not argued.

### Retention was keyed on the directory, not the file — v0.1.0 and v0.2.0

Every file in one source directory keeps its version directories as siblings
under the same store directory. `existing_versions` listed that directory and
handed the whole list to the rolling window, and `prune_plan` kept the newest
version per directory. Both plans were therefore rules about the directory.

**The window, live on the macOS install (ten days old):** the daemon log held
552 `reached 200 versions — rolling the window` lines. In the directory that
triggered most of them, a directory of small JSON records:

| | |
|---|---|
| files in the source directory | 342 |
| version directories in the store | **200** |
| distinct files with at least one version | **200** |
| files with no version at all | **142** |

The same rolling had fired on the repository's top-level directory and on two
source directories. `status` reported paths *held* and was correct; it had no
way to know about the ones that were not.

**Reproduced on the Linux install from the newest source:** 230 distinct files
written into one empty directory. After the first scan the store held exactly
200 version directories for 200 of them; one more file written afterwards
rolled another sibling's only version out.

**The prune, simulated as a pure plan over the real macOS store**, with the
clock set 31 days ahead and nothing deleted:

| | |
|---|---|
| version directories | 37,478 |
| store directories | 6,841 |
| versions the plan would delete | **30,637** |
| mirrored paths that would keep a version | 6,841 (one per directory) |
| mirrored paths that would lose every version | **27,808 of 34,649** |

The first hourly prune after the install turned 30 days old would have done
that. All eleven prune tests passed throughout, because each used one file per
directory: the claim and its evidence did not share a population.

Both plans are keyed on `(directory, leaf)` now, the tests build several files
in one directory, and the daemon forgets at start and after every prune any
indexed path the store no longer holds a version of, so it is captured again
on the next scan. Versions the old window removed were removed; the source
files were never touched.

### More, each by execution

- **The content de-duplication never ran.** A 64-character digest was compared
  against a set of 12-character prefixes. `touch` on an unchanged file wrote a
  second version with the identical hash. It now compares against the newest
  version of the same path only, so a revert to older content still gets its
  own version.
- **A name that is not valid UTF-8 switched protection off for its whole
  root.** One file with two invalid bytes in its name, in a watched tree on the
  Linux install: every scan raised `UnicodeEncodeError` at the index lookup,
  `state` went to `scan-failed`, files after it in the walk were no longer
  captured, and the index transaction was never committed — for as long as the
  file existed. It is an ordinary refusal now, `walk-name-not-utf8`, and the
  walk continues. APFS refuses to create such a name; ext4 does not.
- **An agent-named directory could sit in the store's own namespace.** A
  directory named like a version key, created inside the watched tree, reached
  the store and was listed by the reader as a version dated in 2027 whose
  "leaf" was a directory; `cat` on it raised `IsADirectoryError`. The walk
  refuses the shape (`walk-version-key-shaped`), the path check refuses it, and
  the reader requires a regular file where the leaf should be.

- **The paste-ready `--watch` line could carry a command.** The installer's
  suggestion wrapped each candidate path in bare single quotes. A git working
  tree named `proj'$(id>/tmp/PWNED)'x` under the home — a name an
  unprivileged agent can create — produced a line in which `$(id>/tmp/PWNED)`
  sat outside the quotes, and tokenising it ran the substitution; pasted with
  `sudo`, it would have run as root before the installer started. Terminal
  escape sequences in names reached the terminal raw. Paths are now quoted
  with every embedded quote closed and re-opened, and a name carrying a
  control character is omitted and counted.
- **An owner-owned file under a root-owned `0700` directory was mirrored
  world-readable.** On the Linux install: `cat` on the original was refused,
  and 25 seconds later the copy in `store/` read back with no sudo. The walk
  now refuses any directory the owner could not enter, on the fstat of the
  open fd, and the same rule applies to every watch-root component.
- **A write that failed for want of space left an empty version directory and
  an orphan staging file**, and nothing swept or reported them (simulated by
  making `os.write` raise `ENOSPC`). The version directory is now created only
  after the bytes are on disk, the staging file is removed on every failure,
  and the daemon sweeps `var/tmp` at start and says how many it removed.
- **A corrupted index was a restart every two seconds** with a frozen `ok`
  heartbeat and no ERROR line, because `open_index` raised outside any
  handler. The index is a cache; a file that is not a database is moved aside
  with an ERROR line and a fresh one opened, at the cost of one re-hash.
- **A backwards wall-clock step would have keyed the newest capture as the
  oldest**, and the rolling window discards the oldest first (shown over the
  pure functions, not on a real clock change). Keys are kept monotonic per
  path.

### Proof items closed by the same review

- **The confirmation prompt has now prompted**, on the Linux host with a real
  terminal: it asked; EOF aborted with nothing written; `no` aborted; `yes`
  installed; and a pipe with no terminal proceeded, printing that no human had
  confirmed the plan. The unit file and the daemon binary kept their old
  timestamps across both aborts.
- **`warning` fired live on Linux**: a 20 GiB volume with 14.6 GiB free
  against the 10 GiB floor reported `warning free-space-low`, and the installer
  finished with `INSTALLED AND CAPTURING — BUT CAPTURE WILL STOP` in place of
  its OK line, exit 0.

## 5. What is still unproven

- **Survival across a reboot** on either platform. The service files declare it
  (`KeepAlive` on macOS, `Restart=always` plus `enable` on Linux) and the
  installer asserts the service is registered, but no run here has rebooted the
  machine and re-checked.
- **The daemon's walk and copy path are proven by the staging runs above, not
  by the suite.** The daemon module has unit tests (its state ordering, the
  operator exclusions, the heartbeat fields, and since the review the per-path
  version listing, the two new walk refusals and the index reconciliation), but
  the openat walk with `O_NOFOLLOW`, the `os.link` EEXIST append and the
  degraded stop are exercised only by installing it. Every guarantee in the
  pure decision core is unit-tested; `prune_plan` and `version_window_plan`
  return plans, and the executor that unlinks is never called by a test.
- **Some numbers in the other documents come from runs not transcribed here**:
  the 33 GB directory behind the installer's timeout, the APFS snapshot deleted
  without sudo, the `ln /etc/sudoers` link count, the 14.1 GiB `ok` that
  motivated `warning`, and the refusal-log volume. Each was observed on the
  author's machines and is stated where it is used; none has a transcript in
  this file.
- **The mutation check on the credential rules is run by hand**, in a scratch
  copy, and recorded. Each of the 36 rules was deleted in turn and the full
  suite re-run; every deletion turned at least one test red, with no survivors,
  and neutering the template-suffix constant did too. It is not wired into the
  suite on purpose: a test that edits source is a test that can leave the tree
  mutated when it fails.
