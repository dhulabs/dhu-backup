# Security policy

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting.** On this repository, open the
Security tab and choose *Report a vulnerability*. That opens a private advisory
only the maintainers can see, and it is the preferred route because it keeps the
report, the fix and the disclosure in one place.

If you would rather not use GitHub, email **support@dhulabs.com** with
`SECURITY` in the subject line, so it is not read as an ordinary support
request.

Either way, please do not open a public issue for a vulnerability.

Include what you need to make the finding reproducible: the platform and
version, the commands you ran, and what you observed rather than what you
concluded. A finding that can be demonstrated by execution is worth far more
here than one argued from reading the source, because most of this project's
own findings came from running it.

Expect an acknowledgement within a few days. If a report is valid we will agree
a disclosure timeline with you before anything is published.

## In scope

Anything that breaks one of the four properties the product claims.

- **A path by which a process running as the owner can write, delete, truncate
  or corrupt anything under the install root.** That is the whole guarantee.
- **A path by which a process running as the owner can stop, kill, unload or
  starve the daemon**, or make it report `ok` while capturing nothing.
- **A credential-class file reaching the agent-readable `store/`.** The split
  store exists so that `store/` holds only what the guards an agent already runs
  under would let it read. A path shape that lands a secret in the readable half
  is a finding.
- **Anything that makes the root daemon read or copy a file outside a configured
  watch root**, or copy a file it does not admit — a symlink followed, a hard
  link admitted, a time-of-check window between the notice and the copy.
- **Any way to get the root daemon to execute bytes the owner's account can
  replace**, including through the interpreter, its resolved symlink target, or
  anything on `sys.path`.
- **Privilege gained through the unprivileged helper, the MCP server or the
  hook.** They are supposed to hold no privilege the caller lacks. If one does,
  that is a finding.
- **A denial of service that is silent.** Capture stopping is acceptable and
  designed for; capture stopping while the heartbeat still says `ok` is not.

## Explicitly out of scope

These are named boundaries, not oversights. A report about one of them will be
closed as working-as-designed, so they are listed here rather than discovered in
a reply.

- **Root.** Anything running as root can remove the store, replace the daemon
  and rewrite the config. There is no defence against root in a design whose
  entire mechanism is "root owns the copy".
- **The human owner.** The owner installs this deliberately and can uninstall it
  deliberately, with sudo. This protects work from agents, not from the person
  who owns the machine.
- **A hard link un-protecting a file.** `st_nlink == 1` is a property of the
  inode, so `ln notes.md x` stops both names being mirrored until the link is
  removed. This is a deliberate trade: the alternative is a root reader that
  follows hard links, which is the file-disclosure oracle the check exists to
  close. Versions already captured survive, and the refusal is logged and
  counted in the heartbeat.
- **The userspace-watcher ceiling.** No userspace watcher can promise that
  nothing is missed. A file whose entire lifetime is shorter than the
  notice-to-read latency is never seen, and a file created and deleted inside
  one 15-second interval is missed. Closing this needs write-path interposition
  — an EndpointSecurity client or a FUSE layer — which is a different product.
- **The name-based credential predicate.** It cannot see content, so renaming a
  secret to an ordinary-looking path puts the bytes at an admitted path. Content
  inspection is refused on purpose: a wrong "this is not a secret" is
  unrecoverable, while a wrong "this is a secret" costs one `sudo`. A report
  that a *specific credential file shape* is admitted is very much in scope; a
  report that renaming defeats a name-based rule is not.
- **The installer as a trust transfer.** `install.sh` ships from a directory an
  agent can write and runs under sudo, so an agent could edit it before you run
  it. There is no way around this for a root daemon. It is kept short enough to
  read, it prints the sha256 of everything it installs, and after installation
  nothing in the repo is on the trust path.
- **The restore log.** `~/.dhu-backup-restores.log` is agent-writable and
  therefore advisory only. It is a courtesy trail, never a tamper-evident
  record. The daemon's own root-owned capture log is the authoritative one.
