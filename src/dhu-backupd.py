"""DHU Backup daemon — the append-only mirror.

Runs as ROOT under a LaunchDaemon. Every byte it executes is root-owned under
/Library/DHU/backup/, invoked as `/usr/bin/python3 -E -s -S`, with zero
repo dependency: the repo is both the thing that gets deleted and a tree the
adversary writes, so nothing in it can be on the protection path (review C2/H3).

The adversary is an LLM agent running as the owner (uid 501). It is not
malicious, it is incompetent at scale, and it has been observed editing its own
guard and then running it. Everything here is therefore structural: the daemon
PULLS, agents never write the store, and the guarantees are enforced by syscalls
(O_NOFOLLOW, openat, os.link's EEXIST) rather than by rules the code remembers.

  usage: /usr/bin/python3 -E -s -S dhu-backupd [--config PATH] [--once] [--interval N]

`--config`, `--once` and `--interval` exist so the MECHANICS can be proven in an
unprivileged staging run against a scratch store; the production config path is
the default and the LaunchDaemon passes no flags.
"""

import argparse
import ctypes
import errno
import hashlib
import json
import os
import select
import signal
import sqlite3
import stat as stat_mod
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dhu_backup_core  # noqa: E402
from dhu_backup_core import Allow, Copy, Degraded, Limits, Refuse, Skip  # noqa: E402

# Platform-selected, from the one table in dhu_backup_core: /Library/DHU/backup
# on macOS, /opt/dhu-backup on Linux. The LaunchDaemon and the systemd unit both
# pass no --config, so this default is what production actually uses.
DEFAULT_CONFIG_PATH = os.path.join(
    dhu_backup_core.DEFAULT_INSTALL_ROOT, "etc", "dhu-backupd.conf")
MAX_CONSECUTIVE_FREE_SPACE_FAILURES = 3
# The store half is AGENT-READABLE by design (amendment A1 / review R2) and the
# vault half is root-only. Both are root-owned and root-written; the kernel is
# the guarantee. Store files are 0444 — unlink and rename need write permission
# on the PARENT directory, which no agent has at any level, and the file itself
# is not writable even by root without an explicit chmod.
STORE_DIR_MODE = 0o755
STORE_FILE_MODE = 0o444
VAULT_DIR_MODE = 0o700
VAULT_FILE_MODE = 0o400
STATE_FILE_MODE = 0o644
# The index is agent-READABLE but must stay root-WRITABLE: SQLite opens it
# read-write, and setting it to the store's 0444 made every capture fail with
# "attempt to write a readonly database". Caught in staging, not by tsc.
INDEX_FILE_MODE = 0o644
# Manifests are data the helper reads, not stored content; 0644 for the same
# reason state.json is.
MANIFEST_FILE_MODE = 0o644
LOG_FILE_MODE = 0o644
READ_CHUNK = 1024 * 1024

_STOP = {"flag": False}


class Config(object):
    def __init__(self, values, config_path):
        self.config_path = config_path
        self.root = values.get("root", dhu_backup_core.DEFAULT_INSTALL_ROOT)
        self.watchlist = values.get("watchlist", os.path.join(self.root, "etc/watchlist.conf"))
        self.owner_uid = int(values.get("owner_uid", 501))
        self.interval_seconds = int(values.get("interval_seconds", dhu_backup_core.DEFAULT_INTERVAL_SECONDS))
        self.retention_days = int(values.get("retention_days", dhu_backup_core.DEFAULT_RETENTION_DAYS))
        self.prune_interval_seconds = int(
            values.get("prune_interval_seconds", dhu_backup_core.DEFAULT_PRUNE_INTERVAL_SECONDS)
        )
        self.trigger_debounce_seconds = float(values.get("trigger_debounce_seconds", 0.5))
        self.limits = Limits(
            max_file_bytes=int(values.get("max_file_bytes", dhu_backup_core.MAX_FILE_BYTES)),
            max_store_bytes=int(values.get("max_store_bytes", dhu_backup_core.MAX_STORE_BYTES)),
            max_versions_per_path=int(
                values.get("max_versions_per_path", dhu_backup_core.MAX_VERSIONS_PER_PATH)
            ),
            max_new_files_per_scan=int(
                values.get("max_new_files_per_scan", dhu_backup_core.MAX_NEW_FILES_PER_SCAN)
            ),
            min_free_bytes=int(values.get("min_free_bytes", dhu_backup_core.MIN_FREE_BYTES)),
            max_watch_roots=int(values.get("max_watch_roots", dhu_backup_core.MAX_WATCH_ROOTS)),
        )
        # The operator's optional additive vault rules, loaded once at startup
        # by `load_vault_extra`. Empty here rather than unset: a scan that runs
        # without the startup path (a test, a future caller) must get "no extra
        # rules", never an AttributeError halfway through a copy decision.
        self.extra_vault_globs = ()
        self.extra_vault_refusals = ()
        # The operator's optional directory exclusions, loaded once at startup
        # by `load_exclude`. Empty here for the same reason as the pair above: a
        # walk that runs without the startup path must get "no operator
        # exclusions", never an AttributeError halfway down a tree.
        #
        # NOTE THE ASYMMETRY, spelled out at `dhu_backup_core.parse_exclude`:
        # the pair above can only ADD protection, this pair can only REMOVE it.
        # Both files are root-owned 0644 beside `watchlist.conf`, which already
        # decides what is protected at all, and none of the three is writable by
        # the owner's account.
        self.exclude_globs = ()
        self.exclude_refusals = ()

    @property
    def var_dir(self):
        return os.path.join(self.root, "var")

    @property
    def store_dir(self):
        """Agent-readable half: only files the repo's own guards would allow."""
        return os.path.join(self.root, "store")

    @property
    def vault_dir(self):
        """Root-only half: credential-class files, captured but never readable."""
        return os.path.join(self.root, "vault")

    @property
    def roots_dir(self):
        """Manifests mapping (root_id, slug) to an absolute watch root.

        Outside the mirrored trees on purpose: with the original basename as the
        leaf, any name inside a tree could collide with a marker file placed in
        it.
        """
        return os.path.join(self.var_dir, "roots")

    def tree_dir(self, tree):
        return self.vault_dir if tree == dhu_backup_core.VAULT_TREE else self.store_dir

    def tree_modes(self, tree):
        if tree == dhu_backup_core.VAULT_TREE:
            return VAULT_DIR_MODE, VAULT_FILE_MODE
        return STORE_DIR_MODE, STORE_FILE_MODE

    @property
    def tmp_dir(self):
        return os.path.join(self.var_dir, "tmp")

    @property
    def index_path(self):
        return os.path.join(self.var_dir, "index.sqlite3")

    @property
    def state_path(self):
        return os.path.join(self.var_dir, "state.json")

    @property
    def log_path(self):
        return os.path.join(self.var_dir, "dhu-backupd.log")

    @property
    def vault_extra_path(self):
        """etc/vault-extra.conf — OPTIONAL, and additive-only by construction.

        Read from the same root-owned etc/ as every other config. The daemon
        still reads only its root-owned config and the watched trees: this is
        one more file in the first category, not a command channel.
        """
        return os.path.join(self.root, "etc", dhu_backup_core.VAULT_EXTRA_FILENAME)

    @property
    def exclude_path(self):
        """etc/exclude.conf — OPTIONAL, and subtractive-only by construction.

        Read from the same root-owned etc/ as every other config, and never
        shipped by the installer: the operator creates it or it does not exist.
        An example file in etc/ becomes a live config the moment somebody
        uncomments a line, and this is the one file in the tree whose lines can
        only make the store hold LESS.
        """
        return os.path.join(self.root, "etc", dhu_backup_core.EXCLUDE_FILENAME)


def load_config(path):
    values = {}
    try:
        with open(path) as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                key, sep, value = line.partition("=")
                if not sep:
                    continue
                values[key.strip()] = value.strip()
    except IOError as exc:
        # A missing config is fatal and SAID SO. It is never "use the defaults",
        # because the defaults would point a root daemon at a watch list it was
        # not configured with.
        sys.stderr.write("dhu-backupd: cannot read config %s: %s\n" % (path, exc))
        raise SystemExit(2)
    return Config(values, path)


def load_vault_extra(config):
    """`(globs, refusals)` from etc/vault-extra.conf. Absent is not an error.

    An unreadable file is NOT an empty one: it becomes a refusal, so it reaches
    the heartbeat as `vault_extra_refused` instead of looking like an operator
    who never wrote the file. "I could not read your extra rules" and "you have
    no extra rules" are different facts and the daemon must not merge them.
    """
    path = config.vault_extra_path
    if not os.path.exists(path):
        return (), ()
    try:
        with open(path) as handle:
            text = handle.read()
    except (IOError, OSError) as exc:
        return (), ((path, "unreadable:%s" % _errname(exc)),)
    return dhu_backup_core.parse_vault_extra(text)


def load_exclude(config):
    """`(globs, refusals)` from etc/exclude.conf. Absent is not an error.

    An unreadable file is NOT an empty one, and here that distinction decides
    how much gets protected: "I could not read your exclusions" leaves the whole
    tree protected and SAYS SO through `exclude_refused`, while an empty list
    would look like an operator who never wrote the file. The daemon must not
    merge those, in either direction.
    """
    path = config.exclude_path
    if not os.path.exists(path):
        return (), ()
    try:
        with open(path) as handle:
            text = handle.read()
    except (IOError, OSError) as exc:
        return (), ((path, "unreadable:%s" % _errname(exc)),)
    return dhu_backup_core.parse_exclude(text)


# ── logging (H4: paths and decisions, never content) ─────────────────────────


class Logger(object):
    def __init__(self, path):
        self.path = path
        self.handle = None
        try:
            self.handle = open(path, "a")
            try:
                os.chmod(path, LOG_FILE_MODE)
            except OSError as exc:
                sys.stderr.write("dhu-backupd: could not set mode on the log: %s\n" % exc)
        except IOError as exc:
            sys.stderr.write("dhu-backupd: cannot open log %s: %s\n" % (path, exc))

    def write(self, level, message):
        line = "%s %s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S%z"), level, message)
        if self.handle is not None:
            self.handle.write(line)
            self.handle.flush()
        else:
            sys.stderr.write(line)

    def info(self, message):
        self.write("INFO", message)

    def warn(self, message):
        self.write("WARN", message)

    def error(self, message):
        self.write("ERROR", message)


# ── index ─────────────────────────────────────────────────────────────────────


def open_index(config):
    connection = sqlite3.connect(config.index_path)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS files ("
        " root_id TEXT NOT NULL, watch_root TEXT NOT NULL, relpath TEXT NOT NULL,"
        " size INTEGER, mtime_ns INTEGER, sha256 TEXT,"
        " first_seen INTEGER, last_seen INTEGER,"
        " PRIMARY KEY (watch_root, relpath))"
    )
    connection.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    connection.commit()
    try:
        os.chmod(config.index_path, INDEX_FILE_MODE)  # A4
    except OSError as exc:
        sys.stderr.write("dhu-backupd: could not set mode on the index: %s\n" % exc)
    return connection


def meta_get(connection, key, default=None):
    row = connection.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(connection, key, value):
    connection.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, str(value)),
    )


# ── the store ─────────────────────────────────────────────────────────────────


def ensure_dir(path, mode, logger=None):
    if not os.path.isdir(path):
        os.makedirs(path, mode)
    try:
        os.chmod(path, mode)
    except OSError as exc:
        # The store's readability is load-bearing: amendment A1 is what makes
        # recovery-without-sudo true. A silent chmod failure would break that
        # with no signal anywhere.
        message = "could not set mode %o on %s: %s" % (mode, path, exc)
        if logger is not None:
            logger.error(message)
        else:
            sys.stderr.write("dhu-backupd: %s\n" % message)


def measure_store_bytes(store_dir):
    """Sum of every stored version. Walked once at startup, tracked after."""
    total = 0
    for dirpath, _dirnames, filenames in os.walk(store_dir):
        for name in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, name)).st_size
            except OSError:
                continue
    return total


def existing_versions(path_dir, leaf):
    """`[(version_key, capture_epoch_ns, sha_prefix)]` held for ONE mirrored path,
    oldest first.

    `path_dir` holds the version directories of EVERY file in one source
    directory; the LEAF (the original basename) is what says which of them
    belong to this path. The first shipped version took `path_dir` alone and
    handed the whole directory's versions to the rolling window, which then
    "rolled" the only versions of sibling files (independent review,
    2026-09-11: a 342-file directory held exactly 200, one per file for the
    200 luckiest). A version directory holds exactly one leaf, so membership is
    one `lstat` per candidate, no listing.
    """
    held = []
    try:
        names = os.listdir(path_dir)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            raise
        return held
    for name in names:
        parsed = dhu_backup_core.parse_version_key(name)
        if parsed is None:
            continue
        if not os.path.lexists(os.path.join(path_dir, name, leaf)):
            continue
        held.append((name, parsed[0], parsed[1]))
    held.sort(key=lambda row: (row[1], row[0]))
    return held


def write_version(config, tree, root_id, slug, relpath, payload, digest, logger):
    """Link one new version into `tree`. Returns the version key, or None.

    Layout: `<tree>/<root-id>/<slug>/<relpath-dir>/@<capture>-<hash>/<BASENAME>`.
    The version is a DIRECTORY and the ORIGINAL BASENAME is the leaf, so every
    name-based guard in this repo works on a mirror path unchanged — verified
    against a real basename-matching read guard, which returns null for the
    draft's hash-leaf layout and the correct refusal for this one.

    Append-only is enforced by `os.link`, which fails EEXIST rather than
    overwriting — a syscall property, not a check the daemon has to remember.
    """
    dir_mode, file_mode = config.tree_modes(tree)
    # C12: the daemon's own capture clock. Source mtime is never an input here;
    # `version_key`'s signature is the proof.
    key = dhu_backup_core.version_key(time.time_ns(), digest)
    subpath = dhu_backup_core.version_subpath(root_id, slug, relpath, key)
    target = os.path.join(config.tree_dir(tree), subpath)
    ensure_dir(os.path.dirname(target), dir_mode, logger)

    temp_path = os.path.join(config.tmp_dir, "%d-%s" % (os.getpid(), digest[:16]))
    handle = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    try:
        os.write(handle, payload)
        os.fsync(handle)
    finally:
        os.close(handle)
    # Mode set on the temp file, before it is linked into place: a window in
    # which a store file exists at 0600 is a window in which recovery is broken.
    # No copystat, no xattrs, no ACLs (M3) — a plain regular file.
    os.chmod(temp_path, file_mode)
    try:
        os.link(temp_path, target)
    except OSError as exc:
        os.unlink(temp_path)
        if exc.errno == errno.EEXIST:
            logger.info("duplicate-version %s/%s" % (root_id, relpath))
            return None
        raise
    os.unlink(temp_path)
    return key


def write_root_manifest(config, root_id, slug, watch_root, logger):
    """Record where an expanded root lives, so the helper can derive a target."""
    path = os.path.join(config.roots_dir, dhu_backup_core.root_manifest_name(root_id, watch_root))
    if os.path.exists(path):
        return
    write_json_atomic(
        config, path,
        {"root_id": root_id, "slug": slug, "watch_root": watch_root},
        MANIFEST_FILE_MODE,
    )


def write_json_atomic(config, path, payload, mode):
    temp_path = os.path.join(config.tmp_dir, "json-%d-%d" % (os.getpid(), time.time_ns()))
    handle = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, mode)
    try:
        os.write(handle, json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        os.fsync(handle)
    finally:
        os.close(handle)
    os.chmod(temp_path, mode)
    os.replace(temp_path, path)


# ── watch roots (C7 / H7) ─────────────────────────────────────────────────────


def resolve_watch_root(path, allowed_uids):
    """(resolved_path, Allow()) or (None, Refuse(reason)) for one watch root.

    Walks the RAW configured path component by component, resolving a symlink
    only when it is met and only when ROOT owns it.

    The first version called `os.path.realpath()` first and component-checked the
    RESULT. After realpath no component is a symlink, so the symlink rule beside
    it was dead code and an agent-owned symlink watch root was followed without
    a word — proven by the round-2 review, which pointed a uid-501 symlink at a
    directory of its choosing and watched the daemon store the target's contents
    with `state: ok` and zero refusals. "Resolve, then check what came back" is a
    check about a path the config never named.

    Root-owned symlinks must still be traversed: `/var` is one, and the $TMPDIR
    watch root goes through it.
    """
    stats = []
    current = "/"
    try:
        stats.append(os.lstat(current))
    except OSError as exc:
        return None, Refuse("root-unstattable:%s" % _errname(exc))

    parts = [p for p in path.split("/") if p]
    for index, part in enumerate(parts):
        candidate = os.path.join(current, part)
        try:
            st = os.lstat(candidate)
        except OSError as exc:
            return None, Refuse("component-%d-unstattable:%s" % (index, _errname(exc)))
        stats.append(st)
        if stat_mod.S_ISLNK(st.st_mode):
            # Refuse HERE with the accurate reason. Truncating the stat list and
            # letting the pure verdict speak made an intermediate agent-owned
            # symlink report "is-symlink" (the last-component reason) because it
            # had become the last entry in the list.
            if index == len(parts) - 1:
                return None, Refuse("final-component-%d-is-symlink" % index)
            if st.st_uid != 0:
                return None, Refuse("component-%d-symlink-uid=%d" % (index, st.st_uid))
            current = os.path.realpath(candidate)
        else:
            current = candidate

    verdict = dhu_backup_core.watch_root_component_verdict(stats, allowed_uids)
    if isinstance(verdict, Refuse):
        return None, verdict
    return current, verdict


def expand_roots(config, logger):
    """[(root_id, absolute_root)] from the root-owned watchlist, validated.

    Never from the DB, an env var, or anything an agent writes (review C5): a
    path chosen by the adversary and read by a root process that copies what it
    finds is a general exfiltration primitive.
    """
    try:
        with open(config.watchlist) as handle:
            text = handle.read()
    except IOError as exc:
        logger.error("watchlist unreadable: %s" % exc)
        return [], [("watchlist", "unreadable")]

    entries, refusals = dhu_backup_core.parse_watchlist(text, config.limits.max_watch_roots)
    for line, reason in refusals:
        logger.warn("watchlist refused (%s): %s" % (reason, line))

    allowed_uids = {0, config.owner_uid}
    roots = []
    for root_id, pattern in entries:
        if pattern.endswith("*"):
            # dirname of the pattern itself. The first version stripped the `*`
            # and then any trailing `/`, which for a bare `/foo/*` removed the
            # whole last component and enumerated the children of `/`.
            parent = os.path.dirname(pattern) or "/"
            prefix = os.path.basename(pattern)[:-1]
            candidates = []
            # The PARENT is canonicalised from the root-owned config, then its
            # components are lstat-checked; children are enumerated without
            # following symlinks, so a symlinked worktree is skipped, not chased.
            parent_real, verdict = resolve_watch_root(parent, allowed_uids)
            if isinstance(verdict, Refuse):
                logger.warn("watch-root parent refused (%s): %s" % (verdict.reason, parent))
                refusals.append((pattern, verdict.reason))
                continue
            try:
                with os.scandir(parent_real) as iterator:
                    for entry in iterator:
                        if not entry.name.startswith(prefix):
                            continue
                        if not entry.is_dir(follow_symlinks=False):
                            # Logged, not dropped: a symlinked worktree skipped
                            # in silence is a silently unprotected agent, which
                            # is the same fault as a silently dropped root.
                            logger.warn("watch-root candidate refused (not a real directory): %s/%s"
                                        % (parent_real, entry.name))
                            refusals.append((entry.name, "candidate-not-a-directory"))
                            continue
                        candidates.append(os.path.join(parent_real, entry.name))  # re-checked below
            except OSError as exc:
                logger.warn("watch-root parent unscannable %s: %s" % (parent, exc))
                refusals.append((pattern, "parent-unscannable"))
                continue
            # Most-recently-modified first, so the cap drops stale roots not live ones.
            candidates.sort(key=lambda p: _safe_mtime(p), reverse=True)
        else:
            candidates = [pattern]

        for candidate in candidates:
            if len(roots) >= config.limits.max_watch_roots:
                logger.warn("watch-root cap reached, refusing: %s" % candidate)
                refusals.append((candidate, "max-watch-roots"))
                break
            resolved, verdict = resolve_watch_root(candidate, allowed_uids)
            if isinstance(verdict, Refuse):
                logger.warn("watch-root refused (%s): %s" % (verdict.reason, candidate))
                refusals.append((candidate, verdict.reason))
                continue
            roots.append((root_id, resolved))
    return roots, refusals


def _safe_mtime(path):
    try:
        return os.lstat(path).st_mtime
    except OSError:
        return 0


def worktrees_covered_by_another_root(watch_root, roots):
    """Does some OTHER expanded root sit under this root's `.claude/worktrees`?

    Only then does the walk skip that directory under `watch_root`: the
    worktrees are captured under their own roots, and walking them here too
    would store every file twice. With no such root they are walked here.
    """
    prefix = os.path.join(watch_root.rstrip("/"), ".claude", "worktrees") + "/"
    return any(other.startswith(prefix) for _root_id, other in roots)


# ── the walk (C6 / C7 / C8) ───────────────────────────────────────────────────


def open_root_fd(path):
    """Open a watch root, refusing if it moved between the lstat and the open."""
    expected = os.lstat(path)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    actual = os.fstat(fd)
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
        os.close(fd)
        raise OSError(errno.EAGAIN, "watch root changed between check and open")
    return fd


MAX_WALK_DEPTH = 32


def walk_root(root_fd, counters, logger, on_file, absolute_root=None, exclude_globs=(),
              worktrees_covered=False):
    """Depth-first walk over directory file descriptors. Does not close root_fd.

    No path string is ever re-resolved (C8): each directory is opened
    O_NOFOLLOW relative to its parent's fd and each file by BASENAME relative to
    its directory's fd, so there is no window in which the adversary can swap a
    checked name for a symlink or a hard link.

    Recursive rather than a worklist of open fds: a worklist holds one fd per
    PENDING directory, so a single directory with 500 subdirectories exhausts a
    256-fd limit before the walk descends once. Recursion holds one fd per level
    of DEPTH, capped at MAX_WALK_DEPTH.

    `exclude_globs` is the operator's optional `etc/exclude.conf` list. It is a
    WALK rule and lives only here: the whole value of it is that a 33 GB
    directory costs one `scandir` entry instead of a descent, and a rule applied
    at admission would have to walk the tree first to apply it. `classify_entry`
    keeps its own copy of the BUILT-IN list as defence in depth and does not
    know about this one; if a path ever reached admission from somewhere other
    than this walk, it would be admitted rather than excluded — the direction
    that protects MORE, which is the safe one for a subtractive rule.
    """
    _walk_dir(root_fd, "", counters, logger, on_file, 0, absolute_root, exclude_globs,
              worktrees_covered)


def _walk_dir(fd, relative_dir, counters, logger, on_file, depth, absolute_dir=None,
              exclude_globs=(), worktrees_covered=False):
    if absolute_dir is not None and len(counters.directories) < MAX_WATCHED_DIRS:
        # Path strings collected here feed the kqueue TRIGGER only. Capture
        # itself never re-resolves a path (C8); a trigger fd pointing somewhere
        # unexpected can only cause an extra sweep.
        counters.directories.append(absolute_dir)
    subdirectories = []
    try:
        with os.scandir(fd) as iterator:
            for entry in iterator:
                child_rel = "%s/%s" % (relative_dir, entry.name) if relative_dir else entry.name
                try:
                    if dhu_backup_core.parse_version_key(entry.name) is not None:
                        # The store's own namespace. A source entry named like a
                        # version key would be listed by the reader, the prune
                        # and the rolling window as a version of its siblings.
                        counters.refuse("walk-version-key-shaped")
                        log_refusal_once(logger, "vkey|" + child_rel,
                                         "refusing an entry named like a version key: %s"
                                         % child_rel)
                        continue
                    if not _utf8_encodable(entry.name):
                        # Surrogate-escaped by the OS; neither the sqlite index
                        # nor the log can take it, and one such name aborted
                        # every scan of its whole root (independent review,
                        # 2026-09-11). Refused and counted, like any other entry.
                        counters.refuse("walk-name-not-utf8")
                        log_refusal_once(logger, "utf8|" + _printable(child_rel),
                                         "refusing a name that is not valid UTF-8: %s"
                                         % _printable(child_rel))
                        continue
                    if entry.is_symlink():
                        counters.refuse("walk-symlink")
                        log_refusal_once(logger, "sym|" + child_rel,
                                         "not following symlink: %s" % child_rel)
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if dhu_backup_core.is_excluded_dir(entry.name, child_rel,
                                                           worktrees_covered):
                            counters.refuse("walk-excluded-dir")
                            log_refusal_once(logger, "exdir|" + child_rel,
                                             "not descending excluded dir: %s" % child_rel)
                            continue
                        # Counted under its OWN reason, never merged into the
                        # built-in one above. An operator who writes a glob and
                        # sees no counter move cannot tell "the rule is working"
                        # from "the rule never matched", and the second is the
                        # one that costs them the disk they were trying to save.
                        operator_glob = dhu_backup_core.exclude_glob_match(
                            entry.name, exclude_globs)
                        if operator_glob is not None:
                            counters.refuse("walk-excluded-dir-operator")
                            log_refusal_once(
                                logger, "opdir|" + child_rel,
                                "not descending %s: operator exclude.conf glob %r"
                                % (child_rel, operator_glob))
                            continue
                        subdirectories.append((entry.name, child_rel))
                        continue
                    on_file(fd, entry.name, child_rel)
                except OSError as exc:
                    # An exception in the scan loop is logged with its reason and
                    # counted. It never becomes a silent "0 files".
                    counters.refuse("entry-error-%s" % _errname(exc))
                    logger.warn("entry error %s: %s" % (child_rel, _errname(exc)))
    except OSError as exc:
        counters.refuse("scandir-%s" % _errname(exc))
        logger.warn("scandir failed %s: %s" % (relative_dir or ".", _errname(exc)))
        return

    for name, child_rel in subdirectories:
        if depth + 1 > MAX_WALK_DEPTH:
            counters.refuse("max-depth")
            logger.warn("depth cap reached, not descending: %s" % child_rel)
            continue
        try:
            child_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
        except OSError as exc:
            counters.refuse("dir-open-%s" % _errname(exc))
            logger.warn("dir open refused %s: %s" % (child_rel, _errname(exc)))
            continue
        try:
            _walk_dir(child_fd, child_rel, counters, logger, on_file, depth + 1,
                      os.path.join(absolute_dir, name) if absolute_dir else None,
                      exclude_globs, worktrees_covered)
        finally:
            os.close(child_fd)


def _errname(exc):
    return errno.errorcode.get(getattr(exc, "errno", None), str(getattr(exc, "errno", "?")))


def _utf8_encodable(name):
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _printable(text):
    """A log-safe rendering of a name that may carry surrogate escapes."""
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


MAX_LOGGED_REFUSAL_KEYS = 5000

# Refusals are re-evaluated every scan (admission runs BEFORE the index
# short-circuit, deliberately — a file's ownership or link count can change
# without its mtime moving). Logging each one every 15 s meant ~63 lines per
# scan on this repo, 363k lines and ~36 MB a DAY, into a root-owned file with no
# rotation, on the same volume whose free space triggers the irreversible
# DEGRADED. The counters still count every occurrence; only the log de-dupes.
_LOGGED_REFUSALS = set()


def log_refusal_once(logger, key, message):
    if key in _LOGGED_REFUSALS:
        return
    if len(_LOGGED_REFUSALS) >= MAX_LOGGED_REFUSAL_KEYS:
        if "__cap__" not in _LOGGED_REFUSALS:
            _LOGGED_REFUSALS.add("__cap__")
            logger.warn("refusal-log cap reached (%d distinct); further refusals are counted "
                        "in state.json but not logged" % MAX_LOGGED_REFUSAL_KEYS)
        return
    _LOGGED_REFUSALS.add(key)
    logger.info(message)


MAX_WATCHED_DIRS = 8192


class BaseTrigger(object):
    """The change trigger, as an interface — an ACCELERATOR, never the guarantee.

    Every implementation answers the same four questions and nothing else:

        refresh(directories)  track exactly these absolute directory paths
        wait(timeout)         True if one of them changed within the timeout
        directories_watched   how many are actually being watched right now
        name                  what to report in the heartbeat and the log

    The floor sweep runs underneath all of them and re-validates everything
    through the openat walk, so no trigger is on the trust path: a spoofed,
    spurious or entirely absent event costs one sweep and nothing else. That is
    what makes a second platform's trigger a small change rather than a new
    threat model.

    Two counters are part of the interface because their absence is the failure
    mode this class of code has. `directories_watched` below the directory count
    and `watch_failures` above zero both mean part of the tree has lost its
    accelerator, which is invisible from the outside: capture still happens, one
    poll interval later. Both are REPORTED in the heartbeat every cycle.
    """

    #: What this implementation is called when it is working.
    NAME = "poll-only"

    def __init__(self, logger):
        self.logger = logger
        self.available = False
        self.watch_failures = 0
        self._failed_paths = set()

    @property
    def name(self):
        """The heartbeat's `trigger` value. `poll-only` whenever the chosen
        trigger could not be created — an unavailable kqueue must never still
        report `kqueue`."""
        return self.NAME if self.available else "poll-only"

    @property
    def directories_watched(self):
        return 0

    def _note_watch_failure(self, path, detail):
        """Count every failed watch, and log each DIRECTORY once.

        Counted every time and logged once, for the same reason the refusal log
        de-dupes: a failure that re-occurs every refresh would otherwise write
        an unrotated root-owned log on the volume whose free space stops the
        daemon.
        """
        self.watch_failures += 1
        if path in self._failed_paths:
            return
        if len(self._failed_paths) < MAX_WATCHED_DIRS:
            self._failed_paths.add(path)
        self.logger.warn("trigger: could not watch %s (%s); it relies on the floor sweep"
                         % (path, detail))

    def refresh(self, directories):
        return 0, 0

    def wait(self, timeout_seconds):
        time.sleep(max(0.0, timeout_seconds))
        return False

    def close(self):
        pass


class PollOnlyTrigger(BaseTrigger):
    """No trigger at all: the floor sweep, alone, on an unsupported platform.

    It is a CLASS rather than a `None` so that every caller keeps working and
    the heartbeat keeps reporting, and it never wakes early: `wait` sleeps the
    whole timeout. The daemon logs an ERROR at startup naming the platform, and
    the heartbeat says `poll-only` for as long as it runs this way.
    """

    NAME = "poll-only"


class KqueueTrigger(BaseTrigger):
    """macOS: kqueue EVFILT_VNODE on watched DIRECTORIES.

    **What it does NOT catch, measured on this machine rather than assumed:** a
    directory watch fires on create, delete and rename (0.1 ms latency), and
    does NOT fire when a file inside it is rewritten IN PLACE. Editors that
    write-then-rename are caught immediately; `echo x > f` is not. That is why
    the floor sweep stays at the full poll interval — the poll remains the
    guarantee and this only makes the common case faster.

    Linux's inotify differs here, and `InotifyTrigger` says so with its own
    measurement. The difference is a property of the two kernel interfaces, not
    a choice made in this file.

    Watching every FILE would close that gap at ~6,000 more fds and a much
    larger amount of state in the one process that must never die. Not taken.
    """

    NAME = "kqueue"

    def __init__(self, logger):
        BaseTrigger.__init__(self, logger)
        self.fds = {}
        self.kq = None
        try:
            self.kq = select.kqueue()
            self.available = True
        except Exception as exc:  # noqa: BLE001
            logger.error("kqueue unavailable (%s) — the floor sweep is now the ONLY "
                         "capture path; the heartbeat says poll-only" % exc)

    @property
    def directories_watched(self):
        return len(self.fds)

    def refresh(self, directories):
        """Track exactly `directories`. Returns (added, dropped)."""
        if not self.available:
            return 0, 0
        wanted = set(directories)
        dropped = 0
        for path in list(self.fds):
            if path not in wanted:
                try:
                    os.close(self.fds.pop(path))
                except OSError:
                    self.fds.pop(path, None)
                dropped += 1
        added = 0
        for path in wanted:
            if path in self.fds:
                continue
            if len(self.fds) >= MAX_WATCHED_DIRS:
                # Bounded, and SAID so: an unannounced cap would mean part of
                # the tree silently loses its accelerator.
                self.logger.warn("directory-trigger cap (%d) reached; the remaining "
                                 "directories rely on the floor sweep" % MAX_WATCHED_DIRS)
                break
            try:
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError as exc:
                self._note_watch_failure(path, _errname(exc))
                continue
            try:
                self.kq.control([select.kevent(
                    fd,
                    filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                    fflags=(select.KQ_NOTE_WRITE | select.KQ_NOTE_DELETE
                            | select.KQ_NOTE_RENAME | select.KQ_NOTE_EXTEND),
                )], 0, 0)
            except OSError as exc:
                os.close(fd)
                self._note_watch_failure(path, _errname(exc))
                continue
            self.fds[path] = fd
            added += 1
        return added, dropped

    def wait(self, timeout_seconds):
        """True if a watched directory changed within the timeout."""
        if not self.available:
            time.sleep(max(0.0, timeout_seconds))
            return False
        try:
            events = self.kq.control(None, 16, max(0.0, timeout_seconds))
        except OSError:
            time.sleep(max(0.0, timeout_seconds))
            return False
        return bool(events)

    def close(self):
        for fd in self.fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self.fds.clear()
        if self.kq is not None:
            self.kq.close()


# ── inotify, via ctypes ───────────────────────────────────────────────────────
#
# Python's stdlib has no inotify binding, and this daemon may import nothing
# outside the stdlib and its own root-owned directory (review H3) — so no
# `inotify_simple`, no `watchdog`. `ctypes` against libc is the stdlib way to
# reach the three syscalls, and it keeps the dependency surface at zero.
#
# THE EVENT MASK VALUES BELOW ARE KERNEL ABI. They are identical on every Linux
# architecture and have not changed since inotify was merged in 2.6.13, which is
# what makes it legitimate to write them down rather than read them from a
# header we do not have. They are pinned by a test for exactly that reason: a
# typo here is a watch that silently never fires, and the floor sweep would hide
# it perfectly.
IN_ATTRIB = 0x00000004        # metadata changed — catches a chmod/chown that
                              # moves a file across the admission guards
IN_CLOSE_WRITE = 0x00000008   # a writable fd was closed: an IN-PLACE REWRITE.
                              # This is the event macOS's directory kqueue does
                              # not have, and the reason Linux capture of
                              # `echo x > f` is immediate rather than sweep-bound
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400   # the watched directory itself went away
IN_MOVE_SELF = 0x00000800     # ... or was renamed
IN_Q_OVERFLOW = 0x00004000    # the kernel dropped events. REPORTED, because the
                              # honest answer is "the accelerator lost some";
                              # the floor sweep still captures them
IN_IGNORED = 0x00008000       # the kernel removed this watch (deleted/unmounted)
IN_ONLYDIR = 0x01000000       # refuse to watch a non-directory: the trigger must
                              # not be steerable into watching something else
IN_DONT_FOLLOW = 0x02000000   # never resolve a symlink at the final component
                              # (review C7, restated for the trigger)

INOTIFY_WATCH_MASK = (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
                      | IN_CLOSE_WRITE | IN_ATTRIB | IN_DELETE_SELF | IN_MOVE_SELF
                      | IN_ONLYDIR | IN_DONT_FOLLOW)

#: `struct inotify_event` is `int wd; uint32 mask; uint32 cookie; uint32 len;`
#: followed by `len` bytes of name. Fixed part is 16 bytes on every ABI.
INOTIFY_EVENT_HEADER = 16

#: The kernel's per-user watch ceiling, as a path rather than a number: it is a
#: sysctl an operator can raise, and the daemon reports what it found rather
#: than assuming a default that has changed twice in the last decade.
INOTIFY_MAX_USER_WATCHES = "/proc/sys/fs/inotify/max_user_watches"


def read_inotify_watch_limit():
    """The kernel's max_user_watches, or None if it could not be read."""
    try:
        with open(INOTIFY_MAX_USER_WATCHES) as handle:
            return int(handle.read().strip())
    except (IOError, OSError, ValueError):
        return None


class InotifyTrigger(BaseTrigger):
    """Linux: inotify on watched DIRECTORIES, through ctypes.

    Same contract as `KqueueTrigger`, and one MEASURED difference: a directory
    watch on Linux reports `IN_CLOSE_WRITE` for a file written inside it, so an
    in-place rewrite (`echo x > f`) wakes the daemon immediately instead of
    waiting for the floor sweep. That is a measurement recorded in src/README.md
    from the container run, not an inference from the manual page.

    **The limits are real and are REPORTED.** `inotify_add_watch` fails with
    ENOSPC when the per-user `max_user_watches` ceiling is reached and EMFILE
    when the per-user instance limit is, and a tree of a few hundred thousand
    directories reaches the first on a stock host. Every failure is counted into
    `trigger_watch_failures` in the heartbeat and logged once per directory. The
    consequence is bounded and stated: those directories fall back to the floor
    sweep, which is the guarantee in the first place.
    """

    NAME = "inotify"

    def __init__(self, logger):
        BaseTrigger.__init__(self, logger)
        self.fd = -1
        self.wds = {}       # absolute path -> watch descriptor
        self.paths = {}     # watch descriptor -> absolute path
        self.libc = None
        self.overflows = 0
        self.watch_limit = read_inotify_watch_limit()
        try:
            self.libc = _load_libc()
            fd = self.libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
            if fd < 0:
                raise OSError(ctypes.get_errno(), "inotify_init1 failed")
            self.fd = fd
            self.available = True
        except Exception as exc:  # noqa: BLE001
            logger.error("inotify unavailable (%s: %s) — the floor sweep is now the ONLY "
                         "capture path; the heartbeat says poll-only"
                         % (type(exc).__name__, exc))

    @property
    def directories_watched(self):
        return len(self.wds)

    def refresh(self, directories):
        """Track exactly `directories`. Returns (added, dropped)."""
        if not self.available:
            return 0, 0
        wanted = set(directories)
        dropped = 0
        for path in list(self.wds):
            if path not in wanted:
                wd = self.wds.pop(path)
                self.paths.pop(wd, None)
                # A watch the kernel already dropped (the directory was deleted)
                # returns EINVAL here; that is the expected case, not an error.
                self.libc.inotify_rm_watch(self.fd, wd)
                dropped += 1
        added = 0
        for path in wanted:
            if path in self.wds:
                continue
            if len(self.wds) >= MAX_WATCHED_DIRS:
                self.logger.warn("directory-trigger cap (%d) reached; the remaining "
                                 "directories rely on the floor sweep" % MAX_WATCHED_DIRS)
                break
            wd = self.libc.inotify_add_watch(
                self.fd, path.encode("utf-8", "surrogateescape"), INOTIFY_WATCH_MASK)
            if wd < 0:
                err = ctypes.get_errno()
                detail = errno.errorcode.get(err, str(err))
                if err == errno.ENOSPC and self.watch_limit is not None:
                    detail += " (max_user_watches=%d reached)" % self.watch_limit
                self._note_watch_failure(path, detail)
                continue
            self.wds[path] = wd
            self.paths[wd] = path
            added += 1
        return added, dropped

    def wait(self, timeout_seconds):
        """True if a watched directory changed within the timeout."""
        if not self.available:
            time.sleep(max(0.0, timeout_seconds))
            return False
        timeout = max(0.0, timeout_seconds)
        try:
            readable, _, _ = select.select([self.fd], [], [], timeout)
        except (OSError, ValueError):
            time.sleep(timeout)
            return False
        if not readable:
            return False
        try:
            data = os.read(self.fd, 65536)
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return False
            return True
        # The event bodies are drained but never TRUSTED: the daemon's answer to
        # any event is its ordinary sweep, which re-validates everything through
        # the openat walk. The only thing decoded here is the overflow flag,
        # because "the kernel dropped events" is a fact worth reporting.
        for mask in _inotify_event_masks(data):
            if mask & IN_Q_OVERFLOW:
                self.overflows += 1
                self.logger.warn("inotify queue overflow — events were dropped by the "
                                 "kernel; the floor sweep still captures them")
        return True

    def close(self):
        self.wds.clear()
        self.paths.clear()
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1


def _load_libc():
    """The C library, with errno tracking. Raises if it cannot be loaded.

    `ctypes.CDLL(None)` is the running interpreter's own process image, and the
    inotify entry points live in the libc it is already linked against — glibc
    and musl alike. It is tried FIRST, deliberately: `ctypes.util.find_library`
    can shell out to `ldconfig`, `gcc` or `ld` to locate a library, and a root
    daemon that executes only root-owned bytes does not spawn linkers to find
    the libc it is already running on. The named fallbacks cover an interpreter
    whose main image does not export the symbols.
    """
    last = None
    for name in (None, "libc.so.6", "libc.so"):
        try:
            libc = ctypes.CDLL(name, use_errno=True)
            libc.inotify_init1.argtypes = [ctypes.c_int]
            libc.inotify_init1.restype = ctypes.c_int
            libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            libc.inotify_add_watch.restype = ctypes.c_int
            libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
            libc.inotify_rm_watch.restype = ctypes.c_int
            return libc
        except (OSError, AttributeError) as exc:
            last = exc
            continue
    raise OSError("no usable libc for inotify: %s" % last)

def _inotify_event_masks(data):
    """The mask of every complete event in a read() buffer. PURE over bytes."""
    masks = []
    offset = 0
    total = len(data)
    while offset + INOTIFY_EVENT_HEADER <= total:
        mask = int.from_bytes(data[offset + 4:offset + 8], sys.byteorder, signed=False)
        length = int.from_bytes(data[offset + 12:offset + 16], sys.byteorder, signed=False)
        masks.append(mask)
        offset += INOTIFY_EVENT_HEADER + length
    return masks


def make_trigger(logger, platform_string=None):
    """The trigger this platform gets, chosen by `trigger_name_for_platform`.

    An unsupported platform gets `PollOnlyTrigger` AND an ERROR line naming it.
    Neither half is optional: capture still works there, at the floor interval,
    and an operator who is not told will read the ordinary latency as a fault.
    """
    platform_string = sys.platform if platform_string is None else platform_string
    chosen = dhu_backup_core.trigger_name_for_platform(platform_string)
    if chosen == "kqueue":
        return KqueueTrigger(logger)
    if chosen == "inotify":
        return InotifyTrigger(logger)
    logger.error("no change trigger for platform %r — running POLL-ONLY: every change "
                 "waits for the floor sweep (interval_seconds). Capture is unaffected; "
                 "latency is not." % platform_string)
    return PollOnlyTrigger(logger)


class Counters(object):
    def __init__(self):
        self.directories = []
        self.files_scanned = 0
        self.versions_written = 0
        self.bytes_written = 0
        # Content already in the store (a touch, or a revert). A SUCCESS —
        # filing it under refusals made "the file is protected" look like "the
        # file was rejected".
        self.already_held = 0
        # Captured into the root-only vault rather than the readable store.
        self.vaulted = 0
        # Old versions dropped by the per-path rolling window.
        self.rolled = 0
        self.refusals = {}

    def refuse(self, reason):
        self.refusals[reason] = self.refusals.get(reason, 0) + 1


# ── one scan ──────────────────────────────────────────────────────────────────


def scan_once(config, connection, logger, state):
    counters = Counters()
    roots, root_refusals = expand_roots(config, logger)
    if not roots:
        logger.error("no usable watch roots — nothing is being protected")

    store_bytes = int(meta_get(connection, "store_bytes", "0"))
    free_bytes = None
    free_space_error = None
    try:
        vfs = os.statvfs(config.store_dir)
        free_bytes = vfs.f_bavail * vfs.f_frsize
    except OSError as exc:
        # Fail closed, but NOT under a fabricated reason. Setting free_bytes = 0
        # made budget_decision return Degraded("free-space-floor") — a permanent,
        # human-only-recoverable stop whose stated cause was "the volume is
        # full", printed beside a heartbeat reporting 30 GB free (internal audit).
        # "Could not measure" and "measured, and it is too low" are two facts.
        free_space_error = _errname(exc)
        logger.error("statvfs failed (%s) — free space UNKNOWN" % free_space_error)

    degraded_reason = state.get("degraded_reason")
    if free_space_error:
        # A permanent, human-only-recoverable stop is too heavy for one failed
        # measurement, and DEGRADED never self-heals — so a one-second glitch
        # became a permanent outage. Skip the cycle, say so, and degrade only
        # after this many CONSECUTIVE failures (round-2 review, I2).
        state["free_space_failures"] = state.get("free_space_failures", 0) + 1
        if state["free_space_failures"] >= MAX_CONSECUTIVE_FREE_SPACE_FAILURES:
            if not degraded_reason:
                degraded_reason = "free-space-unknown:%s" % free_space_error
        else:
            logger.warn("free space unmeasurable (%s), attempt %d of %d — skipping this cycle"
                        % (free_space_error, state["free_space_failures"],
                           MAX_CONSECUTIVE_FREE_SPACE_FAILURES))
            return (counters, store_bytes, None, len(roots), len(root_refusals),
                    "statvfs failed (%s) — free space unknown, cycle skipped" % free_space_error)
    else:
        state.pop("free_space_failures", None)

    for root_id, watch_root in roots:
        if degraded_reason:
            break
        try:
            root_fd = open_root_fd(watch_root)
        except OSError as exc:
            counters.refuse("root-open-%s" % _errname(exc))
            logger.warn("watch root unopenable %s: %s" % (watch_root, _errname(exc)))
            continue

        slug = dhu_backup_core.root_slug(root_id, watch_root)
        write_root_manifest(config, root_id, slug, watch_root, logger)

        def handle_file(dir_fd, name, relpath, _root_id=root_id, _watch_root=watch_root,
                        _slug=slug):
            nonlocal store_bytes, degraded_reason
            if degraded_reason:
                # Counted so a MID-WALK degrade still describes the rest of the
                # tree. When the degrade happens before the walk (the free-space
                # path) nothing is walked at all and this never fires — the
                # heartbeat then describes no part of the tree, which is what
                # `state: degraded` is for.
                counters.refuse("skipped-while-degraded")
                return
            try:
                file_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=dir_fd,
                )
            except OSError as exc:
                # ELOOP here is the kernel refusing a symlink — exactly C7.
                counters.refuse("open-%s" % _errname(exc))
                return
            try:
                st = os.fstat(file_fd)  # on the FD, never the path
                counters.files_scanned += 1
                verdict = dhu_backup_core.classify_entry(
                    name, st, relpath, config.limits, config.owner_uid
                )
                if isinstance(verdict, Refuse):
                    counters.refuse("admission-" + verdict.reason.split(":")[0].split("=")[0])
                    log_refusal_once(
                        logger,
                        "%s|%s|%s" % (_root_id, relpath, verdict.reason),
                        "refused %s/%s: %s" % (_root_id, relpath, verdict.reason),
                    )
                    return
                assert isinstance(verdict, Copy)

                row = connection.execute(
                    "SELECT size, mtime_ns, sha256 FROM files WHERE watch_root = ? AND relpath = ?",
                    (_watch_root, relpath),
                ).fetchone()
                # M1: a relpath with NO record is always hashed and copied,
                # whatever its mtime — `mv` preserves mtime, so a file moved into
                # the tree looks old to a (size, mtime) test and would never be
                # seen again.
                if row is not None and row[0] == st.st_size and row[1] == st.st_mtime_ns:
                    return

                payload = _read_all(file_fd, st.st_size, config.limits.max_file_bytes)
                if payload is None:
                    counters.refuse("grew-past-cap")
                    logger.warn("refused %s/%s: grew past the size cap while being read"
                                % (_root_id, relpath))
                    return
                digest = hashlib.sha256(payload).hexdigest()
                now = int(time.time())

                # One predicate, evaluated at copy time on the ORIGINAL relpath,
                # decides which half of the store this goes to (review C4b).
                tree = dhu_backup_core.destination_for(
                    relpath, config.extra_vault_globs)
                path_dir = os.path.join(
                    config.tree_dir(tree),
                    dhu_backup_core.path_subpath(_root_id, _slug, relpath),
                )
                held = existing_versions(path_dir, os.path.basename(relpath))
                if held and held[-1][2] == digest[:dhu_backup_core.VERSION_HASH_CHARS]:
                    counters.already_held += 1
                    # The NEWEST version of this path already holds these bytes
                    # (a `touch`, or a rewrite with the same content). Refresh
                    # the index so we stop hashing it every cycle. Only the
                    # newest is compared: a revert to OLDER content is a real
                    # change and gets its own version, so `--asof` and `restore`
                    # describe what the file actually held. The first shipped
                    # version compared the full 64-hex digest against 12-hex
                    # prefixes, so this branch never ran and every `touch`
                    # wrote a duplicate version (independent review, 2026-09-11).
                    _remember(connection, _root_id, _watch_root, relpath, st, digest, now, row)
                    return

                entry_verdict = dhu_backup_core.entry_budget_decision(
                    len(payload), counters.versions_written, config.limits
                )
                if isinstance(entry_verdict, Skip):
                    counters.refuse("skip-%s" % entry_verdict.reason)
                    # Keyed by REASON for the throttle, by file for everything
                    # else: a cold start defers ~4,300 files, which would consume
                    # 85% of the de-dupe cap on the first scan and then silence
                    # the log for genuinely new refusals (round-2 review, M13).
                    key = (
                        "skip|throttle"
                        if entry_verdict.reason == "new-files-per-scan-throttle"
                        else "skip|%s|%s|%s" % (_root_id, relpath, entry_verdict.reason)
                    )
                    log_refusal_once(
                        logger, key,
                        "skipped %s/%s: %s (further throttle skips are counted, not logged)"
                        % (_root_id, relpath, entry_verdict.reason),
                    )
                    return

                store_verdict = dhu_backup_core.budget_decision(
                    store_bytes, free_bytes, len(payload), config.limits
                )
                if isinstance(store_verdict, Degraded):
                    degraded_reason = store_verdict.reason
                    return

                # Per-path ROLLING WINDOW, not a skip. As a skip this cap
                # inverted the guarantee for exactly the file the incident lost:
                # an actively edited file reaches the cap in under an hour at a
                # 15 s interval, and from then on its NEWEST content was the one
                # thing missing from the store. Ordering is by the capture clock
                # in the key (C12), so `touch -t` cannot choose what is dropped.
                window = dhu_backup_core.version_window_plan(
                    [(key, epoch_ns) for key, epoch_ns, _sha in held],
                    config.limits.max_versions_per_path,
                )
                if window:
                    rolled, rolled_bytes, rolled_failed, _pinned = remove_version_dirs(
                        [(path_dir, key) for key in window], logger
                    )
                    store_bytes = max(0, store_bytes - rolled_bytes)
                    counters.rolled += rolled
                    if rolled_failed:
                        counters.refuse("version-window-removal-failed")
                    log_refusal_once(
                        logger, "window|%s|%s" % (_root_id, relpath),
                        "%s/%s reached %d versions — rolling the window (further rolls "
                        "on this path are counted, not logged)"
                        % (_root_id, relpath, config.limits.max_versions_per_path),
                    )

                try:
                    written = write_version(
                        config, tree, _root_id, _slug, relpath, payload, digest, logger
                    )
                except OSError as exc:
                    # A store write that fails (ENOSPC, EROFS, EPERM, EDQUOT)
                    # means the store has stopped accepting data. Sharing the
                    # source-read handler filed it under `read-*`, blamed the
                    # source file in the log, and left the daemon reporting "ok"
                    # forever while mirroring nothing (internal audit, injected).
                    degraded_reason = "store-write-failed:%s" % _errname(exc)
                    counters.refuse("store-write-%s" % _errname(exc))
                    logger.error("STORE WRITE FAILED (%s) — the store is not accepting data"
                                 % _errname(exc))
                    return
                if written is not None:
                    counters.versions_written += 1
                    counters.bytes_written += len(payload)
                    store_bytes += len(payload)
                    if tree == dhu_backup_core.VAULT_TREE:
                        counters.vaulted += 1
                    logger.info("captured %s/%s -> %s (%d bytes)"
                                % (_root_id, relpath, tree, len(payload)))
                _remember(connection, _root_id, _watch_root, relpath, st, digest, now, row)
            except OSError as exc:
                counters.refuse("read-%s" % _errname(exc))
                logger.warn("read failed %s/%s: %s" % (_root_id, relpath, _errname(exc)))
            finally:
                os.close(file_fd)

        try:
            walk_root(root_fd, counters, logger, handle_file, watch_root,
                      exclude_globs=config.exclude_globs,
                      worktrees_covered=worktrees_covered_by_another_root(watch_root, roots))
        finally:
            os.close(root_fd)

    meta_set(connection, "store_bytes", store_bytes)
    connection.commit()

    if degraded_reason:
        if not state.get("degraded_reason"):
            state["degraded_reason"] = degraded_reason
            state["degraded_since"] = int(time.time())
        # EVERY cycle, not just the transition. The docs promised "an ERROR is
        # logged every cycle" and the guard made it one line per process, so an
        # operator tailing the log saw silence in the steady state (internal audit).
        logger.error(
            "DEGRADED (%s) — mirroring has STOPPED. Everything already stored is kept. "
            "This never self-heals; a human must widen the budget or free space."
            % state["degraded_reason"]
        )

    return counters, store_bytes, free_bytes, len(roots), len(root_refusals), None


def _read_all(fd, size, cap):
    """Read the whole file from an already-open fd. None if it grew past the cap."""
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, READ_CHUNK)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


def _remember(connection, root_id, watch_root, relpath, st, digest, now, previous_row):
    connection.execute(
        "INSERT INTO files (root_id, watch_root, relpath, size, mtime_ns, sha256, first_seen, last_seen)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(watch_root, relpath) DO UPDATE SET"
        "  size = excluded.size, mtime_ns = excluded.mtime_ns,"
        "  sha256 = excluded.sha256, last_seen = excluded.last_seen",
        (
            root_id,
            watch_root,
            relpath,
            st.st_size,
            st.st_mtime_ns,
            digest,
            now,
            now,
        ),
    )


# ── retention ─────────────────────────────────────────────────────────────────


def collect_index_rows(tree_root):
    """[(path_dir, leaf, version_key, capture_epoch_ns)] for every version in a tree.

    Walks the mirrored tree looking for directories whose name parses as a
    version key. The capture clock comes from that key and from nowhere else
    (C12) — never from the stored file's mtime, which is a copy of an
    agent-controlled value. The LEAF is part of the row because it is what
    identifies the path: version directories of every file in one source
    directory are siblings, and a plan keyed on the directory alone kept one
    version per directory (independent review, 2026-09-11). A version
    directory with no leaf (a crash between mkdir and link) carries `None` and
    ages out like any other.
    """
    rows = []
    for dirpath, dirnames, _filenames in os.walk(tree_root):
        for name in list(dirnames):
            parsed = dhu_backup_core.parse_version_key(name)
            if parsed is None:
                continue
            dirnames.remove(name)  # a version directory holds one leaf; do not descend
            leaves = _listdir(os.path.join(dirpath, name))
            rows.append((dirpath, leaves[0] if leaves else None, name, parsed[0]))
    return rows


def held_paths(tree_root):
    """`{(path_dir, leaf)}` — every mirrored path with at least one version."""
    return set((path_dir, leaf) for path_dir, leaf, _name, _ns in collect_index_rows(tree_root)
               if leaf is not None)


def reconcile_index_with_store(config, connection, logger):
    """Forget index rows whose path has NO version left in either tree.

    The index short-circuits a file whose size and mtime are unchanged, so a
    file whose versions were removed from the store (by the directory-keyed
    window and prune that shipped first — independent review, 2026-09-11)
    stays unprotected until it changes. Dropping its row makes the next scan
    hash and capture it again. Runs at start and after every prune, and it
    only ever DELETES INDEX ROWS: the store is not touched. Returns the count.
    """
    held = held_paths(config.store_dir) | held_paths(config.vault_dir)
    rows = connection.execute("SELECT root_id, watch_root, relpath FROM files").fetchall()
    forgotten = 0
    for root_id, watch_root, relpath in rows:
        if not dhu_backup_core.is_safe_relpath(relpath):
            continue
        slug = dhu_backup_core.root_slug(root_id, watch_root)
        tree = dhu_backup_core.destination_for(relpath, config.extra_vault_globs)
        path_dir = os.path.join(config.tree_dir(tree),
                                dhu_backup_core.path_subpath(root_id, slug, relpath))
        if (path_dir, os.path.basename(relpath)) in held:
            continue
        connection.execute("DELETE FROM files WHERE watch_root = ? AND relpath = ?",
                           (watch_root, relpath))
        forgotten += 1
    connection.commit()
    if forgotten:
        logger.warn("index: %d indexed path(s) had no version in the store and will be "
                    "captured again on the next scan" % forgotten)
    return forgotten


def _listdir(path):
    try:
        return os.listdir(path)
    except OSError:
        return []


def remove_version_dirs(plan, logger):
    """Unlink the version directories in `plan`. The ONE deletion path.

    Shared by age pruning and the per-path rolling window so retention has a
    single executor. It is never called by a test: `prune_plan` and
    `version_window_plan` return plans, and this applies them (the incident — a
    destructive sink is not fired to prove its guard).

    Returns (removed, freed_bytes, failed, link_pinned).
    """
    removed = freed = failed = pinned = 0
    for path_dir, key in plan:
        version_dir = os.path.join(path_dir, key)
        try:
            for leaf in os.listdir(version_dir):
                target = os.path.join(version_dir, leaf)
                st = os.lstat(target)
                os.unlink(target)
                # Credited only AFTER the unlink succeeds.
                freed += st.st_size
                if st.st_nlink > 1:
                    # M8: an agent can `ln` a 0444 store file into its own
                    # workspace — linking needs write permission only on the
                    # destination — which pins the inode so this frees nothing.
                    pinned += 1
                    logger.warn("removed a version with %d links — space not reclaimed"
                                % st.st_nlink)
            os.rmdir(version_dir)
            removed += 1
        except OSError as exc:
            failed += 1
            logger.warn("version removal failed %s: %s" % (key, _errname(exc)))
    return removed, freed, failed, pinned


def run_prune(config, connection, logger):
    """The ONE deletion the store ever performs. Plan first, then execute.

    `dhu_backup_core.prune_plan` is pure and tested; this executor is never called by a
    test, so no mutated destructive sink is ever fired.
    """
    window_ns = config.retention_days * 24 * 60 * 60 * 1_000_000_000
    freed = 0
    failed = 0
    planned = 0
    pinned = 0
    for tree_root in (config.store_dir, config.vault_dir):
        rows = collect_index_rows(tree_root)
        plan = dhu_backup_core.prune_plan(rows, time.time_ns(), window_ns)
        planned += len(plan)
        _removed, tree_freed, tree_failed, tree_pinned = remove_version_dirs(plan, logger)
        freed += tree_freed
        failed += tree_failed
        pinned += tree_pinned
    if planned:
        store_bytes = max(0, int(meta_get(connection, "store_bytes", "0")) - freed)
        meta_set(connection, "store_bytes", store_bytes)
        connection.commit()
        logger.info("pruned %d of %d planned versions (%d bytes, %d failures, %d link-pinned) "
                    "beyond the %d-day window"
                    % (planned - failed, planned, freed, failed, pinned, config.retention_days))
    return planned - failed, freed, failed


def _prune_and_record(config, connection, logger, state):
    """Run the prune and put its outcome where a reader can see it.

    Both call sites used to discard the return value, so a prune that failed on
    every version was indistinguishable from one with nothing to do.
    """
    try:
        removed, freed, failed = run_prune(config, connection, logger)
        state["prune_last_removed"] = removed
        state["prune_last_failed"] = failed
        state["index_reconciled"] = reconcile_index_with_store(config, connection, logger)
        if failed:
            logger.error("prune could not remove %d version(s)" % failed)
    except Exception as exc:  # noqa: BLE001
        state["prune_last_failed"] = -1
        logger.error("prune failed: %s: %s" % (type(exc).__name__, exc))


# ── heartbeat ─────────────────────────────────────────────────────────────────


def write_state(config, state, counters, store_bytes, free_bytes, roots, refused_roots,
                scan_error=None, trigger=None, interpreter_ok=None, logger=None):
    """state.json — counts and state ONLY, never paths (H4).

    FIVE distinguishable states, because a reader must be able to tell these
    apart and the first version could not:

      ok            mirroring comfortably, with at least one usable watch root.
      warning       mirroring NORMALLY, and close to a store-wide budget that
                    will stop it. Never conflated with `ok`: capture ending is
                    designed for, capture ending with no notice is the defect.
                    A volume at 99% full with 16.1 GiB free against a 10 GiB
                    floor reported `ok` up to the cycle that stopped it.
      degraded      a store-wide budget stopped it. Never self-heals.
      unprotected   the daemon is alive and healthy and is watching NOTHING —
                    an unreadable watchlist, every root refused, or a wrong
                    `owner_uid`. The first version wrote "ok" here, with
                    `files_scanned: 0`, and a status banner reading it said
                    "protecting uncommitted work" (internal audit, reproduced).
      scan-failed   the scan raised. Previously the heartbeat was simply not
                    rewritten, so it kept describing the last SUCCESSFUL scan
                    and read as "ok" for the whole staleness window.
    """
    # Computed here rather than passed in: it is a pure function of the two
    # numbers already on their way into this payload, so it cannot disagree with
    # the `store_bytes` and `free_bytes` printed beside it.
    warning = dhu_backup_core.budget_warning(store_bytes or 0, free_bytes, config.limits)

    # Ordered most-severe first. `warning` sits BELOW the three failures because
    # it is a forecast about a daemon that is capturing, and each of those three
    # says it is not capturing (or is protecting nothing) right now.
    if state.get("degraded_reason"):
        status = "degraded"
    elif scan_error is not None:
        status = "scan-failed"
    elif roots == 0:
        status = "unprotected"
    elif warning is not None:
        status = "warning"
    else:
        status = "ok"

    payload = {
        "state": status,
        "last_scan_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "last_scan_epoch": int(time.time()),
        "files_scanned": counters.files_scanned,
        "versions_written": counters.versions_written,
        "bytes_written": counters.bytes_written,
        "content_already_held": counters.already_held,
        "vaulted": counters.vaulted,
        # The operator extension, REPORTED rather than assumed. A malformed
        # vault-extra.conf must not be a file that looks like it is working:
        # `vault_extra_refused` above zero is the operator's signal that a line
        # they believe is protecting something is not.
        "vault_extra_globs": len(config.extra_vault_globs),
        "vault_extra_refused": len(config.extra_vault_refusals),
        # The SUBTRACTIVE operator extension, reported the same way and for a
        # sharper reason: every glob in force here is protection the operator
        # has switched off, and every refused line is a directory they believe
        # is being skipped and is not. `refusals_by_reason` carries
        # `walk-excluded-dir-operator` beside these, so "the rule exists" and
        # "the rule fired" are two separate, visible facts.
        "exclude_globs": len(config.exclude_globs),
        "exclude_refused": len(config.exclude_refusals),
        "versions_rolled": counters.rolled,
        "refusals_by_reason": counters.refusals,
        # Files whose copy was DEFERRED to a later scan by the per-scan
        # throttle. Named for what it counts: it includes files that already
        # have an older version stored, so it is "not up to date", not "not
        # protected at all". A cold start on this repo defers ~4,300 files.
        "files_deferred_by_throttle": counters.refusals.get("skip-new-files-per-scan-throttle", 0),
        # The trigger, reported rather than assumed. `trigger` is the NAME of
        # what is actually running — a chosen trigger that failed to start says
        # `poll-only`, never its own name. `trigger_watch_failures` above zero
        # means some directories lost their accelerator (inotify's ENOSPC /
        # EMFILE, a directory that vanished between the walk and the watch);
        # capture is unaffected because the floor sweep is the guarantee, and
        # latency for those directories is. Both are invisible without this.
        "directories_watched": (trigger.directories_watched if trigger is not None else None),
        "trigger": (trigger.name if trigger is not None else "poll-only"),
        "trigger_watch_failures": (trigger.watch_failures if trigger is not None else None),
        # Review H2 as a heartbeat FIELD, not only a log line: false here means
        # the bytes this root daemon executes are replaceable by the owner's own
        # account, which is the whole threat model inverted. A boolean and not a
        # path — no paths ever appear in this file (H4).
        "interpreter_root_owned": interpreter_ok,
        "watch_roots": roots,
        "watch_roots_refused": refused_roots,
        "store_bytes": store_bytes,
        "free_bytes": free_bytes,
        # The two numbers those are measured AGAINST, always present rather than
        # only under `warning`. "16.1 GiB free" is not a fact a reader can act
        # on without the floor it is heading for, and a reader who has to open
        # etc/dhu-backupd.conf to interpret the heartbeat will not.
        "min_free_bytes": config.limits.min_free_bytes,
        "max_store_bytes": config.limits.max_store_bytes,
        "retention_days": config.retention_days,
        "interval_seconds": config.interval_seconds,
        "prune_last_removed": state.get("prune_last_removed"),
        "prune_last_failed": state.get("prune_last_failed"),
    }
    if warning is not None:
        # A LIST, always, even for one reason. Both triggers can be true at
        # once — a nearly-full store on a nearly-full volume is one situation,
        # not two heartbeats — and a single-string field would force a lossy
        # choice between two live facts. A reader parses one shape.
        payload["warning_reason"] = list(warning.reasons)
        payload["warning_detail"] = warning.detail
    if state.get("degraded_reason"):
        payload["degraded_reason"] = state["degraded_reason"]
        payload["degraded_since_epoch"] = state.get("degraded_since")
    if scan_error is not None:
        payload["scan_error"] = scan_error
    write_json_atomic(config, config.state_path, payload, STATE_FILE_MODE)
    _log_warning_transition(state, warning, logger)


def _log_warning_transition(state, warning, logger):
    """Log a budget warning when it ARRIVES or CHANGES, and when it clears.

    Deliberately NOT every cycle, which is where this differs from the DEGRADED
    line. Degraded is a terminal condition an operator may be tailing for, and
    it stops the log growing by stopping capture. A warning is the steady state
    for as long as the volume is tight: one line per 15 s scan is 5,760 lines a
    day into a root-owned file with no rotation, on the same volume whose free
    space is what the warning is about. The heartbeat carries it every cycle;
    the log carries the EVENT.
    """
    previous = state.get("warning_reason")
    current = list(warning.reasons) if warning is not None else None
    state["warning_reason"] = current
    if logger is None or current == previous:
        return
    if current:
        logger.warn("WARNING (%s) — %s. Capture is still running; it will STOP, and "
                    "stopping never self-heals." % (",".join(current), warning.detail))
    elif previous:
        logger.info("warning cleared (%s) — back inside the budgets" % ",".join(previous))


def load_persisted_state(config):
    """Degradation survives a restart. It NEVER self-heals (review C11)."""
    try:
        with open(config.state_path) as handle:
            payload = json.load(handle)
    except (IOError, ValueError):
        return {}
    if payload.get("state") == "degraded":
        return {
            "degraded_reason": payload.get("degraded_reason", "unknown"),
            "degraded_since": payload.get("degraded_since_epoch"),
        }
    return {}


# ── main ──────────────────────────────────────────────────────────────────────


def _handle_signal(_signum, _frame):
    _STOP["flag"] = True


def _check_own_interpreter(logger, executable):
    """Log the verdict on the interpreter this process is running under.

    Returns True/False. The rule itself is `dhu_backup_core.interpreter_verdict`
    — the SAME pure function install.sh calls before writing the service file —
    so there is one place the rule is written down and one place it is tested.
    """
    if not executable:
        logger.error("INTERPRETER: sys.executable is empty; cannot check who owns "
                     "the bytes this root daemon is executing (review H2)")
        return False
    try:
        link_uid = os.lstat(executable).st_uid
        is_symlink = os.path.islink(executable)
    except OSError:
        link_uid, is_symlink = None, False
    try:
        target = os.path.realpath(executable)
        target_uid = os.stat(target).st_uid
    except OSError:
        target, target_uid = None, None
    verdict = dhu_backup_core.interpreter_verdict(
        executable, is_symlink, link_uid, target, target_uid)
    if verdict.ok:
        logger.info("interpreter: %s" % verdict.reason)
    else:
        logger.error("INTERPRETER NOT ROOT-OWNED (review H2): %s — a root daemon "
                     "executing bytes an agent can replace is a root shell for that "
                     "agent. Reinstall against a root-owned interpreter."
                     % verdict.reason)
    return verdict.ok


def main(argv=None):
    parser = argparse.ArgumentParser(prog="dhu-backupd", description="DHU Backup daemon")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--once", action="store_true", help="one scan, then exit")
    parser.add_argument("--interval", type=int, default=None, help="override the poll interval")
    parser.add_argument("--prune-now", action="store_true", help="run the prune pass immediately")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    if args.interval is not None:
        config.interval_seconds = args.interval

    ensure_dir(config.var_dir, 0o755)
    ensure_dir(config.store_dir, STORE_DIR_MODE)
    ensure_dir(config.vault_dir, VAULT_DIR_MODE)
    ensure_dir(config.roots_dir, STORE_DIR_MODE)
    ensure_dir(config.tmp_dir, 0o700)

    logger = Logger(config.log_path)
    logger.info(
        "start pid=%d uid=%d config=%s interval=%ds retention=%dd"
        % (os.getpid(), os.geteuid(), config.config_path, config.interval_seconds,
           config.retention_days)
    )

    config.extra_vault_globs, config.extra_vault_refusals = load_vault_extra(config)
    if config.extra_vault_globs:
        logger.info("vault-extra: %d basename glob(s) from %s"
                    % (len(config.extra_vault_globs), config.vault_extra_path))
    for line, reason in config.extra_vault_refusals:
        # Never dropped silently: a refused line is a rule the operator believes
        # is in force and is not.
        logger.error("vault-extra REFUSED %r: %s" % (line, reason))

    config.exclude_globs, config.exclude_refusals = load_exclude(config)
    if config.exclude_globs:
        # WARN and not INFO. Every glob here is protection the operator has
        # switched off, and it is the one config in the tree that can only
        # subtract. The count belongs in the log at a level someone greps for.
        logger.warn("exclude.conf: %d directory-name glob(s) from %s — directories "
                    "matching these are NOT protected: %s"
                    % (len(config.exclude_globs), config.exclude_path,
                       ", ".join(repr(g) for g in config.exclude_globs)))
    for line, reason in config.exclude_refusals:
        logger.error("exclude.conf REFUSED %r: %s" % (line, reason))

    connection = open_index(config)
    if meta_get(connection, "store_bytes") is None:
        measured = (measure_store_bytes(config.store_dir)
                    + measure_store_bytes(config.vault_dir))
        meta_set(connection, "store_bytes", measured)
        connection.commit()
        logger.info("measured existing store: %d bytes" % measured)

    state = load_persisted_state(config)
    if state.get("degraded_reason"):
        logger.error("resuming DEGRADED (%s) — mirroring stays stopped" % state["degraded_reason"])

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # H2, checked at every start rather than only at install time. The
    # installer asserts this before it writes the service file; a machine can
    # change underneath that (a package upgrade, an operator's pyenv shim), and
    # the one process that would notice is this one. REPORTED, not enforced: the
    # daemon is already executing under that interpreter by the time it can look,
    # so refusing to run would only remove the protection while leaving the
    # interpreter exactly as it is. What it can do is say so, loudly, every cycle.
    interpreter_ok = _check_own_interpreter(logger, sys.executable)

    trigger = make_trigger(logger)
    logger.info("directory trigger: platform=%s selected=%s running=%s"
                % (sys.platform, dhu_backup_core.trigger_name_for_platform(sys.platform),
                   trigger.name))
    if isinstance(trigger, InotifyTrigger) and trigger.available:
        # Printed at startup, with the number it is measured against, because
        # ENOSPC on inotify_add_watch is the one limit an operator can actually
        # act on (`sysctl fs.inotify.max_user_watches`) and the one that is
        # otherwise silent: the floor sweep hides it perfectly.
        logger.info("inotify max_user_watches=%s (one watch per watched DIRECTORY; "
                    "over the limit, those directories fall back to the floor sweep)"
                    % (trigger.watch_limit if trigger.watch_limit is not None
                       else "UNREADABLE " + INOTIFY_MAX_USER_WATCHES))

    # A path the index remembers but the store no longer holds is a path that
    # would never be captured again. Checked once at start (the store built by
    # the first shipped version has such paths) and after every prune.
    state["index_reconciled"] = reconcile_index_with_store(config, connection, logger)

    last_prune = 0.0
    if args.prune_now:
        _prune_and_record(config, connection, logger, state)
        last_prune = time.time()

    while True:
        started = time.time()
        scan_error = None
        try:
            counters, store_bytes, free_bytes, roots, refused, scan_error = scan_once(
                config, connection, logger, state
            )
        except Exception as exc:  # noqa: BLE001 — a scan must never kill the daemon silently
            # sqlite3.Error is not an OSError, so an index failure lands here.
            # The heartbeat is published ANYWAY, saying scan-failed: leaving the
            # previous one in place made a daemon that throws every cycle
            # indistinguishable from a healthy one for five minutes, and then
            # from a DEAD one forever (internal audit, injected).
            scan_error = "%s: %s" % (type(exc).__name__, exc)
            logger.error("scan failed: %s" % scan_error)
            # store_bytes is None, not 0: a failed scan measured nothing, and a
            # fabricated zero for a store that may hold gigabytes is the shape
            # that turned a data problem into a "hallucination" once already.
            counters, store_bytes, free_bytes, roots, refused = Counters(), None, None, 0, 0
        if not args.once:
            added, dropped = trigger.refresh(counters.directories)
            if trigger.available and trigger.directories_watched < len(counters.directories):
                # Said once per cycle rather than never: "watching 900 of 1,500
                # directories" is the difference between second-latency and
                # interval-latency for the other 600, and nothing else reports it.
                logger.warn("trigger: watching %d of %d directories (%d failure(s) so far)"
                            % (trigger.directories_watched, len(counters.directories),
                               trigger.watch_failures))
        try:
            write_state(config, state, counters, store_bytes, free_bytes, roots, refused,
                        scan_error=scan_error, trigger=trigger,
                        interpreter_ok=interpreter_ok, logger=logger)
        except Exception as exc:  # noqa: BLE001
            # The heartbeat is the only surface a reader has. If publishing it
            # fails, say so on the one channel that is left.
            logger.error("HEARTBEAT PUBLISH FAILED: %s: %s — the state file is now STALE"
                         % (type(exc).__name__, exc))

        if not state.get("degraded_reason") and time.time() - last_prune >= config.prune_interval_seconds:
            _prune_and_record(config, connection, logger, state)
            last_prune = time.time()

        if args.once or _STOP["flag"]:
            break

        # The trigger only ACCELERATES; the floor sweep below is the guarantee
        # and is the interval that was proven in staging. On macOS a directory
        # event (create / delete / rename) wakes the next sweep in milliseconds
        # and an in-place rewrite does NOT fire one, so it waits for the floor.
        # On Linux a directory watch also reports IN_CLOSE_WRITE for files
        # inside it, so the in-place rewrite wakes it too — measured, see
        # src/README.md. Neither changes the floor, which is the guarantee.
        elapsed = time.time() - started
        remaining = max(0.5, config.interval_seconds - elapsed)
        if trigger.wait(remaining):
            # Debounced: a burst of writes must not turn into a scan per write.
            time.sleep(min(config.trigger_debounce_seconds, remaining))

    trigger.close()
    logger.info("stop pid=%d" % os.getpid())
    connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
