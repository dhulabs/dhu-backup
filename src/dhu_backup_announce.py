#!/usr/bin/env -S /usr/bin/python3 -E -s -S
# `env -S` and not a bare `#!/usr/bin/python3 -E -s -S`: LINUX passes the whole
# tail of a shebang line as ONE argument, so that spelling reaches python as the
# single option "-E -s -S" and it exits with `Unknown option: -`. macOS splits
# it and works. Measured in the container, 2026-09-02, on this file. `env -S`
# splits it itself and is present and root-owned on both platforms; the
# interpreter after it stays ABSOLUTE, so no PATH lookup is introduced and the
# three flags that drop PYTHON* env, the user site directory and site.py all
# survive (review H3).
"""DHU Backup — self-announcing recovery (Property 4). Installed as
`bin/dhu_backup_announce.py`. UNPRIVILEGED, and importable as a library.

    from dhu_backup_announce import announce, format_text, to_json
    result = announce("/Users/you/Projects/x/lib/gone.ts")
    if result.status == "held":
        print(format_text(result))

This is what an agent tool calls when its own read fails with ENOENT. The point
of Property 4 is that the ERROR carries the recovery: an agent that never read
the project's instructions file still learns, at the moment it needs to, that
three versions of the file it just lost are on disk and how to read them back.

**It sits on the hot path of every failed read, so it must be cheap.** The
helper's `load_entries` walks the whole store — about 6,000 paths on this
machine — to answer any question at all. Nothing here calls it. A file lookup is
one `listdir` of that path's version-parent directory plus one `lstat` per
version directory found; a not-held file costs two `stat`s and stops. The store
layout is what makes that possible: a path's versions live at exactly
`store/<root-id>/<slug>/<relpath-dir>/@<capture>-<sha>/<basename>`, so the
directory to list is computable from the path alone.

**It must never raise.** A recovery hint that throws inside an error handler
turns a recoverable ENOENT into a crash in the tool that was trying to help.
Every `OSError` becomes a `store-unavailable` result carrying the errno text —
which is a REPORT, never a fallback to "nothing is held". Those are opposite
claims and an agent that confuses them abandons work that is on disk.

It holds no privilege the agent lacks (review C9): it reads a world-readable
store as the caller, opens nothing else, and writes nothing at all.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dhu_backup_core  # noqa: E402
from dhu_backup_core import Located  # noqa: E402

DEFAULT_INSTALL_ROOT = dhu_backup_core.DEFAULT_INSTALL_ROOT

#: Version directories examined for one file lookup. A path's versions are
#: capped at 200 by the daemon, but a directory holding many files holds all of
#: their version directories as siblings, so the listing is bounded by the
#: directory's fan-out and not by that cap. Above this the NEWEST keys are kept
#: (version keys sort lexically by a zero-padded capture clock) and the result
#: says it was capped, rather than pretending the list is complete.
MAX_VERSION_DIRS = 20000

#: Distinct paths counted under a held directory before the walk stops and the
#: result reports "at least N". A deleted directory is the incident's shape, and
#: an unbounded walk of a watch root on the hot path is not acceptable.
MAX_HELD_PATHS = 10000


# ── the probe ─────────────────────────────────────────────────────────────────


def read_vault_extra(install_root):
    """`(globs, refusals)` from `etc/vault-extra.conf`, unprivileged.

    The file is 0644 root-owned like the other etc/ files, so the helper, the
    hook and the MCP server read exactly what the daemon read. Reading it here
    is what lets an extra-glob match be announced as `vaulted` instead of as
    `not-held` — the one answer this tool must never give about a file it holds.
    Absent is not an error; unreadable is reported as a refusal, never as "no
    extra rules".
    """
    path = os.path.join(install_root, "etc", dhu_backup_core.VAULT_EXTRA_FILENAME)
    if not os.path.exists(path):
        return (), ()
    try:
        with open(path) as handle:
            text = handle.read()
    except (IOError, OSError) as exc:
        return (), ((path, "unreadable: %s" % exc),)
    return dhu_backup_core.parse_vault_extra(text)


def _read_roots(install_root):
    """`([(root_id, slug, watch_root)], error)` from `var/roots/*.json`."""
    directory = os.path.join(install_root, "var", "roots")
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        return [], "roots-unreadable: %s" % _errtext(exc, directory)
    roots = []
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(directory, name)) as handle:
                meta = json.load(handle)
        except (IOError, OSError, ValueError):
            # One unreadable manifest is not a store failure: the others still
            # describe real watch roots. It IS a smaller population than the
            # daemon has; when EVERY manifest fails the whole lookup is
            # reported unavailable rather than answered from a partial list.
            roots.append(None)
            continue
        if isinstance(meta, dict) and isinstance(meta.get("watch_root"), str):
            roots.append((meta.get("root_id"), meta.get("slug"), meta["watch_root"]))
        else:
            roots.append(None)
    good = [r for r in roots if r is not None]
    if names and not good:
        return [], ("roots-unreadable: %d manifest(s) under %s, none usable"
                    % (len(names), directory))
    return good, None


def read_state(install_root, now_epoch):
    """`(state, health)` — the parsed heartbeat AND its verdict, from ONE read.

    `state` is the raw dict, or None when there was nothing to parse. Callers
    that want only the verdict use `_read_health`, which is this function; the
    pair exists because `dhu-backup status` reports the store size, the free
    space and the glob counts that live in the SAME file the verdict came from,
    and reading it twice can hand a reader a verdict from one heartbeat beside
    numbers from the next. Never raises.
    """
    path = os.path.join(install_root, "var", "state.json")
    try:
        with open(path) as handle:
            state = json.load(handle)
    except (IOError, OSError) as exc:
        return None, dhu_backup_core.health_verdict(
            None, now_epoch, error_kind="missing",
            error_detail="no heartbeat at %s (%s)" % (path, _errtext(exc, path)))
    except ValueError as exc:
        return None, dhu_backup_core.health_verdict(
            None, now_epoch, error_kind="unreadable",
            error_detail="heartbeat at %s did not parse: %s" % (path, exc))
    return state, dhu_backup_core.health_verdict(state, now_epoch)


def _read_health(install_root, now_epoch):
    """`Health(verdict, detail)` for the daemon. Never raises."""
    return read_state(install_root, now_epoch)[1]


def _errtext(exc, path):
    strerror = getattr(exc, "strerror", None)
    if strerror:
        return "%s: %s" % (strerror, path)
    return "%s: %s" % (type(exc).__name__, path)


def _probe(install_root, located):
    """What the store holds for one located path, as DATA for the pure core.

    Returns the `lookup` dict `announce_missing` consumes. Never raises.
    """
    lookup = {"roots_error": None, "store_error": None, "probed": False,
              "versions": [], "held_path_count": 0,
              "held_path_count_capped": False, "versions_capped": False}
    store = os.path.join(install_root, dhu_backup_core.STORE_TREE)
    try:
        if not os.path.isdir(store):
            lookup["store_error"] = "store-not-found: %s" % store
            return lookup
    except OSError as exc:                                  # pragma: no cover
        lookup["store_error"] = _errtext(exc, store)
        return lookup

    if located.relpath:
        error = _probe_file(store, located, lookup)
        if error is not None:
            lookup["store_error"] = error
            return lookup
        if lookup["versions"]:
            lookup["probed"] = True
            return lookup

    error = _probe_directory(store, located, lookup)
    if error is not None:
        lookup["store_error"] = error
        return lookup
    lookup["probed"] = True
    return lookup


def _probe_file(store, located, lookup):
    """Versions of one exact path. One `listdir` + one `lstat` per candidate."""
    try:
        subpath = dhu_backup_core.path_subpath(located.root_id, located.slug, located.relpath)
    except ValueError as exc:                               # pragma: no cover
        # `locate_in_roots` already refused unsafe relpaths, so reaching here
        # means the two disagree; say so rather than guessing.
        return "unsafe-relpath: %s" % exc
    version_parent = os.path.join(store, subpath)
    basename = located.relpath.split("/")[-1]

    try:
        names = os.listdir(version_parent)
    except OSError as exc:
        if getattr(exc, "errno", None) in (2, 20):   # ENOENT, ENOTDIR
            # No directory of versions for this path. That is an ANSWER — the
            # store is readable and holds nothing here — not a failure.
            return None
        return "store-unreadable: %s" % _errtext(exc, version_parent)

    keyed = []
    for name in names:
        parsed = dhu_backup_core.parse_version_key(name)
        if parsed is not None:
            keyed.append((name, parsed))
    if len(keyed) > MAX_VERSION_DIRS:
        # Version keys begin with a zero-padded capture clock, so a descending
        # lexical sort is a descending chronological sort. Keeping the newest is
        # the right truncation: the newest version is the one you want back.
        keyed.sort(key=lambda item: item[0], reverse=True)
        keyed = keyed[:MAX_VERSION_DIRS]
        lookup["versions_capped"] = True

    versions = []
    for name, (epoch_ns, sha) in keyed:
        full = os.path.join(version_parent, name, basename)
        try:
            size = os.lstat(full).st_size
        except OSError:
            # This version directory belongs to a SIBLING file in the same
            # source directory — every file in one directory keeps its versions
            # as siblings here. Not an error, just not ours.
            continue
        versions.append({"key": name, "epoch_ns": epoch_ns, "sha": sha,
                         "size": size, "store_path": full,
                         "iso": iso(epoch_ns)})
    versions.sort(key=lambda v: (v["epoch_ns"], v["key"]))
    lookup["versions"] = versions
    return None


def _probe_directory(store, located, lookup):
    """How many distinct paths the store holds UNDER this path. Bounded walk."""
    parts = [p for p in located.relpath.split("/") if p] if located.relpath else []
    base = os.path.join(store, located.root_id, located.slug, *parts)
    try:
        if not os.path.isdir(base):
            return None
    except OSError as exc:                                  # pragma: no cover
        return "store-unreadable: %s" % _errtext(exc, base)

    held = set()
    try:
        for dirpath, dirnames, _filenames in os.walk(base, onerror=_raise):
            for name in list(dirnames):
                if dhu_backup_core.parse_version_key(name) is None:
                    continue
                dirnames.remove(name)   # never descend into a version directory
                for leaf in _listdir_quiet(os.path.join(dirpath, name)):
                    held.add((dirpath, leaf))
                    if len(held) >= MAX_HELD_PATHS:
                        lookup["held_path_count"] = len(held)
                        lookup["held_path_count_capped"] = True
                        return None
    except OSError as exc:
        return "store-unreadable: %s" % _errtext(exc, base)
    lookup["held_path_count"] = len(held)
    return None


def _raise(exc):
    raise exc


def _listdir_quiet(path):
    try:
        return os.listdir(path)
    except OSError:
        return []


def iso(epoch_ns):
    """Local-time ISO seconds for a capture clock."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch_ns / 1e9))


# ── the library call ──────────────────────────────────────────────────────────


def announce(abs_path, install_root=DEFAULT_INSTALL_ROOT, now=None):
    """Classify a path whose read just failed. NEVER raises.

    Returns a `dhu_backup_core.Announcement` whose `status` is one of
    `dhu_backup_core.ANNOUNCE_STATUSES`, always carrying the daemon's health
    verdict. Cost: a handful of `stat`/`listdir` calls. It never walks the store
    unless the path names a directory the store actually holds.
    """
    now_epoch = time.time() if now is None else now
    try:
        if not isinstance(install_root, str) or not install_root:
            # Never silently substitute the default. A caller that passed a bad
            # install root would get an answer about a DIFFERENT install, and
            # "not held" about the wrong store is the worst answer this tool can
            # give. Report that we could not look.
            return dhu_backup_core.Announcement(
                status="store-unavailable",
                path=abs_path if isinstance(abs_path, str) else repr(abs_path),
                reason="install_root is not a path: %r" % (install_root,),
                health="unreadable-heartbeat",
                health_detail="not determined: no install root to read a heartbeat from",
                install_root=DEFAULT_INSTALL_ROOT)
        health = _read_health(install_root, now_epoch)
        roots, roots_error = _read_roots(install_root)
        extra_globs, _extra_refusals = read_vault_extra(install_root)
        lookup = {"roots_error": roots_error, "store_error": None, "probed": False,
                  "versions": [], "held_path_count": 0,
                  "held_path_count_capped": False, "versions_capped": False}
        if roots_error is None:
            located = dhu_backup_core.locate_in_roots(abs_path, roots)
            if isinstance(located, Located) and not (
                located.relpath
                and dhu_backup_core.is_credential_class(located.relpath, extra_globs)
            ):
                lookup = _probe(install_root, located)
                lookup["roots_error"] = None
        return dhu_backup_core.announce_missing(
            abs_path, roots, lookup, health, now_epoch, install_root=install_root,
            extra_globs=extra_globs)
    except Exception as exc:            # noqa: BLE001 — the whole point
        # The contract is "never raises", and a contract that holds only for the
        # exceptions we thought of is not the contract. Anything unforeseen
        # becomes the honest status: we could not find out.
        return dhu_backup_core.Announcement(
            status="store-unavailable",
            path=abs_path if isinstance(abs_path, str) else repr(abs_path),
            reason="internal error: %s: %s" % (type(exc).__name__, exc),
            health="unreadable-heartbeat",
            health_detail="not determined: the lookup itself failed",
            install_root=install_root if isinstance(install_root, str)
            else DEFAULT_INSTALL_ROOT)


# ── rendering ─────────────────────────────────────────────────────────────────


#: Watch roots printed before the list is elided with a count.
_MAX_ROOTS_SHOWN = 6

_HEALTH_NOTE = {
    # Present tense for a thing that has not happened yet, and no hedging: the
    # store is still growing, which is exactly why there is time to act.
    "warning": "!! CAPTURE WILL STOP — a store-wide budget is close; capture is "
               "still running",
    "degraded": "!! CAPTURE STOPPED — nothing has been captured since it degraded",
    "unprotected": "!! THE DAEMON IS WATCHING NOTHING — no usable watch roots",
    "scan-failed": "!! EVERY CAPTURE IS FAILING",
    "stale": "!! STALE — the daemon may not be running",
    "no-heartbeat": "!! NO HEARTBEAT — DHU Backup may not be installed",
    "unreadable-heartbeat": "!! HEARTBEAT UNREADABLE — capture status UNKNOWN",
}


#: The sentence `dhu-backup status` prints for `ok`, and the one verdict
#: `_HEALTH_NOTE` deliberately has no entry for. That table is the list of
#: verdicts worth SHOUTING about on the hot path, and `format_text` prints an
#: entry the moment it finds one — so putting `ok` in it would hang a banner
#: over every announcement that has nothing wrong with it. Keeping the ok
#: sentence here, beside the table rather than in a second module, is what makes
#: `health_sentence` one vocabulary rather than two.
HEALTH_OK_SENTENCE = "OK — capture is running and the store is being written"


def health_sentence(verdict):
    """One sentence for any `dhu_backup_core.HEALTH_VERDICTS` member. PURE.

    The text is `_HEALTH_NOTE`'s, verbatim, "!!" and all: `status` says the
    same words about a degraded daemon that a failed read says, because an
    operator who has seen one should recognise the other.

    An unknown verdict raises, as `announce_exit_code` does for an unknown
    status. `health_verdict` cannot produce one, so reaching here means this
    file and the vocabulary have gone out of step, and saying nothing about a
    verdict we do not know is how `ok` gets printed over a stopped daemon.
    """
    if verdict == "ok":
        return HEALTH_OK_SENTENCE
    note = _HEALTH_NOTE.get(verdict)
    if note is None:
        raise ValueError("unknown health verdict: %r" % (verdict,))
    return note


def format_text(result):
    """A few lines an agent reads. Never raises."""
    lines = []
    note = _HEALTH_NOTE.get(result.health)
    if note:
        lines.append("%s (%s)" % (note, result.health_detail))

    if result.status == "held":
        newest = result.newest or {}
        lines.append("dhu-backup: HELD — %s%d version(s) of %s"
                     % ("at least " if result.versions_capped else "",
                        len(result.versions), result.relpath))
        lines.append("  origin  %s" % result.origin)
        lines.append("  newest  %s  (%s bytes, sha %s)"
                     % (newest.get("iso", "?"), newest.get("size", "?"), newest.get("sha", "?")))
    elif result.status == "held-directory":
        lines.append("dhu-backup: HELD (directory) — the store holds %s%d path(s) under %s"
                     % ("at least " if result.held_path_count_capped else "",
                        result.held_path_count, result.origin))
    elif result.status == "vaulted":
        lines.append("dhu-backup: VAULTED — %s is credential-class (%s), so if it was "
                     "captured it is in the root-only vault, which is unreadable "
                     "without sudo." % (result.relpath, result.reason))
        lines.append("  This tool cannot see the vault and does not claim the file is "
                     "there. Look with sudo:")
    elif result.status == "not-held":
        lines.append("dhu-backup: NOT HELD — %s is inside the watch root %s, the store "
                     "was read, and it holds no version of that path."
                     % (result.relpath, result.watch_root))
    elif result.status == "outside-watch-roots":
        lines.append("dhu-backup: NOT PROTECTED — %s (%s), so it was never captured."
                     % (result.path, result.reason))
        if result.watch_roots:
            # 30 watch roots on one line is not readable, and the point of the
            # line is "here is the shape of what IS protected", not a manifest.
            # The count is always stated so the elision is never silent.
            shown = list(result.watch_roots[:_MAX_ROOTS_SHOWN])
            more = len(result.watch_roots) - len(shown)
            lines.append("  %d watch root(s): %s%s"
                         % (len(result.watch_roots), ", ".join(shown),
                            (" ... and %d more" % more) if more else ""))
        else:
            lines.append("  no watch roots are configured.")
    elif result.status == "store-unavailable":
        lines.append("dhu-backup: STORE UNAVAILABLE — could not determine whether %s is "
                     "held: %s" % (result.path, result.reason))
        lines.append("  This is NOT the same as 'no versions'. Do not treat it as one.")
    else:                                                    # pragma: no cover
        lines.append("dhu-backup: %s" % result.status)

    lines.append("  daemon  %s (%s)" % (result.health, result.health_detail))
    for command in result.commands:
        lines.append("    %s" % command)
    return "\n".join(lines)


def to_json(result):
    """The machine-readable shape. `status` first; stable field names."""
    payload = {
        "status": result.status,
        "path": result.path,
        "health": result.health,
        "health_detail": result.health_detail,
        "reason": result.reason,
        "install_root": result.install_root,
        "root_id": result.root_id,
        "slug": result.slug,
        "watch_root": result.watch_root,
        "relpath": result.relpath,
        "origin": result.origin,
        "versions": [dict(v) for v in result.versions],
        "versions_capped": bool(result.versions_capped),
        "newest": dict(result.newest) if result.newest else None,
        "held_path_count": result.held_path_count,
        "held_path_count_capped": bool(result.held_path_count_capped),
        "watch_roots": list(result.watch_roots),
        "commands": list(result.commands),
        "exit_code": dhu_backup_core.announce_exit_code(result.status),
    }
    return payload


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    install_root = DEFAULT_INSTALL_ROOT
    if "--install-root" in argv:
        index = argv.index("--install-root")
        if index + 1 >= len(argv):
            sys.stderr.write("usage: dhu_backup_announce.py <path> [--json] "
                             "[--install-root DIR]\n")
            return 2
        install_root = argv[index + 1]
        del argv[index:index + 2]
    if len(argv) != 1:
        sys.stderr.write("usage: dhu_backup_announce.py <path> [--json] "
                         "[--install-root DIR]\n")
        return 2

    result = announce(argv[0], install_root=install_root)
    if as_json:
        print(json.dumps(to_json(result), indent=2))
    else:
        print(format_text(result))
    return dhu_backup_core.announce_exit_code(result.status)


if __name__ == "__main__":
    raise SystemExit(main())
