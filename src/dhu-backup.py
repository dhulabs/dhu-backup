#!/usr/bin/env -S /usr/bin/python3 -E -s -S
# `env -S` and not a bare `#!/usr/bin/python3 -E -s -S`: LINUX passes the whole
# tail of a shebang line as ONE argument, so that spelling reaches python as the
# single option "-E -s -S" and it exits with `Unknown option: -`. macOS splits
# it and works. Measured in the container, 2026-09-02, on this file. `env -S`
# splits it itself and is present and root-owned on both platforms; the
# interpreter after it stays ABSOLUTE, so no PATH lookup is introduced and the
# three flags that drop PYTHON* env, the user site directory and site.py all
# survive (review H3).
"""DHU Backup — recovery. Installed as `bin/dhu-backup`. UNPRIVILEGED.

    dhu-backup status [--json]                     is this working? and if not, what to type
    dhu-backup ls   <path-substring> [--root ID]   which protected paths have versions
    dhu-backup log  <path>                         versions of one path: time, size, hash
    dhu-backup cat  <path> [--asof T|--version @TAG]  print one version to stdout
    dhu-backup restore <path> [--asof T] [--into DIR]   restore one file
    dhu-backup restore-dir <dir> [--asof T] [--into DIR]  restore a directory as of a time
    dhu-backup missing <abs-path>                  what the store holds for a path that is GONE

`--asof` takes an ISO timestamp or a relative age (`20m`, `2h`, `3d`) and
resolves to the newest version at or before it.

**This helper holds no privilege the agent lacks, and nothing about the
guarantee depends on it.** It runs as the owner, reads a world-readable store,
and writes only where the caller could already write. An agent can bypass it
entirely with `ls` and `cp`, and that is fine — it exists for ergonomics, not
enforcement. The kernel enforces the mirror's integrity, not this code.

Three anti-patterns are therefore forbidden by name, because each would build a
privileged path back that the agent could drive:

  1. **No setuid-root helper.** The agent chooses the arguments; a setuid binary
     taking agent-chosen paths is an arbitrary root write.
  2. **No `sudoers` NOPASSWD entry** for this or for `tmutil`. Same defect,
     spelled differently, and it hands over passwordless root besides.
  3. **No command channel into the daemon** — no request file, no FIFO, no
     socket it polls for "please restore/prune/forget X". Any of those turns the
     one process the agent cannot touch into a proxy it can steer. The daemon
     reads its root-owned config and the watched trees, and nothing else, ever.

`vault/` (credential-class files) is unreadable here by directory mode. A
vaulted path is REPORTED as vaulted rather than silently missing, so an agent
gets an honest answer and the owner recovers it with sudo.
"""

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dhu_backup_core  # noqa: E402
import dhu_backup_announce  # noqa: E402
from dhu_backup_core import Refuse, Target  # noqa: E402

DEFAULT_INSTALL_ROOT = dhu_backup_core.DEFAULT_INSTALL_ROOT
RESTORE_LOG = os.path.expanduser("~/.dhu-backup-restores.log")


# ── reading the store ─────────────────────────────────────────────────────────


def load_roots(install_root):
    """{(root_id, slug): watch_root} from the daemon's manifests."""
    roots = {}
    directory = os.path.join(install_root, "var", "roots")
    for name in _listdir(directory):
        try:
            with open(os.path.join(directory, name)) as handle:
                meta = json.load(handle)
        except (IOError, ValueError):
            continue
        roots[(meta.get("root_id"), meta.get("slug"))] = meta.get("watch_root", "")
    return roots


def trees_this_process_may_read():
    """`("store",)` or `("store", "vault")` for THIS process. See `trees_to_read`."""
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    return dhu_backup_core.trees_to_read(euid, os.environ.get("DHU_BACKUP_ALLOW_ROOT"))


def load_entries(install_root):
    """Every mirrored path this process may read, with its versions.

    Deliberately reads the store TREE, not `var/index.sqlite3`. The index is
    written by a live root process, and a read-only SQLite open against a
    database with a hot rollback journal fails — a recovery tool that breaks
    precisely while the daemon is mid-commit is a recovery tool that breaks when
    you need it. The tree is plain files and is always readable.

    `vault/` is included ONLY for root with `DHU_BACKUP_ALLOW_ROOT` set, which
    is what makes the documented vault recovery — `sudo DHU_BACKUP_ALLOW_ROOT=1
    dhu-backup cat <path> > <origin>` — actually work. It was previously
    documented and did not: this function joined `install_root` with "store"
    and nothing else, so the helper found nothing in the vault however it was
    invoked. Each entry records the tree it came from so a reader is never left
    guessing which half of the mirror an answer came out of.
    """
    store = os.path.join(install_root, "store")
    if not os.path.isdir(store):
        return None, "store-not-found: %s" % store
    roots = load_roots(install_root)
    entries = {}
    for tree in trees_this_process_may_read():
        tree_root = os.path.join(install_root, tree)
        if not os.path.isdir(tree_root):
            # An absent `vault/` is not an error — nothing credential-class has
            # been captured yet, or this is not an install that has one. An
            # absent `store/` is caught above, before this loop.
            continue
        for root_id in sorted(_listdir(tree_root)):
            for slug in sorted(_listdir(os.path.join(tree_root, root_id))):
                base = os.path.join(tree_root, root_id, slug)
                watch_root = roots.get((root_id, slug), "")
                for dirpath, dirnames, _files in os.walk(base):
                    for name in list(dirnames):
                        if dhu_backup_core.parse_version_key(name) is None:
                            continue
                        dirnames.remove(name)
                        version_dir = os.path.join(dirpath, name)
                        leaves = [f for f in _listdir(version_dir)]
                        if not leaves:
                            continue
                        leaf = leaves[0]
                        relative_dir = os.path.relpath(dirpath, base)
                        relpath = leaf if relative_dir == "." else os.path.join(relative_dir, leaf)
                        epoch_ns, sha = dhu_backup_core.parse_version_key(name)
                        full = os.path.join(version_dir, leaf)
                        try:
                            size = os.lstat(full).st_size
                        except OSError:
                            continue
                        entry = entries.setdefault(
                            (tree, root_id, slug, relpath),
                            {"root_id": root_id, "slug": slug, "relpath": relpath,
                             "watch_root": watch_root, "tree": tree, "versions": []},
                        )
                        entry["versions"].append(
                            {"key": name, "epoch_ns": epoch_ns, "sha": sha,
                             "path": full, "size": size}
                        )
    result = list(entries.values())
    for entry in result:
        entry["versions"].sort(key=lambda v: v["epoch_ns"])
    result.sort(key=lambda e: (e["tree"], e["root_id"], e["relpath"]))
    return result, None


def _tree_tag(entry):
    """`"  [vault]"` for a vault entry, `""` for a store entry.

    Store-only output is therefore byte-identical to what it was before the
    vault could be read at all, which the golden test asserts. A root user
    reading both trees needs to know which half an answer came from, because
    only one of them is agent-readable.
    """
    return "  [vault]" if entry.get("tree") == dhu_backup_core.VAULT_TREE else ""


def vault_is_present(install_root):
    """Whether a root-only vault exists at all, so `ls` can be honest."""
    return os.path.isdir(os.path.join(install_root, "vault"))


def _listdir(path):
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def _iso(epoch_ns):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(epoch_ns / 1e9))


def select_entries(entries, needle, root_id=None):
    return [
        e for e in entries
        if (not root_id or e["root_id"] == root_id)
        and (not needle or needle in e["relpath"])
    ]


# ── the daemon's health, surfaced on every invocation ─────────────────────────


def print_health_banner(install_root):
    """C11: a degraded or stale daemon is announced BEFORE any result.

    A recovery tool that answers "no versions" without mentioning that capture
    stopped two days ago is answering a different question than the one asked.
    """
    path = os.path.join(install_root, "var", "state.json")
    try:
        with open(path) as handle:
            state = json.load(handle)
    except IOError:
        print("!! no heartbeat at %s — DHU Backup may not be installed" % path)
        return
    except ValueError:
        print("!! heartbeat at %s is unreadable — capture status UNKNOWN" % path)
        return
    label = state.get("state")
    age = int(time.time()) - int(state.get("last_scan_epoch") or 0)
    if label == "degraded":
        print("!! CAPTURE STOPPED (%s) — nothing has been captured since it degraded."
              % state.get("degraded_reason", "reason not recorded"))
    elif label == "unprotected":
        print("!! THE DAEMON IS WATCHING NOTHING — no usable watch roots.")
    elif label == "scan-failed":
        print("!! EVERY CAPTURE IS FAILING (%s)." % state.get("scan_error", "reason not recorded"))
    elif age > 300:
        # Checked BEFORE `warning`, and the same way round in `health_verdict`:
        # "the last capture was two days ago" supersedes a forecast about a
        # daemon that may not be running at all.
        print("!! STALE — the last capture was %ds ago; the daemon may not be running." % age)
    elif label == "warning":
        # Said in full, not softened. This is the one banner printed while
        # everything still works, and it is the whole point of the state: an
        # operator who reads "capture will stop" a week early can free space,
        # and one who reads `ok` until the day it stops cannot.
        print("!! CAPTURE WILL STOP (%s) — %s"
              % (",".join(state.get("warning_reason") or ["reason not recorded"]),
                 state.get("warning_detail", "no detail recorded")))


def health_object(install_root):
    """The same verdict as the banner, as DATA for `--json`.

    In JSON mode the banner cannot be a printed line — one line of prose ahead
    of the object would make every output unparseable, so a caller would learn
    to pass `--quiet` and would then never see that capture had stopped. It
    becomes a field instead, so the health travels with the answer rather than
    being something the caller can drop.
    """
    health = dhu_backup_announce._read_health(install_root, time.time())
    return {"verdict": health.verdict, "detail": health.detail}


def _emit_json(payload):
    print(json.dumps(payload, indent=2))


# ── status: "is this working?", answered unprivileged ─────────────────────────
#
# Everything below reads. The one question this product could not answer without
# `cat var/state.json` was the everyday one, and a status a human only reads by
# parsing JSON is a status nobody reads until the day their work is gone.

#: Version directories `status` will OPEN, across every watch root, to count the
#: paths the store holds. It is a budget rather than a cap on the answer because
#: it is the thing that costs: a path's versions are siblings in one directory,
#: so the only way to learn a path's NAME is to look inside a version directory.
#: Measured on a real store (2026-09-11): 37,425 version directories cost 1.2 s
#: of opens on top of a 0.6 s tree walk, so 20,000 keeps the whole command under
#: about a second on a store far larger than a first install has.
#:
#: A root whose share of the budget runs out reports "at least N", never a
#: silently truncated number — the same rule the announce probe follows when it
#: caps a version listing.
STATUS_VERSION_DIR_BUDGET = 20000


def read_watchlist(install_root):
    """`(entries, refusals, error)` from the root-owned `etc/watchlist.conf`.

    This file, not `var/roots/`, is what "the watch roots in force" means. The
    manifests under `var/roots/` are written per EXPANDED root and are never
    removed, so a machine whose watchlist changed last month still has
    manifests for directories nothing watches now — reading those would report
    protection that ended weeks ago.

    It is 0644 root-owned by design, so this needs no privilege. Unreadable is
    REPORTED as an error and never as "no roots configured": the second is a
    claim about the machine, and this code would not have grounds for it.
    """
    path = os.path.join(install_root, "etc", "watchlist.conf")
    try:
        with open(path) as handle:
            text = handle.read()
    except (IOError, OSError) as exc:
        return (), (), "watchlist-unreadable: %s (%s)" % (path, exc)
    entries, refusals = dhu_backup_core.parse_watchlist(text)
    return entries, refusals, None


def count_held_paths(store_dir, root_id, budget):
    """`(paths, capped, error, opened)` — distinct paths held under one root id.

    A PATH count, not a version count: a file with 200 versions counts once.
    The distinction matters because the number is read as "how much of my work
    is in there", and versions-per-path is a retention setting.

    The walk descends `store/<root-id>/` and treats a version-key directory as a
    leaf, opening it for the one basename it holds. `budget` bounds how many of
    those opens happen; when it runs out the count so far is returned with
    `capped=True`, so the caller says "at least N". `opened` is what was
    actually spent, so a root that finishes under its share hands the remainder
    back rather than burning it.
    """
    base = os.path.join(store_dir, root_id)
    held = set()
    opened = [0]

    def walk(directory):
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as exc:
            raise _StoreWalkError(_errtext(exc, directory))
        subdirectories = []
        for entry in entries:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:                                  # pragma: no cover
                continue
            if dhu_backup_core.parse_version_key(entry.name) is None:
                subdirectories.append(entry.path)
                continue
            if opened[0] >= budget:
                return False
            opened[0] += 1
            try:
                names = os.listdir(entry.path)
            except OSError as exc:
                # A version directory that cannot be listed is a path this
                # command cannot name, and skipping it quietly would subtract
                # one from a number a human reads as "how much of my work is in
                # there". Reported as an error on the whole root instead.
                raise _StoreWalkError(_errtext(exc, entry.path))
            for leaf in names:
                held.add((directory, leaf))
        for subdirectory in subdirectories:
            if not walk(subdirectory):
                return False
        return True

    if not os.path.isdir(base):
        # An answer, not a failure: the daemon writes `store/<root-id>/` on the
        # first capture, so a root configured five minutes ago legitimately has
        # no directory yet.
        return 0, False, None, 0
    try:
        complete = walk(base)
    except _StoreWalkError as exc:
        return len(held), True, str(exc), opened[0]
    return len(held), not complete, None, opened[0]


class _StoreWalkError(Exception):
    """A directory under the store could not be read. Reported, never swallowed."""


def _errtext(exc, path):
    strerror = getattr(exc, "strerror", None)
    return "%s: %s" % (strerror or type(exc).__name__, path)


def held_paths_by_root_id(install_root, root_ids, budget=STATUS_VERSION_DIR_BUDGET):
    """`{root_id: (paths, capped, error)}`, sharing one budget across the roots.

    The budget is divided as the walk goes — each root gets an equal share of
    what is LEFT, and hands back whatever it did not spend — so a first root
    with a huge history cannot consume the whole allowance and leave every later
    root reporting nothing, and four small roots do not leave three quarters of
    the budget unused. Deterministic: the same store, walked in watchlist order,
    produces the same numbers on every run.
    """
    store_dir = os.path.join(install_root, dhu_backup_core.STORE_TREE)
    counts = {}
    remaining = max(0, int(budget))
    left = list(root_ids)
    while left:
        root_id = left.pop(0)
        share = remaining // (len(left) + 1)
        paths, capped, error, opened = count_held_paths(store_dir, root_id, share)
        counts[root_id] = (paths, capped, error)
        remaining = max(0, remaining - opened)
    return counts


def store_root_ids(install_root):
    """`(root_ids, error)` — the top level of `store/`, one entry per watch id."""
    store_dir = os.path.join(install_root, dhu_backup_core.STORE_TREE)
    try:
        names = sorted(os.listdir(store_dir))
    except OSError as exc:
        return (), "store-unreadable: %s" % _errtext(exc, store_dir)
    return tuple(n for n in names if os.path.isdir(os.path.join(store_dir, n))), None


def status_payload(install_root, now=None, budget=STATUS_VERSION_DIR_BUDGET,
                   platform_string=None):
    """Everything `status` reports, as DATA. NEVER raises.

    The contract `announce` holds, for the same reason: this is the command an
    operator runs when they already suspect something is wrong, and a traceback
    there answers the question with "and now the tool is broken too".
    """
    now_epoch = time.time() if now is None else now
    platform_string = sys.platform if platform_string is None else platform_string
    if not isinstance(install_root, str) or not install_root:
        # Never silently substitute the default, for the reason `announce` does
        # not: an answer about a DIFFERENT install is the worst answer this
        # command can give, and "capturing normally" about the wrong store is
        # worse still.
        return _status_undetermined(
            dhu_backup_core.DEFAULT_INSTALL_ROOT,
            "install_root is not a path: %r" % (install_root,), platform_string)
    try:
        return _status_payload(install_root, now_epoch, budget, platform_string)
    except Exception as exc:            # noqa: BLE001 — the whole point
        return _status_undetermined(
            install_root,
            "the status lookup itself failed: %s: %s" % (type(exc).__name__, exc),
            platform_string)


def _status_undetermined(install_root, detail, platform_string):
    """The payload for "I could not find out", with every field still present.

    A caller reading `--json` gets the same keys it gets from a healthy
    install, so a missing field never has to stand in for a failure.
    """
    step = dhu_backup_core.status_next_step(
        "unreadable-heartbeat", install_root, platform_string)
    return {
        "install_root": install_root,
        "health": {"verdict": "unreadable-heartbeat", "detail": detail,
                   "sentence": dhu_backup_announce.health_sentence("unreadable-heartbeat")},
        "capturing": False,
        "exit_code": dhu_backup_core.status_exit_code("unreadable-heartbeat"),
        "last_capture": None, "watch_roots": None, "store": None,
        "free_space": None, "warning": None, "exclusions": None, "vault_extra": None,
        "next_step": {"sentence": step.sentence, "command": step.command},
    }


def _status_payload(install_root, now_epoch, budget, platform_string):
    state, health = dhu_backup_announce.read_state(install_root, now_epoch)
    state = state if isinstance(state, dict) else {}
    step = dhu_backup_core.status_next_step(health.verdict, install_root, platform_string)

    payload = {
        "install_root": install_root,
        "health": {"verdict": health.verdict, "detail": health.detail,
                   "sentence": dhu_backup_announce.health_sentence(health.verdict)},
        "capturing": health.verdict in dhu_backup_core.CAPTURING_VERDICTS,
        "exit_code": dhu_backup_core.status_exit_code(health.verdict),
        "last_capture": _last_capture(state, now_epoch),
        "watch_roots": _watch_root_status(install_root, state, budget),
        "store": _store_status(state),
        "free_space": _free_space_status(state),
        "warning": _warning_status(state, health),
        "exclusions": _glob_status(state, "exclude_globs", "exclude_refused"),
        "vault_extra": _glob_status(state, "vault_extra_globs", "vault_extra_refused"),
        "next_step": {"sentence": step.sentence, "command": step.command},
    }
    return payload


def _last_capture(state, now_epoch):
    raw = state.get("last_scan_epoch")
    try:
        epoch = int(raw)
    except (TypeError, ValueError):
        return None
    return {"epoch": epoch, "iso": _iso(epoch * 1_000_000_000),
            "age_seconds": max(0, int(now_epoch) - epoch)}


def _limits_from_state(state):
    """The daemon's OWN budgets, not this module's defaults.

    `etc/dhu-backupd.conf` can raise either ceiling, and that is the documented
    way out of DEGRADED — so a status that measured headroom against the
    compiled-in defaults would print the wrong number on precisely the machine
    where somebody acted on the last one. Every heartbeat carries both.
    """
    limits = dhu_backup_core.DEFAULT_LIMITS
    for field, key in (("max_store_bytes", "max_store_bytes"),
                       ("min_free_bytes", "min_free_bytes")):
        value = state.get(key)
        if isinstance(value, int) and value > 0:
            limits = limits._replace(**{field: value})
    return limits


def _store_status(state):
    store_bytes = state.get("store_bytes")
    if not isinstance(store_bytes, int):
        return None
    limits = _limits_from_state(state)
    headroom = dhu_backup_core.budget_headroom(store_bytes, None, limits)
    return {"bytes": store_bytes, "human": dhu_backup_core.human_bytes(store_bytes),
            "ceiling_bytes": limits.max_store_bytes,
            "ceiling_human": dhu_backup_core.human_bytes(limits.max_store_bytes),
            "headroom_bytes": headroom.store_left,
            "headroom_human": dhu_backup_core.human_bytes(max(0, headroom.store_left))}


def _free_space_status(state):
    free_bytes = state.get("free_bytes")
    if not isinstance(free_bytes, int):
        # None here means the daemon did not measure it this cycle, which it
        # reports on its own path. Never 0: a fabricated "the volume is full"
        # beside a heartbeat showing 30 GB free is a defect this project shipped
        # once already.
        return None
    limits = _limits_from_state(state)
    headroom = dhu_backup_core.budget_headroom(0, free_bytes, limits)
    return {"bytes": free_bytes, "human": dhu_backup_core.human_bytes(free_bytes),
            "floor_bytes": limits.min_free_bytes,
            "floor_human": dhu_backup_core.human_bytes(limits.min_free_bytes),
            "headroom_bytes": headroom.free_left,
            "headroom_human": dhu_backup_core.human_bytes(max(0, headroom.free_left))}


def _warning_status(state, health):
    if health.verdict != "warning":
        return None
    reasons = state.get("warning_reason")
    if not isinstance(reasons, (list, tuple)):
        reasons = [reasons] if reasons else []
    return {"reasons": [str(r) for r in reasons],
            "detail": str(state.get("warning_detail") or health.detail)}


def _glob_status(state, globs_key, refused_key):
    """`{"globs": n, "refused": n}` or None when there are none of either.

    None means "the operator has added no rules of this kind", which is the
    common case and deserves no line at all. Zero globs WITH refusals is not
    that: it means every line the operator wrote was thrown out, which is the
    one case here worth printing.
    """
    globs = state.get(globs_key)
    refused = state.get(refused_key)
    globs = globs if isinstance(globs, int) else 0
    refused = refused if isinstance(refused, int) else 0
    if not globs and not refused:
        return None
    return {"globs": globs, "refused": refused}


def _watch_root_status(install_root, state, budget):
    """The roots in force, each with the count of paths the store holds for it."""
    entries, refusals, error = read_watchlist(install_root)
    ids, store_error = store_root_ids(install_root)
    configured_ids = [root_id for root_id, _pattern in entries]
    counts = held_paths_by_root_id(install_root, configured_ids, budget) if not error else {}

    roots = []
    for root_id, pattern in entries:
        paths, capped, count_error = counts.get(root_id, (None, False, None))
        roots.append({"root_id": root_id, "pattern": pattern,
                      "paths_held": paths, "paths_held_capped": capped,
                      "error": count_error})
    return {
        "error": error,
        "store_error": store_error,
        "configured": roots,
        "refused_lines": [{"line": line, "reason": reason} for line, reason in refusals],
        # The daemon's own expansion of those patterns. A single `--watch
        # worktrees=/…/worktrees/*` line becomes one root per directory, so the
        # count of lines above and the count of roots the daemon holds are
        # different numbers and neither substitutes for the other.
        "expanded": state.get("watch_roots"),
        "expanded_refused": state.get("watch_roots_refused"),
        # Store subtrees whose id no longer appears in the watchlist: history
        # that is KEPT and is no longer being added to. Saying so is the
        # difference between "my old repo is still protected" and the truth.
        "unwatched_root_ids": [i for i in ids if i not in configured_ids],
    }


def format_status(payload):
    """The few lines a human reads at a glance. Never raises."""
    lines = []
    health = payload["health"]
    lines.append("dhu-backup: %s" % health["sentence"])
    lines.append("  daemon       %s (%s)" % (health["verdict"], health["detail"]))

    last = payload.get("last_capture")
    if last:
        lines.append("  last capture %s (%ds ago)" % (last["iso"], last["age_seconds"]))
    else:
        lines.append("  last capture not recorded — the heartbeat names no last_scan_epoch")
    lines.append("  install root %s" % payload["install_root"])

    lines.extend(_format_watch_roots(payload.get("watch_roots")))

    store = payload.get("store")
    if store:
        lines.append("  store        %s of its %s ceiling (%s left)"
                     % (store["human"], store["ceiling_human"], store["headroom_human"]))
    else:
        lines.append("  store        size not reported by the heartbeat")
    free = payload.get("free_space")
    if free:
        lines.append("  free space   %s on this volume; capture stops below %s (%s left)"
                     % (free["human"], free["floor_human"], free["headroom_human"]))
    else:
        lines.append("  free space   not measured this cycle (the daemon reports why itself)")

    warning = payload.get("warning")
    if warning:
        lines.append("  warning      %s" % ", ".join(warning["reasons"]))
        lines.append("               %s" % warning["detail"])

    for label, key in (("exclusions  ", "exclusions"), ("vault extras", "vault_extra")):
        globs = payload.get(key)
        if globs:
            lines.append("  %s %d glob(s) in force, %d refused"
                         % (label, globs["globs"], globs["refused"]))

    step = payload.get("next_step") or {}
    if step.get("command"):
        lines.append("")
        lines.append("  %s" % step["sentence"])
        lines.append("    %s" % step["command"])
    return "\n".join(lines)


def _format_watch_roots(roots):
    if not roots:
        return ["  watch roots  not determined"]
    lines = []
    if roots["error"]:
        # The one answer this must never give is an empty list, which reads as
        # "nothing is watched" — the opposite claim from "I could not look".
        lines.append("  watch roots  COULD NOT BE READ: %s" % roots["error"])
        return lines
    expanded = roots.get("expanded")
    refused = roots.get("expanded_refused")
    suffix = ""
    if isinstance(expanded, int):
        suffix = "; the daemon holds %d expanded root(s), %s refused" % (
            expanded, refused if isinstance(refused, int) else "?")
    lines.append("  watch roots  %d in etc/watchlist.conf%s"
                 % (len(roots["configured"]), suffix))
    for root in roots["configured"]:
        if root["error"]:
            held = "paths held UNKNOWN: %s" % root["error"]
        elif root["paths_held"] is None:
            held = "paths held not counted"
        else:
            held = "%s%s path(s) held" % ("at least " if root["paths_held_capped"] else "",
                                          "{:,}".format(root["paths_held"]))
        lines.append("    %-12s %s" % (root["root_id"], root["pattern"]))
        lines.append("    %-12s %s" % ("", held))
    if roots["configured"]:
        lines.append("               (a count of PATHS, not of versions)")
    for refusal in roots["refused_lines"]:
        lines.append("  !! watchlist line refused (%s): %s"
                     % (refusal["reason"], refusal["line"]))
    if roots["store_error"]:
        lines.append("  !! %s" % roots["store_error"])
    if roots["unwatched_root_ids"]:
        lines.append("  note         the store also holds %d root id(s) the watchlist no "
                     "longer names: %s"
                     % (len(roots["unwatched_root_ids"]),
                        ", ".join(roots["unwatched_root_ids"])))
        lines.append("               their captured versions are KEPT; nothing under them "
                     "is being watched now.")
    return lines


# ── commands ──────────────────────────────────────────────────────────────────


def command_ls(args):
    entries, error = load_entries(args.install_root)
    if error:
        if args.json:
            _emit_json({"error": error, "health": health_object(args.install_root),
                        "matches": [], "store_paths": 0})
            return 2
        print("ERROR %s" % error)
        return 2
    matches = select_entries(entries, args.substring, args.root_id)
    if args.json:
        _emit_json({
            "error": None,
            "health": health_object(args.install_root),
            "substring": args.substring,
            "root_id": args.root_id,
            "store_paths": len(entries),
            "vault_present": vault_is_present(args.install_root),
            "matches": [
                {"relpath": e["relpath"], "root_id": e["root_id"], "slug": e["slug"],
                 "watch_root": e["watch_root"], "tree": e["tree"],
                 "origin": os.path.join(e["watch_root"], e["relpath"]),
                 "versions": len(e["versions"]),
                 "newest_epoch_ns": e["versions"][-1]["epoch_ns"],
                 "newest_iso": _iso(e["versions"][-1]["epoch_ns"])}
                for e in matches
            ],
        })
        return 0 if matches else 1
    if not matches:
        print("no readable versions match %r (store holds %d path(s))"
              % (args.substring, len(entries)))
        if vault_is_present(args.install_root):
            # Never let "vaulted" look like "not captured".
            print("note: credential-class paths (.env*, keys, .ssh/…) are held in the "
                  "root-only vault and are not listed here — recover one with sudo:")
            # This block previously printed `sudo ... dhu-backup restore <path>`,
            # which did not work twice over: `load_entries` read `store/` only so
            # nothing in the vault was ever found, and a root-written restore
            # would have left the origin root-owned and therefore unprotected.
            # `cat` with the SHELL's redirect creates the file as the invoking
            # user, which is the whole point of the shape.
            print("      sudo DHU_BACKUP_ALLOW_ROOT=1 %s/bin/dhu-backup log <path>"
                  % args.install_root)
            print("      sudo DHU_BACKUP_ALLOW_ROOT=1 %s/bin/dhu-backup cat <path> > <origin>"
                  % args.install_root)
        return 1
    for entry in matches:
        newest = entry["versions"][-1]
        print("%s  [%s]  %d version(s), newest %s%s"
              % (entry["relpath"], entry["root_id"], len(entry["versions"]),
                 _iso(newest["epoch_ns"]), _tree_tag(entry)))
    return 0


def command_log(args):
    if args.json:
        entry, code, failure = _select_one(args, args.path)
        payload = {"health": health_object(args.install_root), "path": args.path}
        if failure is not None:
            payload.update(failure)
            payload["versions"] = []
        else:
            payload.update({
                "error": None, "kind": "ok",
                "relpath": entry["relpath"], "root_id": entry["root_id"],
                "slug": entry["slug"], "watch_root": entry["watch_root"],
                "tree": entry["tree"],
                "origin": os.path.join(entry["watch_root"], entry["relpath"]),
                "versions": [
                    {"key": v["key"], "epoch_ns": v["epoch_ns"], "iso": _iso(v["epoch_ns"]),
                     "size": v["size"], "sha": v["sha"], "store_path": v["path"]}
                    for v in entry["versions"]
                ],
            })
        _emit_json(payload)
        return code
    entry, code = _one_entry(args, args.path)
    if entry is None:
        return code
    print("%s  [%s]%s" % (entry["relpath"], entry["root_id"], _tree_tag(entry)))
    print("  origin: %s" % os.path.join(entry["watch_root"], entry["relpath"]))
    for version in entry["versions"]:
        print("  %s  %8d bytes  %s  %s"
              % (_iso(version["epoch_ns"]), version["size"], version["sha"], version["path"]))
    return 0


def command_cat(args):
    entry, code = _one_entry(args, args.path)
    if entry is None:
        return code
    version, code = _pick_version(entry, args)
    if version is None:
        return code
    with open(version["path"], "rb") as handle:
        payload = handle.read()
    try:
        sys.stdout.write(payload.decode("utf-8"))
    except UnicodeDecodeError:
        sys.stdout.buffer.write(payload)
    return 0


def command_restore(args):
    if _refuse_restore_as_root():
        return 2
    entry, code = _one_entry(args, args.path)
    if entry is None:
        return code
    version, code = _pick_version(entry, args)
    if version is None:
        return code
    return _restore_one(entry, version, args)


def command_restore_dir(args):
    """The incident's actual shape: a deleted directory back in one command."""
    if _refuse_restore_as_root():
        return 2
    entries, error = load_entries(args.install_root)
    if error:
        print("ERROR %s" % error)
        return 2
    prefix = args.directory.strip("/")
    matches = [
        e for e in entries
        if (not args.root_id or e["root_id"] == args.root_id)
        and (e["relpath"] == prefix or e["relpath"].startswith(prefix + "/"))
    ]
    if not matches:
        print("ERROR no readable versions under %r" % args.directory)
        return 1
    at_epoch = _asof_epoch(args)
    if at_epoch is None and args.asof:
        return 2

    restored = skipped = failed = 0
    for entry in matches:
        if at_epoch is None:
            version = entry["versions"][-1]
        else:
            version = dhu_backup_core.resolve_asof(entry["versions"], int(at_epoch * 1_000_000_000))
        if version is None:
            # A file that did not exist yet at that time is not an error, and it
            # is not a silent omission either.
            print("skip %s — no version at or before %s" % (entry["relpath"], args.asof))
            skipped += 1
            continue
        code = _restore_one(entry, version, args)
        if code == 0:
            restored += 1
        else:
            failed += 1
    print("restore-dir: %d restored, %d skipped, %d failed (of %d path(s))"
          % (restored, skipped, failed, len(matches)))
    return 0 if failed == 0 else 1


def _vault_commands(args, needle):
    """The two commands that actually recover a vaulted path.

    Built through the same pure `recovery_commands` the announce path uses, so
    the CLI hint and the Property 4 answer cannot drift into two different
    pieces of advice. `needle` here is a substring rather than a located path,
    so the root-id is left off and the caller narrows it if it is ambiguous.
    """
    located = dhu_backup_core.Located(root_id=None, slug=None, watch_root="",
                                      relpath=needle.strip("/"))
    return dhu_backup_core.recovery_commands("vaulted", args.install_root, located)


def _refuse_restore_as_root():
    """`restore` and `restore-dir` never run as root, opt-in or not."""
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    verdict = dhu_backup_core.restore_permitted(euid)
    if isinstance(verdict, Refuse):
        print("ERROR %s" % verdict.reason)
        return True
    return False


def command_missing(args):
    """Property 4 from the CLI: what does the store hold for a path that is GONE?

    Takes an ABSOLUTE path — the one whose read just failed — rather than the
    substring the other subcommands take, because the caller here is an error
    handler that has an exact path and no idea what the store calls it. The
    mapping from that path to a store key is the whole job.
    """
    result = dhu_backup_announce.announce(args.path, install_root=args.install_root)
    if args.json:
        _emit_json(dhu_backup_announce.to_json(result))
    else:
        print(dhu_backup_announce.format_text(result))
    return dhu_backup_core.announce_exit_code(result.status)


def command_status(args):
    """"Is this working?" — the everyday question, answered without sudo.

    Exit code is the daemon's health, not this command's success: 0 capturing,
    1 not capturing, 2 could not determine. `status` itself succeeding while
    capture has stopped is the report nobody should be able to write a green
    monitor against.
    """
    payload = status_payload(args.install_root)
    if args.json:
        _emit_json(payload)
    else:
        print(format_status(payload))
    return payload["exit_code"]


def _restore_one(entry, version, args):
    verdict = dhu_backup_core.restore_target(entry["relpath"], entry["watch_root"], args.into)
    if isinstance(verdict, Refuse):
        print("ERROR refusing to restore %s: %s" % (entry["relpath"], verdict.reason))
        return 2
    assert isinstance(verdict, Target)
    destination = verdict.path

    with open(version["path"], "rb") as handle:
        payload = handle.read()

    if os.path.lexists(destination) and not args.overwrite:
        existing = _read_bytes(destination)
        if existing == payload:
            print("unchanged %s — the file already holds this version" % destination)
            return 0
        # Never silently clobber, and never silently refuse either: write beside
        # it and say exactly what happened.
        beside = "%s.restored-%s" % (destination, version["key"].lstrip("@"))
        _write(beside, payload)
        print("EXISTS %s differs — wrote %s instead. Re-run with --overwrite to replace it."
              % (destination, beside))
        _log_restore(entry, version, beside, "beside")
        return 1

    parent = os.path.dirname(destination)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, 0o755)
    _write(destination, payload)
    print("restored %s (%d bytes, captured %s) -> %s"
          % (entry["relpath"], len(payload), _iso(version["epoch_ns"]), destination))
    _log_restore(entry, version, destination, "in-place")
    return 0


def _write(path, payload):
    temp = "%s.dhu-backup-restore.%d" % (path, os.getpid())
    with open(temp, "wb") as handle:
        handle.write(payload)
    os.replace(temp, path)


def _read_bytes(path):
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except IOError:
        return None


def _log_restore(entry, version, destination, mode):
    """A courtesy trail for the owner — explicitly NOT tamper-evident.

    The helper is unprivileged, so it cannot write the root-owned daemon log.
    This file is agent-writable and therefore advisory only; the daemon's own
    capture record is the authoritative one. Saying so here is the point.
    """
    line = "%s\t%s\t%s\t%s\t%s\t%s\n" % (
        time.strftime("%Y-%m-%dT%H:%M:%S"), mode, entry["root_id"],
        entry["relpath"], version["key"], destination,
    )
    try:
        with open(RESTORE_LOG, "a") as handle:
            handle.write(line)
    except IOError as exc:
        print("note: could not append to %s (%s) — the restore itself succeeded"
              % (RESTORE_LOG, exc))


def _select_one(args, needle):
    """`(entry, code, failure)` — the selection, with no output of its own.

    Split out of `_one_entry` so `--json` reports the SAME outcomes as the text
    path instead of a second implementation that could drift from it. `failure`
    is a dict when there is no single entry, and it is what `--json` emits.
    """
    entries, error = load_entries(args.install_root)
    if error:
        return None, 2, {"error": error, "kind": "store-unavailable"}
    matches = select_entries(entries, needle, args.root_id)
    if not matches:
        failure = {"error": "no readable versions match %r" % needle,
                   "kind": "no-match", "candidates": []}
        extra_globs, _ = dhu_backup_announce.read_vault_extra(args.install_root)
        if vault_is_present(args.install_root) and dhu_backup_core.is_credential_class(
                needle, extra_globs):
            failure["kind"] = "vaulted"
            failure["note"] = ("%r looks credential-class, so it is held in the "
                               "root-only vault, not the readable store." % needle)
            failure["commands"] = list(_vault_commands(args, needle))
        return None, 1, failure
    if len(matches) > 1:
        exact = [e for e in matches if e["relpath"] == needle.strip("/")]
        if len(exact) == 1:
            return exact[0], 0, None
        return None, 1, {
            "error": "%r matches %d paths; narrow it" % (needle, len(matches)),
            "kind": "ambiguous",
            "candidates": [{"relpath": e["relpath"], "root_id": e["root_id"]}
                           for e in matches[:20]],
        }
    return matches[0], 0, None


def _one_entry(args, needle):
    entry, code, failure = _select_one(args, needle)
    if failure is None:
        return entry, code
    if failure["kind"] == "store-unavailable":
        print("ERROR %s" % failure["error"])
        return None, 2
    if failure["kind"] == "ambiguous":
        print("ERROR %s:" % failure["error"])
        for candidate in failure["candidates"]:
            print("    %s  [%s]" % (candidate["relpath"], candidate["root_id"]))
        return None, 1
    print("ERROR %s" % failure["error"])
    if failure["kind"] == "vaulted":
        print("note: %r looks credential-class, so it is held in the root-only "
              "vault, not the readable store. Recover it with:" % needle)
        for command in failure["commands"]:
            print("      %s" % command)
    return None, 1


def _asof_epoch(args):
    if not args.asof:
        return None
    epoch = dhu_backup_core.parse_asof(args.asof, time.time())
    if epoch is None:
        print("ERROR --asof must be an ISO timestamp or a relative age like 20m / 2h / 3d")
    return epoch


def _pick_version(entry, args):
    if getattr(args, "version", None):
        wanted = args.version if args.version.startswith("@") else "@" + args.version
        for version in entry["versions"]:
            if version["key"] == wanted:
                return version, 0
        print("ERROR no version %s of %s" % (wanted, entry["relpath"]))
        return None, 1
    if args.asof:
        epoch = _asof_epoch(args)
        if epoch is None:
            return None, 2
        version = dhu_backup_core.resolve_asof(entry["versions"], int(epoch * 1_000_000_000))
        if version is None:
            # Never fall back to the newest: answering "what did this look like
            # an hour ago" with the current contents is worse than saying nothing.
            print("ERROR no version of %s at or before %s (earliest is %s)"
                  % (entry["relpath"], args.asof, _iso(entry["versions"][0]["epoch_ns"])))
            return None, 1
        return version, 0
    return entry["versions"][-1], 0


def refuse_root():
    """This tool must never run with privilege — except for a vault READ.

    Its safety argument is that it holds no privilege the agent lacks. Running
    it under sudo would make `--into` an arbitrary ROOT write. The one
    legitimate privileged use is READING a vaulted credential file, which is
    the owner's to do deliberately, so that is opted into rather than assumed:
    `DHU_BACKUP_ALLOW_ROOT=1` gets past this check AND is what makes
    `load_entries` walk `vault/` at all (`trees_to_read`).

    It does NOT unlock `restore`. `restore_permitted` refuses root outright,
    because a file written back by root is root-owned at the origin, which the
    daemon then refuses as `wrong-owner-uid` — the recovery would silently
    un-protect the file it recovered, and the agent could not edit it either.
    The supported shape is `sudo DHU_BACKUP_ALLOW_ROOT=1 dhu-backup cat <path>
    > <origin>`, where the SHELL's redirect makes the new file the user's.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not os.environ.get("DHU_BACKUP_ALLOW_ROOT"):
        print("ERROR dhu-backup must not run as root. The store is world-readable by design, so "
              "recovery needs no sudo.\n"
              "       To READ a VAULTED credential file deliberately, re-run with "
              "DHU_BACKUP_ALLOW_ROOT=1 (`log` and `cat` only; `restore` refuses root\n"
              "       so the recovered file does not end up root-owned and unprotected).")
        return True
    return False


def main(argv=None):
    if refuse_root():
        return 2
    parser = argparse.ArgumentParser(prog="dhu-backup", description="DHU Backup recovery")
    parser.add_argument("--install-root", default=DEFAULT_INSTALL_ROOT)
    parser.add_argument("--root-id", default=None, help="limit to one watch-root id")
    parser.add_argument("--quiet", action="store_true", help="suppress the health banner")
    subparsers = parser.add_subparsers(dest="command")

    status = subparsers.add_parser(
        "status", help="is this working? the health verdict, the roots, the budgets")
    status.add_argument("--json", action="store_true", help="machine-readable output")

    lister = subparsers.add_parser("ls", help="which protected paths have versions")
    lister.add_argument("substring", nargs="?", default=None)
    lister.add_argument("--json", action="store_true", help="machine-readable output")

    logger_cmd = subparsers.add_parser("log", help="versions of one path")
    logger_cmd.add_argument("path")
    logger_cmd.add_argument("--json", action="store_true", help="machine-readable output")

    cat = subparsers.add_parser("cat", help="print one version to stdout")
    cat.add_argument("path")
    cat.add_argument("--asof", default=None)
    cat.add_argument("--version", default=None)

    restore = subparsers.add_parser("restore", help="restore one file")
    restore.add_argument("path")
    restore.add_argument("--asof", default=None)
    restore.add_argument("--version", default=None)
    restore.add_argument("--into", default=None, help="restore under this directory instead")
    restore.add_argument("--overwrite", action="store_true")

    restore_dir = subparsers.add_parser("restore-dir", help="restore a directory as of a time")
    restore_dir.add_argument("directory")
    restore_dir.add_argument("--asof", default=None)
    restore_dir.add_argument("--into", default=None)
    restore_dir.add_argument("--overwrite", action="store_true")

    missing = subparsers.add_parser(
        "missing", help="what the store holds for an ABSOLUTE path that is gone")
    missing.add_argument("path")
    missing.add_argument("--json", action="store_true", help="machine-readable output")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    # The banner is a LINE OF PROSE. Printing it ahead of a JSON object would
    # make every `--json` answer unparseable, so callers would pass `--quiet`
    # and stop seeing health at all. In JSON mode the same verdict is a `health`
    # FIELD of the object instead — carried, never dropped.
    if (not args.quiet and not getattr(args, "json", False)
            and args.command not in ("missing", "status")):
        # `missing` and `status` state the health themselves, in the same block
        # as their answer. Printing the banner as well said it twice in
        # different words, which reads as two findings rather than one.
        print_health_banner(args.install_root)
    return {
        "status": command_status,
        "ls": command_ls,
        "log": command_log,
        "cat": command_cat,
        "restore": command_restore,
        "restore-dir": command_restore_dir,
        "missing": command_missing,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
