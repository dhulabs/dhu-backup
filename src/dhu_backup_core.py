"""DHU Backup — pure decision functions.

Everything in this module is a PURE FUNCTION over plain values. No filesystem
access, no repo dependency, and no import outside the standard library except
`credential_patterns`, its sibling in the same root-owned directory, which is
itself data. The daemon (`dhu-backupd.py`) and the restore helper
(`dhu-backup.py`) import it; the unit tests exercise it directly with fabricated
inputs.

The split exists for one reason: this repo does not fire a destructive sink to
prove its guard. `prune_plan` therefore RETURNS a plan and never deletes;
the executor that unlinks lives in `dhu-backupd.py` and is never called by a test.

Python 3.9 stdlib only — `/usr/bin/python3` is the one interpreter on this
machine that is root-owned, and a root daemon must execute nothing an agent can
replace (review H2/H3).
"""

import fnmatch
import hashlib
import os
import re
import stat as stat_mod
import sys
import time
from collections import namedtuple

# The credential predicate's patterns, as data. Installed beside this file as
# `bin/credential_patterns.py` (0644 root:wheel), so the daemon still executes
# only root-owned bytes; every caller already puts that directory on sys.path.
import credential_patterns  # noqa: E402

# ── Budgets (review C10; overridable from the root-owned config) ──────────────

MAX_FILE_BYTES = 1 * 1024 * 1024            # 1 MiB
MAX_STORE_BYTES = 5 * 1024 * 1024 * 1024    # 5 GiB
MAX_VERSIONS_PER_PATH = 200
MAX_NEW_FILES_PER_SCAN = 2000
MIN_FREE_BYTES = 10 * 1024 * 1024 * 1024    # 10 GiB
MAX_WATCH_ROOTS = 64

DEFAULT_INTERVAL_SECONDS = 15
DEFAULT_RETENTION_DAYS = 30
DEFAULT_PRUNE_INTERVAL_SECONDS = 3600

Limits = namedtuple(
    "Limits",
    "max_file_bytes max_store_bytes max_versions_per_path "
    "max_new_files_per_scan min_free_bytes max_watch_roots",
)

DEFAULT_LIMITS = Limits(
    max_file_bytes=MAX_FILE_BYTES,
    max_store_bytes=MAX_STORE_BYTES,
    max_versions_per_path=MAX_VERSIONS_PER_PATH,
    max_new_files_per_scan=MAX_NEW_FILES_PER_SCAN,
    min_free_bytes=MIN_FREE_BYTES,
    max_watch_roots=MAX_WATCH_ROOTS,
)

# ── Verdict types ─────────────────────────────────────────────────────────────
#
# A verdict is one of two shapes and nothing else. `budget_decision` in
# particular has NO "prune young versions to make room" case: the type cannot
# express the behaviour review C11 forbids, so no reviewer has to check that the
# code avoids it.

Copy = namedtuple("Copy", "relpath size")
Refuse = namedtuple("Refuse", "reason")
Allow = namedtuple("Allow", "")
Degraded = namedtuple("Degraded", "reason")
Skip = namedtuple("Skip", "reason")
Target = namedtuple("Target", "path")


def is_refusal(verdict):
    """True for every negative verdict shape this module produces."""
    return isinstance(verdict, (Refuse, Degraded, Skip))


# ── Exclusions (review H5; static, never git-derived) ─────────────────────────
#
# Running `git` as root inside an agent-writable repo executes agent-controllable
# hooks and `core.fsmonitor`, so the exclusion list is a literal.

EXCLUDED_DIR_NAMES = frozenset(
    [
        "node_modules",
        ".git",
        ".next",
        "dist",
        "build",
        "out",
        "coverage",
        ".cache",
        ".venv",
        "venv",
        "__pycache__",
        ".turbo",
        ".pytest_cache",
        ".playwright-mcp",
    ]
)

# `deploy/` as a whole is NOT excluded — source often lives under it — so only
# the multi-gigabyte payload directories beneath it are dropped. Those
# position-relative rules live in `is_excluded_dir` below.

EXCLUDED_EXTENSIONS = frozenset(
    [
        ".gguf",
        ".safetensors",
        ".bin",
        ".pt",
        ".ckpt",
        ".zip",
        ".tar",
        ".tgz",
        ".gz",
        ".dmg",
        ".mp4",
        ".mov",
        ".wav",
        ".png",
        ".jpg",
        ".jpeg",
        ".log",
    ]
)


def is_excluded_dir(name, relpath):
    """Should the walk refuse to DESCEND into this directory?

    `relpath` is the directory's path relative to its watch root. Checked before
    descending, so a multi-gigabyte artifact tree costs one `scandir` entry
    rather than a walk (review H5).

    Every rule is POSITION-RELATIVE, matched on the tail of the relpath rather
    than anchored at the watch root. The first version anchored `lib/generated`
    and `deploy/*/bundles` at the root, so under the repo root a worktree's copy
    of those directories — `.claude/worktrees/agent-x/lib/generated/…` — matched
    nothing and was mirrored (found by the adversarial review, in the real scan log).
    """
    if name in EXCLUDED_DIR_NAMES:
        return True
    segments = [s for s in relpath.strip("/").split("/") if s] if relpath else []
    if not segments:
        return False

    # `lib/generated`, wherever it sits.
    if len(segments) >= 2 and segments[-2:] == ["lib", "generated"]:
        return True
    # `bundles` anywhere below a `deploy` segment — deployment payloads.
    # A fixed three-segment tail (`deploy/<x>/bundles`) narrowed the original
    # rule without saying so: a deeper `deploy/<x>/<y>/bundles` was excluded
    # before and would not have been (round-2 review, M8).
    if name == "bundles" and "deploy" in segments[:-1]:
        return True
    # `.claude/worktrees` — agent worktrees have their OWN watch root, so
    # walking them from the repo root as well stored every worktree file twice,
    # under two different store keys, against the same budgets (adversarial review).
    # This is only safe because the shipped watchlist globs `worktrees/*`, i.e.
    # EVERY child. It once globbed `agent-*`, and this exclusion then silently
    # removed all protection from a worktree named anything else (round 2, I3).
    if len(segments) >= 2 and segments[-2:] == [".claude", "worktrees"]:
        return True
    return False


# ── The credential predicate (amendment A2) ───────────────────────────────────
#
# C4 (the store laundering `.env.local` past the basename guards) is closed at
# ADMISSION, not at read time: a credential file never enters the store, so no
# reader guard is load-bearing and the store can stay agent-readable (A1).
#
# THE PATTERNS ARE NOT HERE. They live in `credential_patterns.py`, one
# declarative table where every rule carries its own rationale and its own
# worked examples, and this file holds only the matcher that reads it. The
# population that proves the pair is DERIVED from those patterns:
#
#   tests/credential_fixture_own.json   every rule's own regex expanded into
#                                       every string it can match, probed in
#                                       four shapes, by
#                                       src/tools/derive-own-fixture.py.
#
# The predicate is STRICTER than the basename read guard it was ported from in
# exactly two named places, both of which the companion sandbox profile already
# covered — `.env` as a DIRECTORY segment, and `~/.config/<vendor>/` at any depth
# rather than only as the immediate parent. Both were found by the adversarial
# review, which put both shapes in a live store.
#
# It is NAME-BASED, and deliberately stays that way. See src/README.md: the
# daemon must never read a file's CONTENT to decide where it goes, because a
# content heuristic that guesses "not a secret" puts the file in the
# agent-readable half, and that is exactly the C4 laundering.

CredentialMatch = namedtuple("CredentialMatch", "rule reason")


def _credential_match(rule, matched_text):
    """Build the match, with the reason string this rule's kind produces.

    A missing template is a KeyError, not a default string: a new rule kind that
    nobody wrote a reason for must break loudly here rather than be reported to
    the operator as an empty explanation.
    """
    template = credential_patterns.REASON_TEMPLATES[(rule.kind, rule.where)]
    return CredentialMatch(rule, template % matched_text)


def credential_match(relpath):
    """The FIRST rule that refuses `relpath`, with its reason, or `None`.

    Evaluation order is the order of the phases below, and it decides only WHICH
    rule is reported, never whether the path is refused. Path tails run before
    the basename rules on purpose: under the original order `.git/credentials`
    was claimed by `^credentials$` first, so the `.git/credentials` tail rule
    could never fire and no test could tell it apart from a live one.
    """
    if relpath is None:
        return None
    segments = [s for s in str(relpath).replace(os.sep, "/").split("/") if s]
    if not segments:
        return None
    name = segments[-1]
    last_index = len(segments) - 1

    for index, segment in enumerate(segments):
        for rule in credential_patterns.DIR_SEGMENT_ANY:
            if rule.regex.search(segment):
                return _credential_match(rule, segment)
        if index < last_index:
            for rule in credential_patterns.DIR_SEGMENT_NON_FINAL:
                if rule.regex.search(segment):
                    return _credential_match(rule, segment)
        if index > 0 and segments[index - 1] == ".config":
            for rule in credential_patterns.CONFIG_DIR:
                if rule.regex.search(segment):
                    return _credential_match(rule, segment)

    tail = "/".join(segments[-2:])
    for rule in credential_patterns.PATH_TAIL:
        if rule.regex.search(tail):
            return _credential_match(rule, tail)

    # Key material is matched on the basename AND on the basename with a
    # template suffix stripped: a private key does not become safe because
    # someone appended `.example` to it.
    stem = credential_patterns.TEMPLATE_SUFFIX.sub("", name)
    for rule in credential_patterns.KEY_MATERIAL:
        if rule.regex.search(name) or rule.regex.search(stem):
            return _credential_match(rule, name)

    if not credential_patterns.TEMPLATE_SUFFIX.search(name):
        for rule in credential_patterns.TEMPLATABLE:
            if rule.regex.search(name):
                return _credential_match(rule, name)

    # `~/.config/<vendor>/` reached with the vendor as the immediate PARENT and
    # `.config` further up — the shape the segment loop above does not cover.
    if ".config" in segments and len(segments) >= 2:
        parent = segments[-2]
        for rule in credential_patterns.CONFIG_DIR:
            if rule.regex.search(parent):
                return _credential_match(rule, parent)

    return None


def is_credential_path(relpath):
    """Why this path is credential-bearing, or None if it is not.

    THE BASE PREDICATE: patterns only, no operator extension. Applied to the
    ORIGINAL relpath at admission time (never to the store key), so the store
    never holds a file the read guards this was ported from would refuse.
    """
    if relpath is None:
        return "path is missing"
    match = credential_match(relpath)
    return match.reason if match is not None else None


# ── The operator's additive extension (etc/vault-extra.conf) ──────────────────
#
# One basename glob per line, `#` comments. It can ONLY ADD refusals. That is
# not a convention, it is the type: `destination_for` ORs the extension into the
# base predicate, so there is no value of this file that makes a path readable
# which the base predicate refuses. A "readable" direction would be a way for
# anyone who can write root-owned etc/ to un-vault a secret, and the whole point
# of the split store is that nothing can do that.
#
# A line with `/` in it is REFUSED rather than reinterpreted: a path-shaped
# entry would look like it constrained a directory and would silently constrain
# nothing, which is the failure mode this project keeps finding.

VAULT_EXTRA_FILENAME = "vault-extra.conf"
MAX_VAULT_EXTRA_GLOBS = 256


def parse_vault_extra(text):
    """Parse etc/vault-extra.conf into `(globs, refusals)`.

    Refusals are `(line, reason)`, the same shape `parse_watchlist` uses, and
    the caller must report them. A malformed line is never dropped silently: an
    operator who believes a glob is in force and is wrong has a false sense of
    protection, which is worse than no extension at all.
    """
    globs = []
    refusals = []
    for raw in str(text).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\x00" in line:
            refusals.append((line.replace("\x00", "<NUL>"), "nul-byte"))
            continue
        if "/" in line:
            refusals.append((line, "glob-matches-the-basename-only"))
            continue
        if ".." in line:
            refusals.append((line, "path-traversal-in-a-basename-glob"))
            continue
        if len(globs) >= MAX_VAULT_EXTRA_GLOBS:
            refusals.append((line, "too-many-globs"))
            continue
        globs.append(line)
    return tuple(globs), tuple(refusals)


def extra_glob_match(relpath, extra_globs=()):
    """The first operator glob that vaults this path, or None.

    `fnmatch` on the BASENAME only, case-insensitively. Case-insensitive because
    macOS filesystems are, and because every error this direction makes is a
    file vaulted that need not have been — the recoverable one.
    """
    if not extra_globs or relpath is None:
        return None
    segments = [s for s in str(relpath).replace(os.sep, "/").split("/") if s]
    if not segments:
        return None
    name = segments[-1].lower()
    for glob in extra_globs:
        if fnmatch.fnmatchcase(name, glob.lower()):
            return glob
    return None


def vault_reason(relpath, extra_globs=()):
    """Why this path belongs in `vault/`, or None — base predicate OR extension."""
    reason = is_credential_path(relpath)
    if reason is not None:
        return reason
    glob = extra_glob_match(relpath, extra_globs)
    if glob is None:
        return None
    name = [s for s in str(relpath).replace(os.sep, "/").split("/") if s][-1]
    return '"%s" matches the operator vault glob %s' % (name, glob)


def is_credential_class(relpath, extra_globs=()):
    """Does this path belong in the root-only `vault/` rather than `store/`?

    The split (review C4b) is what lets `store/` be agent-readable at all: it
    holds only files the repo's own guards would let an agent read anyway. A
    credential-class file is still CAPTURED — the owner can recover a deleted
    `.env.local` with sudo — it just never becomes agent-readable.

    Fail direction matters and is deliberate: a work file wrongly vaulted costs
    the owner one `sudo`; a secret wrongly placed in `store/` is unrecoverable.
    """
    return vault_reason(relpath, extra_globs) is not None


STORE_TREE = "store"
VAULT_TREE = "vault"


def destination_for(relpath, extra_globs=()):
    """`"vault"` or `"store"` for one original relpath. Evaluated at copy time."""
    return VAULT_TREE if is_credential_class(relpath, extra_globs) else STORE_TREE


# ── Path safety (review C9) ───────────────────────────────────────────────────


def is_safe_relpath(relpath):
    """A relative path that can be re-joined to a root without escaping it.

    Checked at WRITE time (so a bad key never enters the store) and again at
    READ time in the restore helper.
    """
    if not isinstance(relpath, str) or relpath == "":
        return False
    if "\x00" in relpath:
        return False
    normalized = relpath.replace(os.sep, "/")
    if normalized.startswith("/"):
        return False
    # A Windows-style drive or UNC prefix is absolute too.
    if re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("\\\\"):
        return False
    parts = normalized.split("/")
    if any(p == ".." for p in parts):
        return False
    return True


def root_slug(root_id, watch_root):
    """The store's second path level: which EXPANDED root this came from.

    Review §4.2's layout is `<store>/<root-id>/<relpath-dir>/…`, which collides:
    the shipped `worktrees` id globs to many directories, and two worktrees both
    holding `lib/x.ts` would share one version history. The expanded root's
    basename disambiguates them and stays readable; the absolute path lives in a
    manifest under `var/roots/`, outside the mirrored tree so no relpath can
    collide with it.
    """
    base = os.path.basename(watch_root.rstrip("/")) or "root"
    safe = re.sub(r"[^A-Za-z0-9_.@+-]", "_", base)[:64]
    # Two different absolute roots can share a basename (two checkouts of the
    # same repo name). An 8-hex tail of the full path makes the level unique
    # without making it unreadable.
    digest = hashlib.sha256(watch_root.encode("utf-8", "surrogateescape")).hexdigest()[:8]
    return "%s-%s" % (safe, digest)


def root_manifest_name(root_id, watch_root):
    """Filename under `var/roots/` recording one expanded root's absolute path."""
    key = "%s\x00%s" % (root_id, watch_root)
    return hashlib.sha256(key.encode("utf-8", "surrogateescape")).hexdigest() + ".json"


VERSION_PREFIX = "@"
VERSION_HASH_CHARS = 12


def version_key(capture_epoch_ns, content_sha256):
    """The version DIRECTORY name for one captured copy.

    Note the signature: **the source file's mtime is not a parameter.** That is
    the proof of C12, not a comment about it. `touch -t 197001020304 f`
    backdates a file 20,000 days in one command, so a version tag or a retention
    decision derived from source mtime is an agent-driven delete into the
    mirror. `capture_epoch_ns` is the daemon's own clock at copy time; source
    mtime is change-detection input and never authority over a deletion.
    """
    return "%s%019d-%s" % (VERSION_PREFIX, int(capture_epoch_ns),
                           content_sha256[:VERSION_HASH_CHARS])


def parse_version_key(name):
    """(capture_epoch_ns, sha_prefix) for a version directory, or None."""
    match = re.match(
        r"^%s(\d{1,25})-([0-9a-f]{%d})$" % (re.escape(VERSION_PREFIX), VERSION_HASH_CHARS),
        name,
    )
    if not match:
        return None
    return (int(match.group(1)), match.group(2))


def path_subpath(root_id, slug, relpath):
    """`<root-id>/<slug>/<relpath-dir>` — the directory holding a path's versions."""
    if not is_safe_relpath(relpath):
        raise ValueError("unsafe relpath: %r" % (relpath,))
    parts = [p for p in relpath.split("/") if p]
    return "/".join([root_id, slug] + parts[:-1])


def version_subpath(root_id, slug, relpath, key):
    """`<root-id>/<slug>/<relpath-dir>/@<capture>-<hash>/<ORIGINAL BASENAME>`.

    The version is a DIRECTORY and the original basename is the LEAF, so every
    existing name-based guard — a basename read guard, a sandbox profile's
    read denies — works on a mirror path unchanged, with no new denylist to maintain. The
    draft's layout put the source filename in a directory segment and a hash in
    the basename, and the real guard returned null for a mirrored `.env.local`
    and `id_rsa`.
    """
    if not is_safe_relpath(relpath):
        raise ValueError("unsafe relpath: %r" % (relpath,))
    parts = [p for p in relpath.split("/") if p]
    return "/".join([path_subpath(root_id, slug, relpath), key, parts[-1]])


# ── Admission (review C6/C7, amendment A2/A6) ─────────────────────────────────


def classify_entry(name, st, relpath, limits=DEFAULT_LIMITS, owner_uid=None):
    """Copy(...) or Refuse(reason) for one directory entry.

    `st` is any object with `st_mode`, `st_nlink`, `st_uid`, `st_size` — an
    `os.stat_result` from `os.fstat` in production, a fabricated tuple in tests.
    The daemon must fstat the OPEN FD, never the path (C8).

    Every refusal carries a reason; the caller counts it by reason and logs it.
    A refusal is never silently equivalent to "nothing there".
    """
    if not is_safe_relpath(relpath):
        return Refuse("unsafe-relpath")

    mode = st.st_mode
    if stat_mod.S_ISLNK(mode):
        return Refuse("symlink")
    if not stat_mod.S_ISREG(mode):
        return Refuse("not-regular-file")
    if st.st_nlink != 1:
        # A hard link in a source tree is anomalous, and a root reader that
        # follows one is a file-disclosure oracle: `ln /etc/sudoers ./notes.md`
        # succeeds as an unprivileged user (verified). Refusing a rare
        # legitimate hard link is the right trade.
        return Refuse("hardlink-nlink=%d" % st.st_nlink)
    if owner_uid is not None and st.st_uid != owner_uid:
        return Refuse("wrong-owner-uid=%d" % st.st_uid)
    if mode & (stat_mod.S_ISUID | stat_mod.S_ISGID):
        return Refuse("setuid-or-setgid")
    if st.st_size > limits.max_file_bytes:
        return Refuse("too-large=%d" % st.st_size)

    # A credential-class file is NOT refused here. It is captured into the
    # root-only `vault/` instead (see `destination_for`), so a deleted
    # `.env.local` is still recoverable by the owner with sudo while never being
    # agent-readable. Refusing it outright — the first build's behaviour — chose
    # "the agent cannot read it" by making it unrecoverable for anyone.

    segments = relpath.split("/")
    for index, segment in enumerate(segments[:-1]):
        if is_excluded_dir(segment, "/".join(segments[: index + 1])):
            return Refuse("excluded-dir:%s" % segment)

    lowered = name.lower()
    for extension in EXCLUDED_EXTENSIONS:
        if lowered.endswith(extension):
            return Refuse("excluded-extension:%s" % extension)

    return Copy(relpath=relpath, size=st.st_size)


# ── Budgets (review C10/C11) ──────────────────────────────────────────────────


def budget_decision(store_bytes, free_bytes, incoming_bytes, limits=DEFAULT_LIMITS):
    """Allow() or Degraded(reason) — the STORE-WIDE gate.

    Only two conditions belong here, and both mean the store as a whole can no
    longer grow safely: the store ceiling and the volume's free-space floor.

    There is deliberately no third case. "Store full, prune the oldest to make
    room" silently converts a 30-day guarantee into a best-effort cache whose
    only symptom is a file that is not there when you need it (review C11), so
    the return type cannot express it.
    """
    if store_bytes + incoming_bytes > limits.max_store_bytes:
        return Degraded("store-ceiling")
    if free_bytes - incoming_bytes < limits.min_free_bytes:
        return Degraded("free-space-floor")
    return Allow()


def entry_budget_decision(incoming_bytes, new_files_this_scan, limits=DEFAULT_LIMITS):
    """Allow() or Skip(reason) — the PER-ENTRY gate. Never degrades the daemon.

    Written as a separate function returning a separate type after building the
    daemon against review §4.3 as literally written ("on any limit: DEGRADED").
    That is wrong for these limits, and wrong in the direction that matters:
    `MAX_NEW_FILES_PER_SCAN` (2,000) is tripped by the FIRST scan of this repo,
    so a correct daemon would degrade itself on startup before any adversary
    appeared. It is a throttle — the excess is counted and picked up next scan.
    `MAX_FILE_BYTES` is one oversized file, not a store failure.

    **`MAX_VERSIONS_PER_PATH` is deliberately NOT here any more.** As a skip it
    inverted the guarantee for exactly the file the incident lost: at a 15 s
    interval an actively edited file reaches 200 versions in under an hour, and
    from that moment its NEWEST content was the one thing not in the store. The
    cap is now a ROLLING WINDOW (`version_window_plan`) — the daemon prunes that
    path's oldest versions and writes the new one. The parameter is gone from
    this signature so the old behaviour cannot be reintroduced by accident.

    Because this returns `Skip`, not `Degraded`, a per-entry condition cannot
    express a store-wide failure at all.
    """
    if incoming_bytes > limits.max_file_bytes:
        return Skip("file-too-large")
    if new_files_this_scan >= limits.max_new_files_per_scan:
        return Skip("new-files-per-scan-throttle")
    return Allow()


# ── Retention (review H8) ─────────────────────────────────────────────────────


def prune_plan(index_rows, now_ns, window_ns):
    """Version directories eligible for deletion. Returns a PLAN; deletes nothing.

    `index_rows` is an iterable of `(path_dir, version_key, capture_epoch_ns)`.

    Two rules, and the second is the one that makes the first safe:

    H8: naive age-pruning deletes the ONLY copy of a stable file — one written
    31 days ago and never touched has exactly one version, and the guarantee
    inverts for precisely the files most worth keeping. So the newest version of
    every path is never in the plan, whatever its age.

    C12: the age compared here is the CAPTURE clock carried in the version key,
    never the source file's mtime. A source backdated to 1970 must not make its
    captured version prunable — that would be a delete path into the mirror
    driven from an agent-writable tree with one `touch`.
    """
    newest_by_dir = {}
    for store_dir, name, epoch_ns in index_rows:
        current = newest_by_dir.get(store_dir)
        if current is None or epoch_ns > current[0] or (
            epoch_ns == current[0] and name > current[1]
        ):
            newest_by_dir[store_dir] = (epoch_ns, name)

    plan = []
    for store_dir, name, epoch_ns in index_rows:
        if newest_by_dir[store_dir] == (epoch_ns, name):
            continue
        if now_ns - epoch_ns > window_ns:
            plan.append((store_dir, name))
    return plan


def version_window_plan(rows_for_path, cap):
    """Oldest version keys to delete so a NEW version fits under `cap`.

    `rows_for_path` is `[(version_key, capture_epoch_ns)]` for ONE mirrored path.
    Returns a PLAN; deletes nothing. The daemon's shared unlink executor applies
    it, the same one age-pruning uses, so retention stays daemon-only.

    Three properties, each of which is a test:

    * **The newest version is never in the plan.** Same rule as H8, for the same
      reason: the newest is the copy you actually want back.
    * **Below the cap the plan is empty** — no deletion happens on an ordinary
      write.
    * **At or above the cap it returns the (n - cap + 1) OLDEST keys**, leaving
      cap-1 behind so the incoming version lands at exactly `cap`.

    Ordering is by the DAEMON'S capture clock carried in the key (C12), never by
    source mtime. If it read source mtime, `touch -t` would let an agent choose
    which of its own versions the window discards.
    """
    if cap <= 0:
        return []
    ordered = sorted(rows_for_path, key=lambda row: (row[1], row[0]))
    if len(ordered) < cap:
        return []
    wanted = len(ordered) - cap + 1
    # Never the newest, whatever the arithmetic says. At cap == 1 the formula
    # asks for every version including the newest; this clamp is what stops a
    # misconfigured cap from emptying a path.
    deletable = max(0, len(ordered) - 1)
    return [key for key, _ in ordered[: min(wanted, deletable)]]


# ── Restore destination (review C9) ───────────────────────────────────────────


def restore_target(stored_relpath, watch_root, into=None):
    """Target(path) or Refuse(reason) for a restore.

    The DEFAULT destination is derived from the stored relpath plus the watch
    root; it is never a caller-supplied path baked into the store. `--into`
    names an alternative BASE directory and the same relpath is joined under it,
    so the caller chooses where the tree lands, never which file is written.

    The helper is unprivileged, so this is not an escalation boundary — it is
    the boundary that stops a malformed store key writing outside the tree the
    caller asked for. Both the write-time check and this read-time one apply.
    """
    if not is_safe_relpath(stored_relpath):
        return Refuse("unsafe-relpath")
    base = into if into is not None else watch_root
    if not isinstance(base, str) or not base.startswith("/"):
        return Refuse("destination-not-absolute")
    if "\x00" in base:
        return Refuse("destination-has-nul")
    root = os.path.normpath(base)
    candidate = os.path.normpath(os.path.join(root, stored_relpath))
    if candidate != root and not candidate.startswith(root.rstrip("/") + "/"):
        return Refuse("escapes-destination")
    return Target(path=candidate)


def resolve_asof(versions, at_epoch_ns):
    """The newest version at or before `at_epoch_ns`, or None.

    `versions` is an iterable of dicts carrying `epoch_ns`. Empty input yields
    None, and so does a timestamp before the earliest version — NEVER the newest.
    Falling back to the newest would answer "what did this look like an hour ago"
    with the current contents, which is worse than saying nothing.
    """
    eligible = [v for v in versions if v["epoch_ns"] <= at_epoch_ns]
    if not eligible:
        return None
    return max(eligible, key=lambda v: v["epoch_ns"])


RELATIVE_ASOF = re.compile(r"^(\d+)([smhd])$")
_RELATIVE_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_asof(text, now_epoch_seconds):
    """Seconds-since-epoch for an --asof argument, or None if unparseable.

    Accepts an ISO timestamp (`2026-09-01T14:30:00`) or a relative age
    (`20m`, `2h`, `3d`) meaning "that long ago".
    """
    if not isinstance(text, str) or not text:
        return None
    match = RELATIVE_ASOF.match(text.strip())
    if match:
        return now_epoch_seconds - int(match.group(1)) * _RELATIVE_SECONDS[match.group(2)]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(text.strip(), fmt))
        except ValueError:
            continue
    return None


# ── Watch roots (review C7/H7) ────────────────────────────────────────────────


def parse_watchlist(text, max_roots=MAX_WATCH_ROOTS):
    """Parse etc/watchlist.conf into [(root_id, pattern)] plus refusals.

    Format: `<id> <absolute-path>`, one per line, `#` comments. A single
    trailing `*` on the LAST component is the only glob permitted. Returns
    `(entries, refusals)` — refusals are (line, reason) and must be logged, not
    dropped.
    """
    entries = []
    refusals = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            refusals.append((line, "malformed-line"))
            continue
        root_id, pattern = parts[0], parts[1].strip()
        if not re.match(r"^[A-Za-z0-9_-]{1,32}$", root_id):
            refusals.append((line, "bad-root-id"))
            continue
        if not pattern.startswith("/"):
            refusals.append((line, "not-absolute"))
            continue
        if "\x00" in pattern or ".." in pattern.split("/"):
            refusals.append((line, "unsafe-pattern"))
            continue
        head, _, last = pattern.rpartition("/")
        if "*" in head:
            refusals.append((line, "glob-not-in-last-component"))
            continue
        if last.count("*") > 1 or (last.count("*") == 1 and not last.endswith("*")):
            refusals.append((line, "glob-must-be-trailing"))
            continue
        if len(entries) >= max_roots:
            # A silently dropped root is a silently unprotected agent (H7).
            refusals.append((line, "max-watch-roots"))
            continue
        entries.append((root_id, pattern))
    return entries, refusals


def watch_root_component_verdict(component_stats, allowed_uids):
    """Allow() or Refuse(reason) for a watch root, given its components' lstats.

    `component_stats` is the ordered list of `lstat` results for every component
    of the RAW configured root path, walked left to right with each symlink
    resolved as it is met. Never "resolve the whole path, then check what came
    back" — that check is about a path the config never named.

    Rules:
      * the LAST component must be a real directory, never a symlink (it is
        opened `O_NOFOLLOW`);
      * an intermediate component may be a symlink ONLY if the symlink itself is
        owned by root. macOS needs this — `/var` is a root-owned symlink to
        `/private/var`, and the `$TMPDIR` watch root goes through it — but an
        agent-created symlink is owned by uid 501 and is refused. Without the
        ownership rule the owner could re-point any parent of a watch root and
        the daemon would faithfully mirror wherever it landed;
      * every component must be owned by root or the owner uid.

    `.claude/worktrees` is itself agent-writable, so this is not theoretical:
    the watch root can be replaced (C7).
    """
    last = len(component_stats) - 1
    for index, st in enumerate(component_stats):
        if stat_mod.S_ISLNK(st.st_mode):
            if index == last:
                return Refuse("component-%d-is-symlink" % index)
            if st.st_uid != 0:
                return Refuse("component-%d-symlink-uid=%d" % (index, st.st_uid))
            continue
        if not stat_mod.S_ISDIR(st.st_mode):
            return Refuse("component-%d-not-a-directory" % index)
        if st.st_uid not in allowed_uids:
            return Refuse("component-%d-uid=%d" % (index, st.st_uid))
    return Allow()


# ── Self-announcing recovery (Property 4) ─────────────────────────────────────
#
# When an agent's read fails with ENOENT, this is the decision core that turns
# "no such file" into "the store holds three versions of it, here is the
# command". Everything below is a PURE FUNCTION over plain values: the I/O lives
# in `dhu_backup_announce.py`, which probes the store and hands the RESULT of
# that probe back here as data.
#
# The split is the same one the rest of this module makes, for the same reason:
# every status this vocabulary can produce is provable over fabricated inputs,
# with no store on disk and no daemon running.

# The install root only ever appears here as TEXT inside a recovery command.
# Nothing in this module opens it.
#
# It is a TABLE rather than a constant because the product now has two homes,
# and a table is the only shape in which both can be asserted by a test running
# on either platform. `/Library` is the macOS location for software installed by
# an administrator; `/opt` is the Filesystem Hierarchy Standard's location for
# an add-on package on Linux. Both are root-owned 0755 on a stock system, which
# is the property the whole design rests on (review H3): the daemon executes
# only root-owned bytes, out of a directory no agent can write.
DEFAULT_INSTALL_ROOTS = {
    "darwin": "/Library/DHU/backup",
    "linux": "/opt/dhu-backup",
}


def install_root_for_platform(platform_string):
    """The install root for a `sys.platform` string. PURE.

    An unknown platform gets the macOS root rather than a crash: this value is
    only ever TEXT inside a printed recovery command, and a wrong path in a
    hint is a worse-than-useless string, not an unsafe one. The daemon and the
    installer both refuse an unsupported platform loudly elsewhere, where the
    refusal can actually protect something.
    """
    if platform_string.startswith("linux"):
        return DEFAULT_INSTALL_ROOTS["linux"]
    return DEFAULT_INSTALL_ROOTS["darwin"]


DEFAULT_INSTALL_ROOT = install_root_for_platform(sys.platform)


# ── the change trigger, chosen by platform ────────────────────────────────────
#
# The trigger only ACCELERATES capture; the floor sweep is the guarantee, on
# every platform. So the selection below can never make the daemon less safe —
# its worst outcome is "poll-only", which is the guarantee running alone. That
# is exactly why it must be REPORTED: a daemon quietly running without its
# accelerator looks identical to one running with it, until a file that should
# have been captured in a second waits fifteen.

#: Every value `trigger_name_for_platform` can return, and the only values the
#: heartbeat's `trigger` field ever carries.
TRIGGER_NAMES = ("kqueue", "inotify", "poll-only")


def trigger_name_for_platform(platform_string):
    """Which change trigger a `sys.platform` string selects. PURE.

    `poll-only` is a REPORTED outcome, not a silent fallback: the daemon logs an
    ERROR at startup naming the platform, and the heartbeat says `poll-only` for
    as long as it runs that way.
    """
    if platform_string == "darwin":
        return "kqueue"
    if platform_string.startswith("linux"):
        return "inotify"
    return "poll-only"


# ── the interpreter a root daemon is allowed to execute (review H2) ───────────

#: Verdict of `interpreter_verdict`. `ok` is the whole decision; `reason` is
#: always populated, including when `ok` is true, so a log line says WHY it was
#: accepted rather than only that it was.
InterpreterVerdict = namedtuple("InterpreterVerdict", "ok reason")


def interpreter_verdict(path, is_symlink, link_uid, target, target_uid):
    """May a root daemon execute this interpreter? PURE.

    Review H2, restated: the homebrew node on the machine this was designed
    against is a USER-owned symlink, so a root daemon running it is a root shell
    for any agent. The same hazard exists on Linux the moment an interpreter is a
    symlink into a user-writable location, or a pyenv/conda build under a home
    directory.

    The caller supplies five facts it gathered with `readlink`/`stat`:

      path       the interpreter as it is written in the unit or plist
      is_symlink whether `path` ITSELF is a symbolic link (lstat)
      link_uid   the uid of `path` itself; `None` if it could not be lstat'ed
      target     `readlink -f path`, the fully resolved final path; `None` if it
                 could not be resolved
      target_uid the uid of `target`; `None` if it could not be stat'ed

    Both uids are checked, not just the target's. A root-owned python behind an
    agent-owned symlink is an agent-chosen interpreter with a root-owned alibi:
    the agent repoints the link, root executes what it points at, and every
    check made on the resolved path was made on the wrong file.

    `None` for either uid is a REFUSAL, never a pass. "I could not find out who
    owns the thing root is about to execute" is the one answer that must not be
    rounded down to "fine".
    """
    if not path or not path.startswith("/"):
        return InterpreterVerdict(False, "interpreter path is not absolute: %r" % (path,))
    if link_uid is None:
        return InterpreterVerdict(False, "cannot stat the interpreter %s" % path)
    if link_uid != 0:
        return InterpreterVerdict(
            False, "%s is owned by uid %d, not root — a root daemon must execute "
                   "only root-owned bytes" % (path, link_uid))
    if target is None:
        return InterpreterVerdict(False, "cannot resolve the interpreter %s" % path)
    if not target.startswith("/"):
        return InterpreterVerdict(False, "resolved interpreter is not absolute: %r" % (target,))
    if target_uid is None:
        return InterpreterVerdict(False, "cannot stat the resolved interpreter %s" % target)
    if target_uid != 0:
        return InterpreterVerdict(
            False, "%s resolves to %s, which is owned by uid %d, not root"
                   % (path, target, target_uid))
    if is_symlink:
        return InterpreterVerdict(
            True, "%s is a root-owned symlink to the root-owned %s" % (path, target))
    return InterpreterVerdict(True, "%s is a root-owned regular interpreter" % path)

STALE_SECONDS = 300

#: Every health verdict `health_verdict` can return. There is no eighth value
#: and no `None`: "we do not know" is spelled `unreadable-heartbeat`, which is
#: a REPORT, not a silent fallback to `ok`.
HEALTH_VERDICTS = (
    "ok",                     # the daemon scanned within STALE_SECONDS
    "degraded",               # a store-wide budget stopped capture
    "unprotected",            # healthy daemon, no usable watch root
    "scan-failed",            # every scan is throwing
    "stale",                  # no scan for more than STALE_SECONDS
    "no-heartbeat",           # var/state.json is absent
    "unreadable-heartbeat",   # it is present and does not parse, or is a shape
                              # this version does not understand
)

#: Every status `announce_missing` can return.
#:
#: `store-unavailable` is deliberately NOT collapsible into `not-held`. They are
#: opposite claims — "I looked and there is nothing" versus "I could not look" —
#: and an agent that treats the second as the first abandons recoverable work.
ANNOUNCE_STATUSES = (
    "held",                   # the store holds versions of this exact path
    "held-directory",         # the store holds paths UNDER this path
    "vaulted",                # credential-class: it can only be in the vault
    "not-held",               # inside a watch root, store read, no versions
    "outside-watch-roots",    # no watch root contains this path
    "store-unavailable",      # the store/roots/heartbeat could not be read
)

Located = namedtuple("Located", "root_id slug watch_root relpath")
Health = namedtuple("Health", "verdict detail")

Announcement = namedtuple(
    "Announcement",
    "status path reason root_id slug watch_root relpath origin "
    "versions newest held_path_count held_path_count_capped versions_capped "
    "watch_roots commands health health_detail install_root",
)
Announcement.__new__.__defaults__ = (
    None, None, None, None, None, None, None,
    (), None, None, False, False,
    (), (), None, None, DEFAULT_INSTALL_ROOT,
)


def announce_exit_code(status):
    """Process exit code for one status. 0 = something is held.

    Three codes, not two, because a caller must be able to tell "there is
    nothing to recover" (1) from "I could not find out" (2) without parsing
    text.
    """
    if status in ("held", "held-directory"):
        return 0
    if status == "store-unavailable":
        return 2
    if status in ANNOUNCE_STATUSES:
        return 1
    raise ValueError("unknown announce status: %r" % (status,))


def health_verdict(state, now_epoch, error_kind=None, error_detail=None):
    """`Health(verdict, detail)` from a parsed `var/state.json`. PURE.

    `error_kind` is `"missing"` (no heartbeat file) or `"unreadable"` (it is
    there and did not parse) — the caller distinguishes those two by which
    exception it caught, because only the caller does I/O.

    An unrecognised `state` label becomes `unreadable-heartbeat` rather than
    `ok`. A newer daemon writing a label this helper does not know is a status
    this helper genuinely cannot interpret, and reporting it as healthy would be
    the exact silent fallback the rest of this file exists to avoid.
    """
    if error_kind == "missing":
        return Health("no-heartbeat", error_detail or "no heartbeat file")
    if error_kind == "unreadable":
        return Health("unreadable-heartbeat", error_detail or "heartbeat did not parse")
    if error_kind is not None:
        raise ValueError("unknown error_kind: %r" % (error_kind,))

    if not isinstance(state, dict):
        return Health("unreadable-heartbeat", "heartbeat is not a JSON object")

    label = state.get("state")
    if label == "degraded":
        return Health("degraded", str(state.get("degraded_reason") or "reason not recorded"))
    if label == "unprotected":
        return Health("unprotected", "the daemon has no usable watch root")
    if label == "scan-failed":
        return Health("scan-failed", str(state.get("scan_error") or "reason not recorded"))
    if label != "ok":
        return Health("unreadable-heartbeat",
                      "heartbeat state is %r, which this version does not understand"
                      % (label,))

    raw = state.get("last_scan_epoch")
    try:
        last = int(raw)
    except (TypeError, ValueError):
        return Health("unreadable-heartbeat", "last_scan_epoch is %r, not a number" % (raw,))
    age = int(now_epoch) - last
    if age > STALE_SECONDS:
        return Health("stale", "the last capture was %ds ago" % age)
    return Health("ok", "the last capture was %ds ago" % age)


def locate_in_roots(abs_path, roots):
    """`Located(...)` or `Refuse(reason)` for an absolute path. PURE.

    `roots` is `[(root_id, slug, watch_root)]`. A path is inside watch root `W`
    when it EQUALS `W` or starts with `W + "/"`; the relpath is the remainder,
    and the LONGEST matching watch root wins (a worktree nested under a repo
    root belongs to the worktree).

    **The path is normalised and NEVER resolved through symlinks.** There is no
    `realpath` here, deliberately, and for two reasons the review already paid
    for. C7/C8: resolve-then-check is the race — the check would be about a path
    the caller never named. And here it would be worse than a race, because the
    caller's path comes from an agent's own tree: one symlink in that tree would
    aim this lookup at any watch root on the machine and report its contents
    back. `os.path.normpath` is lexical, so `a/../b` collapses without asking
    the filesystem what `a` is.
    """
    if not isinstance(abs_path, str) or abs_path == "":
        return Refuse("path is empty")
    if "\x00" in abs_path:
        return Refuse("path contains NUL")
    if not abs_path.startswith("/"):
        return Refuse("path is not absolute: %r" % (abs_path,))

    normalized = os.path.normpath(abs_path)
    best = None
    for entry in roots:
        root_id, slug, watch_root = entry
        if not isinstance(watch_root, str) or not watch_root.startswith("/"):
            continue
        root = os.path.normpath(watch_root)
        stem = root.rstrip("/")
        if normalized == root:
            relpath = ""
        elif normalized.startswith(stem + "/"):
            relpath = normalized[len(stem) + 1:]
        else:
            continue
        if best is None or len(root) > len(best[0]):
            best = (root, root_id, slug, relpath)

    if best is None:
        return Refuse("no watch root contains this path")
    root, root_id, slug, relpath = best
    if relpath != "" and not is_safe_relpath(relpath):
        # Deliberately NOT `store-unavailable`. That status means "I could not
        # read the store", and returning it here would blame a healthy store for
        # a path the CALLER malformed — the claim and the evidence would come
        # from different populations. `not-held` would be a different lie: it
        # asserts a lookup that never happened. The honest answer is that the
        # path as named cannot be located inside any watch root, which is what
        # `outside-watch-roots` says, with `reason` carrying why.
        return Refuse("%r is not a protectable relative path under %s" % (relpath, root))
    return Located(root_id=root_id, slug=slug, watch_root=root, relpath=relpath)


def _quote(text):
    """Shell-quote one argument for a command a human or agent will paste.

    `shlex` is imported here rather than at module scope so the root daemon,
    which imports this module and never renders a command, does not load it.
    Stdlib either way (review H3 forbids anything else).
    """
    import shlex
    return shlex.quote(text)


def recovery_commands(status, install_root, located, relpath_for_command=None):
    """The exact command(s) that recover this path. PURE — returns strings.

    `--root-id` is always included: the helper matches by SUBSTRING, and a
    relpath that exists under two watch roots (a repo and a worktree of it) is
    the normal case, not the exotic one. Without it the printed command would
    fail with "matches 2 paths" the first time it mattered.
    """
    binary = os.path.join(install_root, "bin", "dhu-backup")
    prefix = [_quote(binary)]
    if install_root != DEFAULT_INSTALL_ROOT:
        prefix += ["--install-root", _quote(install_root)]
    if located.root_id:
        prefix += ["--root-id", _quote(str(located.root_id))]
    target = _quote(relpath_for_command if relpath_for_command is not None else located.relpath)
    line = lambda *rest: " ".join(prefix + list(rest))  # noqa: E731

    if status == "held":
        return (line("cat", target), line("restore", target), line("log", target))
    if status == "held-directory":
        if not located.relpath:
            # The path IS the watch root. `restore-dir` strips slashes off its
            # argument and prefix-matches the result, so there is no argument
            # that means "everything" — emitting one would be a command that
            # silently matches nothing. List instead, and say what to narrow.
            return (line("ls"),)
        return (line("restore-dir", target), line("ls", target))
    if status == "vaulted":
        # `log` first so the human sees the versions, then `cat` REDIRECTED by
        # the shell. The redirect is not decoration: it is what makes the
        # recovered file belong to the human rather than to root.
        #
        # `restore` under sudo would write the origin as root:wheel. The daemon
        # refuses a file it does not own (`wrong-owner-uid`), so that file would
        # stop being protected the moment it was recovered, and the agent that
        # needed it could not edit it either. A recovery that quietly un-protects
        # the file it recovers is a trap, so `restore` refuses root outright
        # (`restore_permitted`) and this command does not offer it.
        #
        # `DHU_BACKUP_ALLOW_ROOT=1` is the deliberate opt-in the CLI already
        # requires, and it is also what makes `load_entries` read `vault/` at
        # all (`trees_to_read`). Both halves of that are needed, which is why
        # the variable appears here rather than a bare `sudo`.
        origin = os.path.join(located.watch_root, located.relpath)
        sudo = ["sudo", "DHU_BACKUP_ALLOW_ROOT=1"] + prefix
        return (
            " ".join(sudo + ["log", target]),
            " ".join(sudo + ["cat", target]) + " > " + _quote(origin),
        )
    return ()


# ── Who may read which tree, and who may write (Property 4 follow-up) ─────────


def trees_to_read(euid, allow_root_env):
    """Which mirror trees a reader is entitled to walk. PURE.

    `("store",)` for everyone, and `("store", "vault")` for root that has opted
    in with `DHU_BACKUP_ALLOW_ROOT`. Both conditions are required, and the
    ordering of the reasoning matters:

    * The euid check is not the security boundary — `vault/` is mode 0700
      root-only, so an unprivileged reader is stopped by the KERNEL whatever
      this function returns. It is here so the tool asks for the vault only when
      it could actually read it, instead of walking a directory it will be
      denied and reporting the denial as a store failure.
    * The env-var check IS meaningful: it keeps an accidental `sudo dhu-backup
      ls` from listing credential paths on a shared screen. `refuse_root` in the
      helper already demands the same variable, so this is the second half of
      one deliberate opt-in rather than a new one.
    """
    if euid == 0 and allow_root_env:
        return (STORE_TREE, VAULT_TREE)
    return (STORE_TREE,)


def restore_permitted(euid):
    """`Allow()` or `Refuse(reason)` — may this process WRITE a restore? PURE.

    Root may never restore, opt-in or not. A file written back by root is
    root-owned at the origin, and two things follow that no message can undo:
    the daemon refuses it on the next scan with `wrong-owner-uid`, so the
    recovered file is no longer protected; and the owner's agent cannot edit
    the work it just got back. Recovering a file by un-protecting it is a trap,
    so the type refuses rather than warns.

    Reading under sudo is a different matter and stays allowed: `cat` writes
    nothing, and the shell redirect in the vault recovery command creates the
    destination as the invoking user.
    """
    if euid == 0:
        return Refuse("restore never runs as root: use `cat ... > <origin>` so the "
                      "file stays yours. A root-written file is refused by the daemon "
                      "(wrong-owner-uid) and cannot be edited by your agent.")
    return Allow()


def _coerce_health(health):
    if isinstance(health, Health):
        return health
    if isinstance(health, dict):
        verdict = health.get("verdict")
        if verdict not in HEALTH_VERDICTS:
            raise ValueError("unknown health verdict: %r" % (verdict,))
        return Health(verdict, health.get("detail"))
    raise TypeError("health must be a Health or a dict, not %r" % (type(health).__name__,))


def announce_missing(abs_path, roots, lookup, health, now_epoch,
                     install_root=DEFAULT_INSTALL_ROOT, extra_globs=()):
    """Classify a path whose read just failed. PURE — no I/O, no clock.

    `roots`  — `[(root_id, slug, watch_root)]` read from `var/roots/*.json`.
    `lookup` — what the caller's store probe FOUND, as data, or `None` if no
               probe was made. Keys:
                 `roots_error`  the manifests could not be read (str or None)
                 `store_error`  the store could not be read for this path
                 `probed`       whether a probe actually ran
                 `versions`     `[{key, epoch_ns, sha, size, store_path, ...}]`
                 `held_path_count`, `held_path_count_capped`, `versions_capped`
    `health` — a `Health` (or a dict with `verdict`/`detail`), carried into
               EVERY result. "Not held" while the daemon has been dead for a day
               is a different fact from "not held" under a healthy daemon, and
               only the health verdict distinguishes them.
    `now_epoch` — passed in rather than read, so the classification is a
               function of its arguments and nothing else.
    `extra_globs` — the operator's additive `etc/vault-extra.conf` globs, so an
               extra-glob match is announced as `vaulted` rather than as
               `not-held`. Passed in, like everything else here: this function
               reads no files.

    Returns an `Announcement`. `status` is one of `ANNOUNCE_STATUSES`.
    """
    health = _coerce_health(health)
    base = {
        "path": abs_path if isinstance(abs_path, str) else repr(abs_path),
        "health": health.verdict,
        "health_detail": health.detail,
        "install_root": install_root,
    }

    if lookup is None:
        return Announcement(status="store-unavailable",
                            reason="no store lookup was performed", **base)
    if lookup.get("roots_error"):
        # Without the manifests there are no watch roots to compare against, so
        # `outside-watch-roots` would be an assertion about a list we could not
        # read. Everything is unavailable, whatever the path.
        return Announcement(status="store-unavailable",
                            reason=str(lookup["roots_error"]), **base)

    watch_roots = tuple(sorted({r[2] for r in roots if isinstance(r[2], str)}))
    located = locate_in_roots(abs_path, roots)
    if isinstance(located, Refuse):
        return Announcement(status="outside-watch-roots", reason=located.reason,
                            watch_roots=watch_roots, **base)

    origin = os.path.join(located.watch_root, located.relpath) if located.relpath \
        else located.watch_root
    placed = {
        "root_id": located.root_id, "slug": located.slug,
        "watch_root": located.watch_root, "relpath": located.relpath,
        "origin": origin,
    }

    if located.relpath and is_credential_class(located.relpath, extra_globs):
        # Never "it IS in the vault". `vault/` is 0700 root-only and this code
        # runs unprivileged, so it has not looked and cannot look. The claim it
        # is entitled to make is about the PREDICATE, which is pure and which
        # the daemon evaluated at copy time on this same relpath.
        return Announcement(
            status="vaulted",
            reason=vault_reason(located.relpath, extra_globs),
            commands=recovery_commands("vaulted", install_root, located),
            **dict(base, **placed))

    if lookup.get("store_error"):
        return Announcement(status="store-unavailable", reason=str(lookup["store_error"]),
                            **dict(base, **placed))
    if not lookup.get("probed"):
        return Announcement(status="store-unavailable",
                            reason="no store lookup was performed for %r" % (located.relpath,),
                            **dict(base, **placed))

    versions = tuple(lookup.get("versions") or ())
    if versions:
        newest = max(versions, key=lambda v: (v["epoch_ns"], v["key"]))
        return Announcement(
            status="held", versions=versions, newest=newest,
            versions_capped=bool(lookup.get("versions_capped")),
            commands=recovery_commands("held", install_root, located),
            **dict(base, **placed))

    count = int(lookup.get("held_path_count") or 0)
    if count > 0:
        return Announcement(
            status="held-directory", held_path_count=count,
            held_path_count_capped=bool(lookup.get("held_path_count_capped")),
            commands=recovery_commands("held-directory", install_root, located,
                                       relpath_for_command=located.relpath or "."),
            **dict(base, **placed))

    return Announcement(status="not-held", **dict(base, **placed))
