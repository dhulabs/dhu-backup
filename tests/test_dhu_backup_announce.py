"""Integration tests for DHU Backup's self-announcing recovery (Property 4).

Run with:  /usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'

The pure decision core is proven in `test_dhu_backup_core.py` over fabricated
values. This file proves the parts that touch a filesystem and a process, and it
does so against a FABRICATED install root built under the scratch directory —
never against `/Library/DHU/backup`. Three rules it obeys:

1. **No destructive sink is fired.** Nothing here restores, writes into a store,
   or runs anything as root. The `restore` paths of the helper are exercised by
   the MCP tool listing and schemas, not by writing files back.
2. **A claim and its evidence share a population.** The golden text below was
   captured by running the CURRENT helper against THIS fixture before `--json`
   and `missing` existed, so "the text output is unchanged" is a comparison
   against the real previous behaviour rather than against a re-description of
   it.
3. **`announce` never raises.** That is asserted directly, on inputs chosen to
   break it, rather than assumed from reading the code.
"""

import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO_ROOT, "src")
sys.path.insert(0, SRC)

import dhu_backup_announce  # noqa: E402
import dhu_backup_core  # noqa: E402

PYTHON = "/usr/bin/python3"
HELPER = os.path.join(SRC, "dhu-backup.py")
MCP = os.path.join(SRC, "dhu-backup-mcp.py")

#: Where the fabricated install roots are built. `None` means "the system temp
#: directory", which is what `tempfile.mkdtemp(dir=None)` uses.
#:
#: This used to DEFAULT to one coding-agent session's private scratch directory,
#: and `setUp` skipped every test when that directory was missing. On the
#: machine where it was written the directory existed and 80 tests ran; on a
#: fresh clone, in CI, and on a clean Linux VM the directory does not exist,
#: all 80 skipped, and the suite still printed OK. That is the silent
#: fallback this project's rules forbid: the claim "the suite passes" and its
#: evidence did not share a population. A test that needs a scratch directory
#: CREATES one; it never skips because a directory is missing. If the env var
#: names a path that does not exist, `mkdtemp` raises and the test ERRORS —
#: loudly, which is the point.
SCRATCH = os.environ.get("DHU_BACKUP_TEST_SCRATCH") or None


# ── the fabricated install root ───────────────────────────────────────────────

OWNER = "/Users/fixture"
FIXTURE_REPO = OWNER + "/Projects/demo"
FIXTURE_WORKTREE = OWNER + "/Projects/demo/.claude/worktrees/agent-x"

T0 = 1788300000_000000000
T1 = 1788300600_000000000
T2 = 1788301200_000000000

FILES = [
    ("repo", "demo-aaaaaaaa", FIXTURE_REPO, "lib/heartbeat.ts",
     [(T0, "000000000001", b"one\n"),
      (T1, "000000000002", b"two two\n"),
      (T2, "000000000003", b"three three three\n")]),
    ("repo", "demo-aaaaaaaa", FIXTURE_REPO, "lib/notes.md",
     [(T1, "0000000000aa", b"notes\n")]),
    ("repo", "demo-aaaaaaaa", FIXTURE_REPO, "lib/deep/inner/thing.txt",
     [(T1, "0000000000bb", b"inner\n")]),
    ("worktrees", "agent-x-bbbbbbbb", FIXTURE_WORKTREE, "lib/heartbeat.ts",
     [(T0, "0000000000cc", b"worktree copy\n")]),
]


def fresh_ok_state():
    """A heartbeat that is `ok` RIGHT NOW.

    `last_scan_epoch` is the wall clock at build time, deliberately: a fixed
    epoch would go stale and the health banner would print a second-by-second
    age, so no golden text could ever be stable.
    """
    return {"state": "ok", "last_scan_epoch": int(time.time()),
            "last_scan_iso": "2026-09-01T22:20:30Z", "files_scanned": 4,
            "store_bytes": 100, "free_bytes": 30000000000, "watch_roots": 2}


def build_fixture_install_root(base, state=None):
    """Create `base` as a complete fake install root with the REAL store layout."""
    if os.path.isdir(base):
        shutil.rmtree(base)
    for sub in ("bin", "etc", "store", "vault", "var/roots", "var/tmp"):
        os.makedirs(os.path.join(base, sub), 0o755)

    seen = set()
    for root_id, slug, watch_root, relpath, versions in FILES:
        if (root_id, slug) not in seen:
            seen.add((root_id, slug))
            manifest = {"root_id": root_id, "slug": slug, "watch_root": watch_root}
            with open(os.path.join(base, "var", "roots",
                                   "%s-%s.json" % (root_id, slug)), "w") as handle:
                json.dump(manifest, handle, indent=2, sort_keys=True)
        parts = relpath.split("/")
        version_parent = os.path.join(base, "store", root_id, slug, *parts[:-1])
        os.makedirs(version_parent, 0o755, exist_ok=True)
        for epoch_ns, sha, content in versions:
            version_dir = os.path.join(version_parent, "@%019d-%s" % (epoch_ns, sha))
            os.makedirs(version_dir, 0o755, exist_ok=True)
            with open(os.path.join(version_dir, parts[-1]), "wb") as handle:
                handle.write(content)

    write_state(base, fresh_ok_state() if state is None else state)
    return base


def write_state(base, state):
    path = os.path.join(base, "var", "state.json")
    if state is None:
        if os.path.exists(path):
            os.unlink(path)
        return
    with open(path, "w") as handle:
        handle.write(state if isinstance(state, str)
                     else json.dumps(state, indent=2, sort_keys=True))


def load_helper_module():
    """Import `src/dhu-backup.py` as a module. Its filename has a hyphen."""
    import importlib.machinery
    import importlib.util

    spec = importlib.util.spec_from_loader(
        "dhu_backup_cli_under_test",
        importlib.machinery.SourceFileLoader("dhu_backup_cli_under_test", HELPER))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FixtureCase(unittest.TestCase):
    """Every test in this file gets its own fabricated install root."""

    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="dhu-fixture-", dir=SCRATCH)
        self.install_root = build_fixture_install_root(os.path.join(self.base, "install"))
        self._restore_modes = []

    def tearDown(self):
        for path, mode in self._restore_modes:
            try:
                os.chmod(path, mode)
            except OSError:
                pass
        shutil.rmtree(self.base, ignore_errors=True)

    def chmod_for_test(self, path, mode):
        """chmod, remembering the old mode so tearDown can always clean up."""
        self._restore_modes.append((path, os.lstat(path).st_mode & 0o7777))
        os.chmod(path, mode)


# ── B: the cheap I/O lookup ───────────────────────────────────────────────────


class AnnounceLookupTests(FixtureCase):
    def announce(self, path, **kwargs):
        return dhu_backup_announce.announce(path, install_root=self.install_root, **kwargs)

    def test_held_reports_three_versions_with_the_newest_first_in_mind(self):
        result = self.announce(FIXTURE_REPO + "/lib/heartbeat.ts")
        self.assertEqual(result.status, "held")
        self.assertEqual(len(result.versions), 3)
        self.assertEqual(result.newest["epoch_ns"], T2)
        self.assertEqual(result.newest["sha"], "000000000003")
        self.assertEqual(result.newest["size"], len(b"three three three\n"))
        self.assertEqual(result.root_id, "repo")
        self.assertEqual(result.origin, FIXTURE_REPO + "/lib/heartbeat.ts")

    def test_held_with_one_version(self):
        result = self.announce(FIXTURE_REPO + "/lib/notes.md")
        self.assertEqual(result.status, "held")
        self.assertEqual(len(result.versions), 1)

    def test_a_sibling_files_version_directories_are_not_counted_as_this_paths(self):
        """Every file in one source directory keeps its versions as SIBLINGS here.

        `lib/` holds seven version directories: three for heartbeat.ts, one for
        notes.md, and three more belonging to neither. Only the ones whose leaf
        is this basename are ours, which is why the probe lstats
        `<version>/<basename>` rather than trusting the directory name.
        """
        parent = os.path.join(self.install_root, "store", "repo", "demo-aaaaaaaa", "lib")
        keys = [n for n in os.listdir(parent) if dhu_backup_core.parse_version_key(n)]
        self.assertEqual(len(keys), 4)
        self.assertEqual(len(self.announce(FIXTURE_REPO + "/lib/notes.md").versions), 1)

    def test_the_longest_watch_root_wins_against_a_real_store(self):
        result = self.announce(FIXTURE_WORKTREE + "/lib/heartbeat.ts")
        self.assertEqual(result.status, "held")
        self.assertEqual(result.root_id, "worktrees")
        self.assertEqual(result.newest["sha"], "0000000000cc")

    def test_held_directory_counts_the_paths_under_it(self):
        result = self.announce(FIXTURE_REPO + "/lib")
        self.assertEqual(result.status, "held-directory")
        self.assertEqual(result.held_path_count, 3)
        self.assertFalse(result.held_path_count_capped)

    def test_a_deeper_directory_counts_only_what_is_under_it(self):
        result = self.announce(FIXTURE_REPO + "/lib/deep")
        self.assertEqual(result.status, "held-directory")
        self.assertEqual(result.held_path_count, 1)

    def test_the_watch_root_itself_is_a_held_directory(self):
        result = self.announce(FIXTURE_REPO)
        self.assertEqual(result.status, "held-directory")
        self.assertEqual(result.held_path_count, 3)
        self.assertEqual(result.relpath, "")

    def test_the_directory_count_is_capped_and_says_so(self):
        original = dhu_backup_announce.MAX_HELD_PATHS
        dhu_backup_announce.MAX_HELD_PATHS = 2
        try:
            result = self.announce(FIXTURE_REPO + "/lib")
        finally:
            dhu_backup_announce.MAX_HELD_PATHS = original
        self.assertEqual(result.status, "held-directory")
        self.assertTrue(result.held_path_count_capped)
        self.assertEqual(result.held_path_count, 2)

    def test_not_held_for_a_path_inside_a_watch_root_with_no_versions(self):
        result = self.announce(FIXTURE_REPO + "/lib/never-existed.ts")
        self.assertEqual(result.status, "not-held")
        self.assertEqual(result.watch_root, FIXTURE_REPO)

    def test_not_held_for_a_path_in_a_directory_the_store_has_never_seen(self):
        result = self.announce(FIXTURE_REPO + "/nowhere/at/all.ts")
        self.assertEqual(result.status, "not-held")

    def test_outside_watch_roots_names_the_roots(self):
        result = self.announce("/etc/hosts")
        self.assertEqual(result.status, "outside-watch-roots")
        self.assertEqual(sorted(result.watch_roots), [FIXTURE_REPO, FIXTURE_WORKTREE])

    def test_vaulted_for_a_credential_class_path(self):
        result = self.announce(FIXTURE_REPO + "/.env.local")
        self.assertEqual(result.status, "vaulted")
        self.assertEqual(len(result.commands), 2)
        for command in result.commands:
            self.assertTrue(command.startswith("sudo DHU_BACKUP_ALLOW_ROOT=1 "))
            self.assertNotIn("<", command)
        self.assertTrue(result.commands[1].endswith(FIXTURE_REPO + "/.env.local"))

    def test_the_vault_is_never_opened_even_when_it_is_readable(self):
        """The predicate is the evidence, not a directory listing.

        In the real install `vault/` is 0700 root-only. This fixture's is
        readable by the test user, so if the probe looked there it would find
        nothing and could report `not-held` for a secret it cannot see. The
        status must come from the predicate regardless.
        """
        os.makedirs(os.path.join(self.install_root, "vault", "repo", "demo-aaaaaaaa"))
        result = self.announce(FIXTURE_REPO + "/.env.local")
        self.assertEqual(result.status, "vaulted")

    def test_store_unavailable_for_an_install_root_that_does_not_exist(self):
        result = dhu_backup_announce.announce("/etc/hosts", install_root="/nonexistent-xyz")
        self.assertEqual(result.status, "store-unavailable")
        self.assertIn("roots-unreadable", result.reason)
        self.assertEqual(result.health, "no-heartbeat")

    def test_store_unavailable_when_the_store_directory_is_unreadable(self):
        store = os.path.join(self.install_root, "store")
        self.chmod_for_test(store, 0o000)
        result = self.announce(FIXTURE_REPO + "/lib/heartbeat.ts")
        self.assertEqual(result.status, "store-unavailable")
        self.assertIn("Permission denied", result.reason)

    def test_store_unavailable_when_the_store_is_missing_entirely(self):
        shutil.rmtree(os.path.join(self.install_root, "store"))
        result = self.announce(FIXTURE_REPO + "/lib/heartbeat.ts")
        self.assertEqual(result.status, "store-unavailable")
        self.assertIn("store-not-found", result.reason)

    def test_store_unavailable_is_NEVER_reported_as_not_held(self):
        """The two opposite claims must not be reachable from one another."""
        self.chmod_for_test(os.path.join(self.install_root, "store"), 0o000)
        for path in (FIXTURE_REPO + "/lib/heartbeat.ts", FIXTURE_REPO + "/lib/gone.ts",
                     FIXTURE_REPO + "/lib"):
            self.assertEqual(self.announce(path).status, "store-unavailable", path)

    def test_an_unreadable_roots_directory_is_unavailable_not_outside_roots(self):
        self.chmod_for_test(os.path.join(self.install_root, "var", "roots"), 0o000)
        result = self.announce("/etc/hosts")
        self.assertEqual(result.status, "store-unavailable")

    def test_a_single_corrupt_manifest_does_not_lose_the_other_roots(self):
        with open(os.path.join(self.install_root, "var", "roots", "junk.json"), "w") as handle:
            handle.write("{not json")
        self.assertEqual(self.announce(FIXTURE_REPO + "/lib/notes.md").status, "held")

    def test_manifests_that_are_ALL_unusable_are_reported_unavailable(self):
        directory = os.path.join(self.install_root, "var", "roots")
        for name in os.listdir(directory):
            os.unlink(os.path.join(directory, name))
        with open(os.path.join(directory, "junk.json"), "w") as handle:
            handle.write("{not json")
        result = self.announce(FIXTURE_REPO + "/lib/notes.md")
        self.assertEqual(result.status, "store-unavailable")

    def test_every_health_verdict_reaches_the_result(self):
        cases = [
            (None, "no-heartbeat"),
            ("{not json", "unreadable-heartbeat"),
            ({"state": "ok", "last_scan_epoch": int(time.time())}, "ok"),
            ({"state": "ok", "last_scan_epoch": int(time.time()) - 4000}, "stale"),
            ({"state": "warning", "last_scan_epoch": int(time.time()),
              "warning_reason": ["free-space-low"],
              "warning_detail": "12.0 GiB free, and capture stops at 10.0 GiB"}, "warning"),
            ({"state": "degraded", "degraded_reason": "store-ceiling"}, "degraded"),
            ({"state": "unprotected"}, "unprotected"),
            ({"state": "scan-failed", "scan_error": "boom"}, "scan-failed"),
        ]
        for state, expected in cases:
            write_state(self.install_root, state)
            result = self.announce(FIXTURE_REPO + "/lib/notes.md")
            self.assertEqual(result.health, expected, expected)
            self.assertEqual(result.status, "held")
            self.assertTrue(result.health_detail)

    def test_not_held_under_a_dead_daemon_still_says_the_daemon_is_dead(self):
        write_state(self.install_root, {"state": "ok",
                                        "last_scan_epoch": int(time.time()) - 86400})
        result = self.announce(FIXTURE_REPO + "/lib/gone.ts")
        self.assertEqual(result.status, "not-held")
        self.assertEqual(result.health, "stale")
        self.assertIn("STALE", dhu_backup_announce.format_text(result))

    def test_announce_never_raises_on_hostile_input(self):
        hostile = ["", "/", "relative/path.ts", "../../etc/passwd", "/a\x00b",
                   FIXTURE_REPO + "/../../etc/passwd", "/" * 500,
                   FIXTURE_REPO + "/" + "x" * 400, None, 17, b"/bytes"]
        for path in hostile:
            result = self.announce(path)
            self.assertIn(result.status, dhu_backup_core.ANNOUNCE_STATUSES, repr(path))
            self.assertIn(result.health, dhu_backup_core.HEALTH_VERDICTS, repr(path))
            self.assertIsInstance(dhu_backup_announce.format_text(result), str)
            self.assertIsInstance(json.dumps(dhu_backup_announce.to_json(result)), str)

    def test_announce_never_raises_when_the_install_root_is_nonsense(self):
        for root in ("", None, "/dev/null", "/etc/hosts", 17):
            result = dhu_backup_announce.announce("/etc/hosts", install_root=root)
            self.assertIn(result.status, dhu_backup_core.ANNOUNCE_STATUSES, repr(root))

    def test_an_install_root_that_is_not_a_path_is_REPORTED_not_defaulted(self):
        """Silently substituting the default would answer about another install.

        "Not held" about the wrong store is the worst answer this tool can give:
        it is confidently wrong about work that exists. So a bad install root is
        `store-unavailable` with the value echoed, not a quiet fallback.
        """
        for root in ("", None, 17, []):
            result = dhu_backup_announce.announce(FIXTURE_REPO + "/lib/notes.md",
                                                  install_root=root)
            self.assertEqual(result.status, "store-unavailable", repr(root))
            self.assertIn("install_root is not a path", result.reason)
            self.assertIn(repr(root), result.reason)

    def test_the_lookup_does_not_walk_the_store_for_a_missing_file(self):
        """Cheapness is the property; prove it by counting the calls.

        `load_entries` in the helper walks every path in the store to answer
        anything. This must not, because it runs on every failed read.
        """
        real_walk = os.walk
        walks = []
        os.walk = lambda *a, **kw: (walks.append(a[0]), real_walk(*a, **kw))[1]
        try:
            self.assertEqual(self.announce(FIXTURE_REPO + "/lib/heartbeat.ts").status, "held")
            self.assertEqual(walks, [])
            self.assertEqual(self.announce(FIXTURE_REPO + "/lib/gone.ts").status, "not-held")
            self.assertEqual(walks, [])
        finally:
            os.walk = real_walk

    def test_to_json_puts_status_first_and_round_trips(self):
        payload = dhu_backup_announce.to_json(self.announce(FIXTURE_REPO + "/lib/notes.md"))
        self.assertEqual(list(payload)[0], "status")
        self.assertEqual(json.loads(json.dumps(payload))["status"], "held")
        self.assertEqual(payload["exit_code"], 0)


class AnnounceCliTests(FixtureCase):
    """The standalone `python3 dhu_backup_announce.py <path>` entry point."""

    def run_announce(self, *argv):
        env = dict(os.environ, TZ="UTC")
        return subprocess.run(
            [PYTHON, "-E", "-s", "-S", os.path.join(SRC, "dhu_backup_announce.py")]
            + list(argv) + ["--install-root", self.install_root],
            capture_output=True, text=True, env=env)

    def test_the_exit_codes_separate_held_absent_and_unknown(self):
        self.assertEqual(self.run_announce(FIXTURE_REPO + "/lib/notes.md").returncode, 0)
        self.assertEqual(self.run_announce(FIXTURE_REPO + "/lib").returncode, 0)
        self.assertEqual(self.run_announce(FIXTURE_REPO + "/lib/gone.ts").returncode, 1)
        self.assertEqual(self.run_announce("/etc/hosts").returncode, 1)
        self.assertEqual(self.run_announce(FIXTURE_REPO + "/.env.local").returncode, 1)

    def test_a_broken_install_root_exits_2(self):
        env = dict(os.environ, TZ="UTC")
        done = subprocess.run(
            [PYTHON, "-E", "-s", "-S", os.path.join(SRC, "dhu_backup_announce.py"),
             "/etc/hosts", "--install-root", "/nonexistent-xyz"],
            capture_output=True, text=True, env=env)
        self.assertEqual(done.returncode, 2)
        self.assertIn("STORE UNAVAILABLE", done.stdout)

    def test_json_mode_prints_one_parseable_object(self):
        done = self.run_announce(FIXTURE_REPO + "/lib/heartbeat.ts", "--json")
        payload = json.loads(done.stdout)
        self.assertEqual(payload["status"], "held")
        self.assertEqual(payload["health"], "ok")
        self.assertEqual(len(payload["versions"]), 3)

    def test_no_arguments_is_a_usage_error(self):
        env = dict(os.environ, TZ="UTC")
        done = subprocess.run(
            [PYTHON, "-E", "-s", "-S", os.path.join(SRC, "dhu_backup_announce.py")],
            capture_output=True, text=True, env=env)
        self.assertEqual(done.returncode, 2)
        self.assertIn("usage", done.stderr)


# ── C: the helper's `missing` subcommand and `--json` ─────────────────────────
#
# GOLDEN was captured by running the helper as it stood BEFORE `--json` and
# `missing` were added, against the fixture this file builds. It is the previous
# behaviour itself, not a description of it, so "the text output is unchanged"
# is a claim whose evidence comes from the same population.
#
# `{base}` stands in for the install root, which is a fresh temporary directory
# on every run. The heartbeat is `ok` at build time, so no health banner is
# printed and the golden covers the whole of stdout.

GOLDEN = {
    "ls": {
        "rc": 0,
        "stdout": "lib/deep/inner/thing.txt  [repo]  1 version(s), newest 2026-09-01T22:10:00\n"
                  "lib/heartbeat.ts  [repo]  3 version(s), newest 2026-09-01T22:20:00\n"
                  "lib/notes.md  [repo]  1 version(s), newest 2026-09-01T22:10:00\n"
                  "lib/heartbeat.ts  [worktrees]  1 version(s), newest 2026-09-01T22:00:00\n",
    },
    "ls heartbeat": {
        "rc": 0,
        "stdout": "lib/heartbeat.ts  [repo]  3 version(s), newest 2026-09-01T22:20:00\n"
                  "lib/heartbeat.ts  [worktrees]  1 version(s), newest 2026-09-01T22:00:00\n",
    },
    "ls lib": {
        "rc": 0,
        "stdout": "lib/deep/inner/thing.txt  [repo]  1 version(s), newest 2026-09-01T22:10:00\n"
                  "lib/heartbeat.ts  [repo]  3 version(s), newest 2026-09-01T22:20:00\n"
                  "lib/notes.md  [repo]  1 version(s), newest 2026-09-01T22:10:00\n"
                  "lib/heartbeat.ts  [worktrees]  1 version(s), newest 2026-09-01T22:00:00\n",
    },
    # DELIBERATELY CHANGED, and the only line of the golden that is. The
    # captured original printed
    #     sudo /usr/bin/python3 -E -s -S {base}/bin/dhu-backup restore <path>
    # which did not work: `load_entries` read `store/` only, so the vault was
    # never searched however the helper was invoked, and a root-written restore
    # would have left the origin root-owned and therefore unprotected. The two
    # lines below are the commands that do work. Everything else in GOLDEN is
    # the pre-change capture, unmodified.
    "ls nomatch": {
        "rc": 1,
        "stdout": "no readable versions match 'nomatch' (store holds 4 path(s))\n"
                  "note: credential-class paths (.env*, keys, .ssh/…) are held in the "
                  "root-only vault and are not listed here — recover one with sudo:\n"
                  "      sudo DHU_BACKUP_ALLOW_ROOT=1 {base}/bin/dhu-backup log <path>\n"
                  "      sudo DHU_BACKUP_ALLOW_ROOT=1 {base}/bin/dhu-backup "
                  "cat <path> > <origin>\n",
    },
    "log lib/notes.md": {
        "rc": 0,
        "stdout": "lib/notes.md  [repo]\n"
                  "  origin: /Users/fixture/Projects/demo/lib/notes.md\n"
                  "  2026-09-01T22:10:00         6 bytes  0000000000aa  "
                  "{base}/store/repo/demo-aaaaaaaa/lib/"
                  "@1788300600000000000-0000000000aa/notes.md\n",
    },
    "log lib/heartbeat.ts": {
        "rc": 1,
        "stdout": "ERROR 'lib/heartbeat.ts' matches 2 paths; narrow it:\n"
                  "    lib/heartbeat.ts  [repo]\n"
                  "    lib/heartbeat.ts  [worktrees]\n",
    },
    "log heartbeat": {
        "rc": 1,
        "stdout": "ERROR 'heartbeat' matches 2 paths; narrow it:\n"
                  "    lib/heartbeat.ts  [repo]\n"
                  "    lib/heartbeat.ts  [worktrees]\n",
    },
    "log nomatch": {
        "rc": 1,
        "stdout": "ERROR no readable versions match 'nomatch'\n",
    },
}


class HelperCliTests(FixtureCase):
    def helper(self, *argv):
        env = dict(os.environ, TZ="UTC")
        return subprocess.run(
            [PYTHON, "-E", "-s", "-S", HELPER, "--install-root", self.install_root]
            + list(argv), capture_output=True, text=True, env=env)

    def test_the_text_output_of_ls_and_log_is_BYTE_IDENTICAL_to_before(self):
        for key, want in sorted(GOLDEN.items()):
            done = self.helper(*key.split(" "))
            self.assertEqual(done.stdout, want["stdout"].replace("{base}", self.install_root),
                             "text output of %r changed" % key)
            self.assertEqual(done.stderr, "", key)
            self.assertEqual(done.returncode, want["rc"], key)

    def test_json_mode_returns_the_same_exit_codes_as_text_mode(self):
        for key, want in sorted(GOLDEN.items()):
            done = self.helper(*(key.split(" ") + ["--json"]))
            self.assertEqual(done.returncode, want["rc"], key)
            json.loads(done.stdout)          # parseable, always

    def test_ls_json_carries_health_and_the_matches(self):
        payload = json.loads(self.helper("ls", "heartbeat", "--json").stdout)
        self.assertEqual(payload["health"]["verdict"], "ok")
        self.assertTrue(payload["health"]["detail"])
        self.assertEqual(payload["store_paths"], 4)
        self.assertEqual([m["root_id"] for m in payload["matches"]], ["repo", "worktrees"])
        self.assertEqual(payload["matches"][0]["versions"], 3)
        self.assertEqual(payload["matches"][0]["newest_iso"], "2026-09-01T22:20:00")

    def test_log_json_carries_health_and_every_version(self):
        payload = json.loads(self.helper("log", "lib/notes.md", "--json").stdout)
        self.assertEqual(payload["health"]["verdict"], "ok")
        self.assertEqual(payload["kind"], "ok")
        self.assertEqual(payload["origin"], FIXTURE_REPO + "/lib/notes.md")
        self.assertEqual(len(payload["versions"]), 1)
        self.assertEqual(payload["versions"][0]["sha"], "0000000000aa")

    def test_log_json_reports_ambiguity_as_data_rather_than_prose(self):
        payload = json.loads(self.helper("log", "heartbeat", "--json").stdout)
        self.assertEqual(payload["kind"], "ambiguous")
        self.assertEqual(len(payload["candidates"]), 2)

    def test_missing_json_carries_health_and_the_status(self):
        payload = json.loads(
            self.helper("missing", FIXTURE_REPO + "/lib/heartbeat.ts", "--json").stdout)
        self.assertEqual(payload["status"], "held")
        self.assertEqual(payload["health"], "ok")
        self.assertEqual(len(payload["versions"]), 3)

    def test_missing_uses_the_same_three_exit_codes_as_the_library(self):
        cases = [(FIXTURE_REPO + "/lib/heartbeat.ts", 0), (FIXTURE_REPO + "/lib", 0),
                 (FIXTURE_REPO + "/lib/gone.ts", 1), ("/etc/hosts", 1),
                 (FIXTURE_REPO + "/.env.local", 1)]
        for path, code in cases:
            self.assertEqual(self.helper("missing", path).returncode, code, path)
            self.assertEqual(self.helper("missing", path, "--json").returncode, code, path)

    def test_a_degraded_daemon_banners_in_TEXT_mode_and_is_a_FIELD_in_json_mode(self):
        """The banner is prose; in JSON it has to travel as data or it is dropped."""
        write_state(self.install_root, {"state": "degraded", "degraded_reason": "store-ceiling",
                                        "last_scan_epoch": int(time.time())})
        text = self.helper("ls", "heartbeat")
        self.assertTrue(text.stdout.startswith("!! CAPTURE STOPPED (store-ceiling)"))
        payload = json.loads(self.helper("ls", "heartbeat", "--json").stdout)
        self.assertEqual(payload["health"]["verdict"], "degraded")
        self.assertIn("store-ceiling", payload["health"]["detail"])

    def test_json_output_stays_parseable_when_the_store_is_gone(self):
        shutil.rmtree(os.path.join(self.install_root, "store"))
        for argv in (["ls", "--json"], ["log", "x", "--json"]):
            done = self.helper(*argv)
            self.assertEqual(done.returncode, 2, argv)
            self.assertIn("store-not-found", json.dumps(json.loads(done.stdout)))


# ── D: the MCP server over stdio ──────────────────────────────────────────────


class McpToolAnnotationTests(unittest.TestCase):
    """Every tool declares all four `ToolAnnotations` hints, and they are TRUE.

    Found by an external MCP index, and the omission was not cosmetic. The
    schema's defaults are `destructiveHint: true` and `openWorldHint: true`, so
    a tool that ships no annotations advertises itself as possibly destructive
    and possibly reaching an open world. Four of these six are strictly
    read-only and were saying the opposite by saying nothing.

    The second test is the one that matters over time. Anyone can keep a list of
    which tools are read-only in sync with the truth for a while; this asserts
    it against the CODE, by reading each dispatched handler's own source for a
    call into a writing path. A handler that starts restoring files while still
    declaring `readOnlyHint: true` fails here without anyone remembering to
    update a list.
    """

    #: Helper entry points that write to the caller's filesystem.
    WRITING_CALLS = ("command_restore", "command_restore_dir", "_run_capturing")

    def setUp(self):
        spec = importlib.util.spec_from_file_location("dhu_backup_mcp_annotations", MCP)
        self.mcp = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mcp)

    def test_every_tool_has_a_human_readable_title(self):
        for tool in self.mcp.TOOLS:
            self.assertTrue(tool.get("title"), "%s has no title" % tool["name"])
            self.assertNotEqual(tool["title"], tool["name"])

    def test_the_server_ships_instructions_that_teach_the_key_distinction(self):
        """`InitializeResult.instructions` is Property 4 at the protocol level.

        The spec describes it as a hint a client MAY put in the model's system
        prompt, so it is the one place this server can speak BEFORE a read has
        failed. Two things are asserted rather than left to prose drift: that it
        names the tool to reach for, and that it carries the store-unavailable
        distinction, which is the single misreading that would cost someone
        recoverable work.
        """
        text = self.mcp.INSTRUCTIONS
        self.assertIn("dhu_backup_missing", text)
        self.assertIn("store-unavailable", text)
        self.assertNotIn("no versions\" is the same", text)

    def test_output_schema_is_omitted_as_a_recorded_decision(self):
        """Absence must be a decision, not a default nobody examined.

        That is the whole lesson of the annotations miss, so the omission of
        `outputSchema` is pinned here: if a tool ever gains one, this test
        fails and whoever added it has to confirm the MUST-conform promise
        holds on every failure path too.
        """
        for tool in self.mcp.TOOLS:
            self.assertNotIn("outputSchema", tool, tool["name"])
        source = open(MCP).read()
        self.assertIn("outputSchema", source,
                      "the reason for omitting outputSchema must be written down")

    def test_every_tool_sets_all_four_hints_explicitly(self):
        for tool in self.mcp.TOOLS:
            annotations = tool.get("annotations")
            self.assertIsNotNone(annotations, "%s has no annotations" % tool["name"])
            for hint in ("readOnlyHint", "destructiveHint", "idempotentHint",
                         "openWorldHint"):
                self.assertIn(hint, annotations, "%s is missing %s" % (tool["name"], hint))
                self.assertIsInstance(annotations[hint], bool,
                                      "%s.%s must be a bool" % (tool["name"], hint))

    def test_a_read_only_claim_is_checked_against_the_handler_source(self):
        for tool in self.mcp.TOOLS:
            handler = self.mcp.DISPATCH[tool["name"]]
            source = inspect.getsource(handler)
            writes = [call for call in self.WRITING_CALLS if call in source]
            claims_read_only = tool["annotations"]["readOnlyHint"]
            if claims_read_only:
                self.assertEqual(
                    writes, [],
                    "%s declares readOnlyHint=True but its handler calls %s"
                    % (tool["name"], ", ".join(writes)))
            else:
                self.assertTrue(
                    writes,
                    "%s declares readOnlyHint=False but its handler calls no "
                    "writing path — either the hint or the handler is wrong"
                    % tool["name"])

    def test_a_writing_tool_is_never_marked_additive_only(self):
        """`destructiveHint: false` promises only additive updates.

        Both writers accept `overwrite`, which replaces a file at the origin, so
        the honest declaration is that they MAY be destructive. A hint a client
        might use to decide whether to ask a human first should describe the
        capability, not the common case.
        """
        for tool in self.mcp.TOOLS:
            if not tool["annotations"]["readOnlyHint"]:
                self.assertTrue(tool["annotations"]["destructiveHint"], tool["name"])
            self.assertFalse(tool["annotations"]["openWorldHint"],
                             "%s reaches only the local store" % tool["name"])


class McpServerTests(FixtureCase):
    def converse(self, messages):
        """Send newline-delimited JSON-RPC in, collect the responses."""
        env = dict(os.environ, TZ="UTC")
        done = subprocess.run(
            [PYTHON, "-E", "-s", "-S", MCP, "--install-root", self.install_root],
            input="".join(json.dumps(m) + "\n" for m in messages),
            capture_output=True, text=True, env=env)
        responses = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
        return done, responses

    @staticmethod
    def call(request_id, name, arguments=None):
        return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                "params": {"name": name, "arguments": arguments or {}}}

    def test_initialize_reports_the_protocol_version_and_the_server_name(self):
        done, responses = self.converse([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        ])
        self.assertEqual(done.returncode, 0)
        self.assertEqual(len(responses), 1, "a notification must not be answered")
        result = responses[0]["result"]
        self.assertEqual(result["protocolVersion"], "2025-06-18")
        self.assertEqual(result["capabilities"], {"tools": {}})
        self.assertEqual(result["serverInfo"]["name"], "dhu-backup")
        self.assertTrue(result["serverInfo"]["version"])

    def test_tools_list_returns_seven_tools_each_with_a_schema(self):
        _done, responses = self.converse([{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}])
        tools = responses[0]["result"]["tools"]
        self.assertEqual([t["name"] for t in tools],
                         ["dhu_backup_status", "dhu_backup_missing", "dhu_backup_ls",
                          "dhu_backup_log", "dhu_backup_cat", "dhu_backup_restore",
                          "dhu_backup_restore_dir"])
        for tool in tools:
            self.assertTrue(tool["description"])
            self.assertEqual(tool["inputSchema"]["type"], "object")
            self.assertIn("properties", tool["inputSchema"])
        required = {t["name"]: t["inputSchema"].get("required", []) for t in tools}
        self.assertEqual(required["dhu_backup_ls"], [])
        self.assertEqual(required["dhu_backup_restore_dir"], ["directory"])

    def test_request_ids_are_echoed_including_a_string_id(self):
        _done, responses = self.converse([
            {"jsonrpc": "2.0", "id": 7, "method": "ping"},
            {"jsonrpc": "2.0", "id": "abc", "method": "tools/list"},
        ])
        self.assertEqual([r["id"] for r in responses], [7, "abc"])
        self.assertTrue(all(r["jsonrpc"] == "2.0" for r in responses))

    def test_an_unknown_method_is_a_minus_32601(self):
        _done, responses = self.converse([{"jsonrpc": "2.0", "id": 1, "method": "no/such"}])
        self.assertEqual(responses[0]["error"]["code"], -32601)
        self.assertNotIn("result", responses[0])

    def test_an_unknown_tool_and_a_missing_argument_are_minus_32602(self):
        _done, responses = self.converse([
            self.call(1, "dhu_backup_nope"),
            self.call(2, "dhu_backup_missing"),
        ])
        self.assertEqual([r["error"]["code"] for r in responses], [-32602, -32602])

    def test_unparseable_input_is_a_minus_32700_and_does_not_kill_the_server(self):
        env = dict(os.environ, TZ="UTC")
        done = subprocess.run(
            [PYTHON, "-E", "-s", "-S", MCP, "--install-root", self.install_root],
            input="{not json\n" + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}) + "\n",
            capture_output=True, text=True, env=env)
        responses = [json.loads(line) for line in done.stdout.splitlines() if line.strip()]
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["id"], 2)
        self.assertEqual(done.returncode, 0)

    def test_the_server_exits_cleanly_on_EOF(self):
        done, _responses = self.converse([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stderr, "")

    def test_every_read_only_tool_answers_and_carries_the_daemon_health(self):
        _done, responses = self.converse([
            self.call(1, "dhu_backup_missing", {"path": FIXTURE_REPO + "/lib/heartbeat.ts"}),
            self.call(2, "dhu_backup_ls", {"substring": "heartbeat"}),
            self.call(3, "dhu_backup_log", {"path": "lib/notes.md"}),
            self.call(4, "dhu_backup_cat", {"path": "lib/notes.md"}),
        ])
        self.assertEqual([r["id"] for r in responses], [1, 2, 3, 4])
        for response in responses:
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["content"][0]["type"], "text")
            # The text block and the structured block are the same object.
            self.assertEqual(json.loads(result["content"][0]["text"]),
                             result["structuredContent"])
            health = result["structuredContent"]["health"]
            verdict = health if isinstance(health, str) else health["verdict"]
            self.assertIn(verdict, dhu_backup_core.HEALTH_VERDICTS)

        missing, listing, log, cat = [r["result"]["structuredContent"] for r in responses]
        self.assertEqual(missing["status"], "held")
        self.assertEqual(len(missing["versions"]), 3)
        self.assertEqual(len(listing["matches"]), 2)
        self.assertEqual(len(log["versions"]), 1)
        self.assertEqual(cat["content"], "notes\n")
        self.assertEqual(cat["encoding"], "utf-8")

    def test_cat_resolves_asof_and_never_falls_back_to_the_newest(self):
        _done, responses = self.converse([
            self.call(1, "dhu_backup_cat",
                      {"path": "lib/heartbeat.ts", "root_id": "repo",
                       "version": "@%019d-000000000001" % T0}),
            self.call(2, "dhu_backup_cat",
                      {"path": "lib/heartbeat.ts", "root_id": "repo",
                       "version": "@0000000000000000001-ffffffffffff"}),
        ])
        first, absent = [r["result"]["structuredContent"] for r in responses]
        self.assertEqual(first["content"], "one\n")
        self.assertEqual(absent["kind"], "no-version")
        self.assertNotIn("content", absent)

    def test_cat_returns_base64_and_SAYS_SO_for_content_that_is_not_utf8(self):
        directory = os.path.join(self.install_root, "store", "repo", "demo-aaaaaaaa", "lib",
                                 "@%019d-0000000000dd" % T1)
        os.makedirs(directory, 0o755)
        with open(os.path.join(directory, "blob.bin"), "wb") as handle:
            handle.write(b"\xff\xfe\x00\x01")
        _done, responses = self.converse([self.call(1, "dhu_backup_cat", {"path": "blob.bin"})])
        payload = responses[0]["result"]["structuredContent"]
        self.assertEqual(payload["encoding"], "base64")
        self.assertEqual(payload["content"], "//4AAQ==")

    def test_a_tool_whose_store_is_gone_is_marked_isError_not_answered_as_empty(self):
        shutil.rmtree(os.path.join(self.install_root, "store"))
        _done, responses = self.converse([
            self.call(1, "dhu_backup_missing", {"path": FIXTURE_REPO + "/lib/heartbeat.ts"}),
            self.call(2, "dhu_backup_ls", {}),
        ])
        for response in responses:
            self.assertTrue(response["result"]["isError"])
        self.assertEqual(responses[0]["result"]["structuredContent"]["status"],
                         "store-unavailable")

    def test_a_vaulted_path_is_reported_vaulted_through_the_tool_too(self):
        _done, responses = self.converse([
            self.call(1, "dhu_backup_missing", {"path": FIXTURE_REPO + "/.env.local"})])
        payload = responses[0]["result"]["structuredContent"]
        self.assertEqual(payload["status"], "vaulted")
        self.assertTrue(all(c.startswith("sudo ") for c in payload["commands"]))


class VaultReadingTests(FixtureCase):
    """`load_entries` reads `vault/` only for root that opted in.

    The tests cannot BE root, so the entitlement decision is proven purely in
    `TreesToReadTests` and what is proven here is the wiring: given the answer
    `("store", "vault")`, the walk finds vault entries, tags them, and marks
    them in the text output. The fixture's vault is readable by the test user,
    which is exactly why the entitlement is a separate pure function rather than
    an `os.access` check that would pass here and mean nothing.
    """

    def setUp(self):
        super(VaultReadingTests, self).setUp()
        self.helper = load_helper_module()
        vault_dir = os.path.join(self.install_root, "vault", "repo", "demo-aaaaaaaa",
                                 "@%019d-0000000000ee" % T1)
        os.makedirs(vault_dir, 0o755)
        with open(os.path.join(vault_dir, ".env.local"), "w") as handle:
            handle.write("SECRET=1\n")

    def entries(self, trees):
        original = self.helper.trees_this_process_may_read
        self.helper.trees_this_process_may_read = lambda: trees
        try:
            return self.helper.load_entries(self.install_root)
        finally:
            self.helper.trees_this_process_may_read = original

    def test_store_only_never_returns_the_vaulted_path(self):
        entries, error = self.entries(("store",))
        self.assertIsNone(error)
        self.assertNotIn(".env.local", [e["relpath"] for e in entries])
        self.assertTrue(all(e["tree"] == "store" for e in entries))

    def test_store_and_vault_returns_it_tagged_with_the_tree_it_came_from(self):
        entries, error = self.entries(("store", "vault"))
        self.assertIsNone(error)
        vaulted = [e for e in entries if e["relpath"] == ".env.local"]
        self.assertEqual(len(vaulted), 1)
        self.assertEqual(vaulted[0]["tree"], "vault")
        self.assertEqual(vaulted[0]["watch_root"], FIXTURE_REPO)
        self.assertEqual(len(vaulted[0]["versions"]), 1)

    def test_a_missing_vault_directory_is_not_an_error(self):
        shutil.rmtree(os.path.join(self.install_root, "vault"))
        entries, error = self.entries(("store", "vault"))
        self.assertIsNone(error)
        self.assertEqual(len(entries), 4)

    def test_a_missing_store_is_still_an_error_even_with_the_vault_present(self):
        shutil.rmtree(os.path.join(self.install_root, "store"))
        entries, error = self.entries(("store", "vault"))
        self.assertIsNone(entries)
        self.assertIn("store-not-found", error)

    def test_ls_marks_a_vault_entry_and_leaves_store_lines_untouched(self):
        import contextlib
        import io as _io

        args = self.helper.argparse.Namespace(
            install_root=self.install_root, root_id=None, substring="env", json=False,
            quiet=True)
        original = self.helper.trees_this_process_may_read
        self.helper.trees_this_process_may_read = lambda: ("store", "vault")
        captured = _io.StringIO()
        try:
            with contextlib.redirect_stdout(captured):
                code = self.helper.command_ls(args)
        finally:
            self.helper.trees_this_process_may_read = original
        self.assertEqual(code, 0)
        self.assertIn(".env.local", captured.getvalue())
        self.assertTrue(captured.getvalue().rstrip().endswith("  [vault]"))


class RestoreRefusesRootTests(FixtureCase):
    """`restore` and `restore-dir` refuse root, opt-in or not.

    Driven by faking the euid rather than by becoming root: the point under test
    is that the pure predicate is WIRED IN, and the predicate itself is proven
    over fabricated euids in `RestorePermittedTests`. Nothing here writes a file,
    which is the same rule the rest of this repo follows — a destructive sink is
    never fired to prove its guard.
    """

    def setUp(self):
        super(RestoreRefusesRootTests, self).setUp()
        self.helper = load_helper_module()

    def as_root(self, function, args):
        import contextlib
        import io as _io

        original = self.helper.os.geteuid
        self.helper.os.geteuid = lambda: 0
        captured = _io.StringIO()
        try:
            with contextlib.redirect_stdout(captured):
                code = function(args)
        finally:
            self.helper.os.geteuid = original
        return code, captured.getvalue()

    def args(self, **kwargs):
        base = dict(install_root=self.install_root, root_id=None, json=False, quiet=True,
                    path="lib/notes.md", directory="lib", asof=None, version=None,
                    into=None, overwrite=False)
        base.update(kwargs)
        return self.helper.argparse.Namespace(**base)

    def test_restore_refuses_as_root_and_writes_nothing(self):
        code, output = self.as_root(self.helper.command_restore, self.args())
        self.assertEqual(code, 2)
        self.assertIn("restore never runs as root", output)
        self.assertIn("cat", output)
        self.assertFalse(os.path.exists(FIXTURE_REPO + "/lib/notes.md"))

    def test_restore_dir_refuses_as_root_too(self):
        code, output = self.as_root(self.helper.command_restore_dir, self.args())
        self.assertEqual(code, 2)
        self.assertIn("restore never runs as root", output)

    def test_the_opt_in_variable_does_NOT_unlock_restore(self):
        os.environ["DHU_BACKUP_ALLOW_ROOT"] = "1"
        try:
            code, output = self.as_root(self.helper.command_restore, self.args())
        finally:
            del os.environ["DHU_BACKUP_ALLOW_ROOT"]
        self.assertEqual(code, 2)
        self.assertIn("restore never runs as root", output)


class SourceInvariantTests(unittest.TestCase):
    """Properties of the new code that are cheaper to assert than to review."""

    def test_nothing_added_here_imports_subprocess_or_shells_out(self):
        """The daemon's rule (H2/H3): no user-owned binary is ever executed.

        These two files are installed root-owned beside the daemon's code, so a
        `subprocess` call in either would be a new place for an agent-writable
        binary to be found on PATH.
        """
        for name in ("dhu_backup_announce.py", "dhu-backup-mcp.py"):
            with open(os.path.join(SRC, name)) as handle:
                source = handle.read()
            for forbidden in ("import subprocess", "os.system", "os.popen", "os.exec"):
                self.assertNotIn(forbidden, source, "%s must not use %s" % (name, forbidden))

    def test_the_announce_module_never_calls_realpath(self):
        """C7/C8: resolve-then-check is the race, and a symlink in the agent's
        own tree would otherwise steer the lookup at another watch root."""
        for name in ("dhu_backup_announce.py",):
            with open(os.path.join(SRC, name)) as handle:
                source = handle.read()
            for forbidden in ("realpath", "os.path.abspath(abs_path)"):
                self.assertNotIn(forbidden, source)

    def test_the_installer_installs_both_new_files(self):
        # install.sh carries what it installs as a `<mode> <source> <dest>`
        # table, read by both the --dry-run plan printer and the install itself.
        with open(os.path.join(SRC, "install.sh")) as handle:
            source = handle.read()
        self.assertIn('"$DEST/bin/dhu_backup_announce.py"', source)
        self.assertIn('"$DEST/bin/dhu-backup-mcp"', source)
        # The announce library must stay 0644 and the server 0755, both root.
        self.assertRegex(
            source, r"(?m)^0644\s+dhu_backup_announce\.py\s+bin/dhu_backup_announce\.py\s*$"
        )
        self.assertRegex(source, r"(?m)^0755\s+dhu-backup-mcp\.py\s+bin/dhu-backup-mcp\s*$")
        # `-g 0` rather than `-g wheel`: gid 0 is root's group on BOTH platforms,
        # and `wheel` is not a group name on Ubuntu. The property being asserted
        # is unchanged — everything the daemon executes is installed root-owned.
        self.assertRegex(source, r'install -o root -g 0 -m "\$_mode"')


# ── E: the `warning` state, end to end on every surface ───────────────────────


WARNING_STATE = {
    "state": "warning",
    "warning_reason": ["free-space-low"],
    "warning_detail": "12.0 GiB free, and capture stops at 10.0 GiB",
    "free_bytes": 12884901888, "min_free_bytes": 10737418240,
    "files_scanned": 4, "store_bytes": 100, "watch_roots": 2,
}


def warning_state(**overrides):
    state = dict(WARNING_STATE, last_scan_epoch=int(time.time()))
    state.update(overrides)
    return state


class WarningSurfaceTests(FixtureCase):
    """`warning` has to arrive on every surface the other states arrive on.

    A state that only the heartbeat knows about is a state nobody reads. These
    are the four places a human or an agent actually learns the daemon's health:
    the helper's banner, `--json`, the announcement renderer and the MCP tools.
    """

    def helper(self, *argv):
        env = dict(os.environ, TZ="UTC")
        return subprocess.run(
            [PYTHON, "-E", "-s", "-S", HELPER, "--install-root", self.install_root]
            + list(argv), capture_output=True, text=True, env=env)

    def test_the_helper_banners_the_warning_before_the_answer(self):
        write_state(self.install_root, warning_state())
        done = self.helper("ls", "heartbeat")
        self.assertTrue(done.stdout.startswith("!! CAPTURE WILL STOP (free-space-low)"),
                        done.stdout[:200])
        self.assertIn("12.0 GiB free", done.stdout)
        # The answer still comes, because capture is still running.
        self.assertIn("heartbeat.ts", done.stdout)
        self.assertEqual(done.returncode, 0)

    def test_a_warning_is_a_FIELD_in_json_mode_and_never_a_printed_line(self):
        write_state(self.install_root, warning_state())
        done = self.helper("ls", "heartbeat", "--json")
        payload = json.loads(done.stdout)          # would raise on a prose banner
        self.assertEqual(payload["health"]["verdict"], "warning")
        self.assertIn("12.0 GiB", payload["health"]["detail"])

    def test_both_reasons_reach_the_banner(self):
        write_state(self.install_root, warning_state(
            warning_reason=["free-space-low", "store-nearly-full"]))
        done = self.helper("ls", "heartbeat")
        self.assertIn("free-space-low,store-nearly-full", done.stdout)

    def test_a_warning_with_no_detail_recorded_still_banners(self):
        state = warning_state()
        del state["warning_detail"]
        write_state(self.install_root, state)
        done = self.helper("ls", "heartbeat")
        self.assertIn("CAPTURE WILL STOP", done.stdout)
        self.assertEqual(done.stderr, "")

    def test_the_announcement_renderer_prints_the_note_above_the_result(self):
        write_state(self.install_root, warning_state())
        result = dhu_backup_announce.announce(FIXTURE_REPO + "/lib/heartbeat.ts",
                                              install_root=self.install_root)
        self.assertEqual(result.health, "warning")
        text = dhu_backup_announce.format_text(result)
        self.assertTrue(text.startswith("!! CAPTURE WILL STOP"), text[:120])
        self.assertIn("HELD", text)

    def test_a_warning_does_not_change_what_the_lookup_FINDS(self):
        """It is a report about the daemon, never a verdict about the file."""
        write_state(self.install_root, warning_state())
        warned = dhu_backup_announce.announce(FIXTURE_REPO + "/lib/heartbeat.ts",
                                              install_root=self.install_root)
        write_state(self.install_root, fresh_ok_state())
        healthy = dhu_backup_announce.announce(FIXTURE_REPO + "/lib/heartbeat.ts",
                                               install_root=self.install_root)
        self.assertEqual(warned.status, healthy.status)
        self.assertEqual(len(warned.versions), len(healthy.versions))
        self.assertNotEqual(warned.health, healthy.health)

    def test_a_not_held_file_under_a_warning_still_says_the_daemon_is_warning(self):
        """The renderer is not the hook: asked directly, it always reports health."""
        write_state(self.install_root, warning_state())
        result = dhu_backup_announce.announce(FIXTURE_REPO + "/lib/gone.ts",
                                              install_root=self.install_root)
        self.assertEqual(result.status, "not-held")
        self.assertEqual(result.health, "warning")
        self.assertIn("CAPTURE WILL STOP", dhu_backup_announce.format_text(result))

    def test_every_health_verdict_has_a_note_in_the_renderer(self):
        """`ok` is the only verdict with no note, because it has nothing to say."""
        noted = set(dhu_backup_announce._HEALTH_NOTE)
        self.assertEqual(set(dhu_backup_core.HEALTH_VERDICTS) - noted, {"ok"})
        self.assertIn("warning", noted)


class WarningMcpToolTests(FixtureCase):
    """The MCP tools carry the verdict on every result, `warning` included.

    A separate class rather than a subclass of `McpServerTests`: inheriting that
    class would re-run its whole suite under a second name, and a suite that
    counts the same assertions twice is a count nobody can reason about.
    """

    def converse(self, messages):
        done = subprocess.run(
            [PYTHON, "-E", "-s", "-S", MCP, "--install-root", self.install_root],
            input="".join(json.dumps(m) + "\n" for m in messages),
            capture_output=True, text=True, env=dict(os.environ, TZ="UTC"))
        return [json.loads(line) for line in done.stdout.splitlines() if line.strip()]

    @staticmethod
    def call(request_id, name, arguments):
        return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}}

    @staticmethod
    def verdict_of(payload):
        """`health` is a dict on the helper-backed tools and the verdict string
        on the announcement-backed ones. Both shapes predate this change."""
        health = payload["health"]
        return health["verdict"] if isinstance(health, dict) else health

    def test_every_tool_result_carries_the_warning_verdict(self):
        write_state(self.install_root, warning_state())
        responses = self.converse([
            self.call(1, "dhu_backup_ls", {"substring": "heartbeat"}),
            self.call(2, "dhu_backup_log", {"path": "lib/heartbeat.ts"}),
            self.call(3, "dhu_backup_missing", {"path": FIXTURE_REPO + "/lib/gone.ts"}),
        ])
        self.assertEqual(len(responses), 3)
        for response in responses:
            payload = json.loads(response["result"]["content"][0]["text"])
            self.assertEqual(self.verdict_of(payload), "warning", payload)

    def test_the_same_tools_say_ok_on_a_healthy_daemon(self):
        """The control: the field is reporting the heartbeat, not a constant."""
        write_state(self.install_root, fresh_ok_state())
        responses = self.converse([
            self.call(1, "dhu_backup_ls", {"substring": "heartbeat"}),
            self.call(2, "dhu_backup_missing", {"path": FIXTURE_REPO + "/lib/gone.ts"}),
        ])
        for response in responses:
            payload = json.loads(response["result"]["content"][0]["text"])
            self.assertEqual(self.verdict_of(payload), "ok", payload)


# ── `dhu-backup status`: the everyday question ────────────────────────────────


class HealthSentenceTests(unittest.TestCase):
    """One health vocabulary, not two.

    `status` says the same words about a stopped daemon that a failed read
    says. A second wording would be a second answer to the same question, and
    the day the two disagreed the reader would believe the friendlier one.
    """

    def test_every_health_verdict_has_a_sentence(self):
        for verdict in dhu_backup_core.HEALTH_VERDICTS:
            self.assertTrue(dhu_backup_announce.health_sentence(verdict), verdict)

    def test_the_sentences_are_the_announce_vocabulary_verbatim(self):
        for verdict, note in dhu_backup_announce._HEALTH_NOTE.items():
            self.assertEqual(dhu_backup_announce.health_sentence(verdict), note, verdict)

    def test_ok_is_deliberately_absent_from_the_hot_path_table(self):
        """`format_text` prints a `_HEALTH_NOTE` entry the moment it finds one.

        An `ok` entry there would hang a banner over every announcement that
        has nothing wrong with it, so the ok sentence lives beside the table
        instead of in it.
        """
        self.assertNotIn("ok", dhu_backup_announce._HEALTH_NOTE)
        self.assertEqual(dhu_backup_announce.health_sentence("ok"),
                         dhu_backup_announce.HEALTH_OK_SENTENCE)

    def test_an_unknown_verdict_raises_rather_than_saying_nothing(self):
        with self.assertRaises(ValueError):
            dhu_backup_announce.health_sentence("brand-new-state")


class ReadStateTests(FixtureCase):
    """The verdict and the numbers come out of ONE read of the heartbeat."""

    def test_it_returns_both_the_raw_state_and_the_verdict(self):
        state, health = dhu_backup_announce.read_state(self.install_root, time.time())
        self.assertEqual(health.verdict, "ok")
        self.assertEqual(state["files_scanned"], 4)

    def test_a_missing_heartbeat_gives_no_state_and_a_report(self):
        write_state(self.install_root, None)
        state, health = dhu_backup_announce.read_state(self.install_root, time.time())
        self.assertIsNone(state)
        self.assertEqual(health.verdict, "no-heartbeat")

    def test_read_health_is_the_same_function(self):
        """Kept as one implementation so the two cannot drift."""
        health = dhu_backup_announce._read_health(self.install_root, time.time())
        self.assertEqual(health, dhu_backup_announce.read_state(
            self.install_root, time.time())[1])


class StatusPayloadTests(FixtureCase):
    """The data `status` reports, against a fabricated install root."""

    def setUp(self):
        super(StatusPayloadTests, self).setUp()
        self.helper = load_helper_module()
        self.write_watchlist("repo        %s\nworktrees   %s\n"
                             % (FIXTURE_REPO, FIXTURE_WORKTREE))

    def write_watchlist(self, text):
        path = os.path.join(self.install_root, "etc", "watchlist.conf")
        with open(path, "w") as handle:
            handle.write(text)

    def payload(self, **kwargs):
        return self.helper.status_payload(self.install_root, platform_string="darwin",
                                          **kwargs)

    def test_a_healthy_install_reports_capturing_and_exits_zero(self):
        payload = self.payload()
        self.assertEqual(payload["health"]["verdict"], "ok")
        self.assertTrue(payload["capturing"])
        self.assertEqual(payload["exit_code"], 0)
        self.assertIsNone(payload["next_step"]["command"])

    def test_it_counts_PATHS_not_versions(self):
        """`lib/heartbeat.ts` has three versions in the fixture and counts once.

        The number is read as "how much of my work is in there", and
        versions-per-path is a retention setting, not an amount of work.
        """
        roots = {r["root_id"]: r for r in self.payload()["watch_roots"]["configured"]}
        self.assertEqual(roots["repo"]["paths_held"], 3)
        self.assertFalse(roots["repo"]["paths_held_capped"])
        self.assertEqual(roots["worktrees"]["paths_held"], 1)

    def test_a_spent_budget_reports_at_least_rather_than_a_wrong_number(self):
        payload = self.payload(budget=1)
        roots = {r["root_id"]: r for r in payload["watch_roots"]["configured"]}
        self.assertTrue(roots["repo"]["paths_held_capped"])
        self.assertLessEqual(roots["repo"]["paths_held"], 3)
        self.assertIn("at least", self.helper.format_status(payload))

    def test_the_budget_is_handed_back_when_a_root_does_not_spend_it(self):
        """A first root with a small history must not burn the whole allowance.

        With a budget of 5 and four version directories under `repo`, the
        second root still has enough left to be counted exactly.
        """
        payload = self.payload(budget=6)
        roots = {r["root_id"]: r for r in payload["watch_roots"]["configured"]}
        self.assertFalse(roots["worktrees"]["paths_held_capped"])
        self.assertEqual(roots["worktrees"]["paths_held"], 1)

    def test_a_root_with_nothing_captured_yet_reports_zero_not_an_error(self):
        self.write_watchlist("fresh  /Users/fixture/brand-new\n")
        roots = self.payload()["watch_roots"]["configured"]
        self.assertEqual(roots[0]["paths_held"], 0)
        self.assertIsNone(roots[0]["error"])

    def test_an_unreadable_watchlist_is_reported_never_read_as_no_roots(self):
        """"I could not look" and "nothing is watched" are opposite claims."""
        os.unlink(os.path.join(self.install_root, "etc", "watchlist.conf"))
        payload = self.payload()
        self.assertIn("watchlist-unreadable", payload["watch_roots"]["error"])
        self.assertEqual(payload["watch_roots"]["configured"], [])
        self.assertIn("COULD NOT BE READ", self.helper.format_status(payload))

    def test_a_refused_watchlist_line_is_carried_not_dropped(self):
        self.write_watchlist("repo  %s\nBAD LINE HERE\n" % FIXTURE_REPO)
        payload = self.payload()
        self.assertEqual(len(payload["watch_roots"]["refused_lines"]), 1)
        self.assertIn("refused", self.helper.format_status(payload))

    def test_store_ids_the_watchlist_no_longer_names_are_reported_as_kept(self):
        """History for a root that was removed is KEPT and is not being added to.

        Saying nothing here is the difference between an operator believing
        their old repo is still protected and knowing that it is not.
        """
        self.write_watchlist("repo  %s\n" % FIXTURE_REPO)
        payload = self.payload()
        self.assertEqual(payload["watch_roots"]["unwatched_root_ids"], ["worktrees"])
        self.assertIn("no longer names", self.helper.format_status(payload))

    def test_the_budgets_come_from_the_heartbeat_not_from_the_defaults(self):
        """Raising `max_store_bytes` is the documented way out of DEGRADED.

        A status that measured headroom against the compiled-in default would
        print the wrong number on exactly the machine where somebody acted on
        the last one.
        """
        state = fresh_ok_state()
        state.update({"store_bytes": 100, "max_store_bytes": 1000,
                      "free_bytes": 900, "min_free_bytes": 400})
        write_state(self.install_root, state)
        payload = self.payload()
        self.assertEqual(payload["store"]["ceiling_bytes"], 1000)
        self.assertEqual(payload["store"]["headroom_bytes"], 900)
        self.assertEqual(payload["free_space"]["floor_bytes"], 400)
        self.assertEqual(payload["free_space"]["headroom_bytes"], 500)

    def test_an_unmeasured_free_space_is_said_rather_than_shown_as_zero(self):
        state = fresh_ok_state()
        state["free_bytes"] = None
        write_state(self.install_root, state)
        payload = self.payload()
        self.assertIsNone(payload["free_space"])
        self.assertIn("not measured this cycle", self.helper.format_status(payload))

    def test_a_warning_carries_its_reasons_and_what_is_left(self):
        state = fresh_ok_state()
        state.update({"state": "warning",
                      "warning_reason": ["free-space-low"],
                      "warning_detail": "11.0 GiB free, and capture stops at 10.0 GiB",
                      "store_bytes": 10, "free_bytes": 11 * 1024 ** 3})
        write_state(self.install_root, state)
        payload = self.payload()
        self.assertEqual(payload["health"]["verdict"], "warning")
        self.assertTrue(payload["capturing"])
        self.assertEqual(payload["exit_code"], 0)
        self.assertEqual(payload["warning"]["reasons"], ["free-space-low"])
        text = self.helper.format_status(payload)
        self.assertIn("capture stops at 10.0 GiB", text)
        self.assertIn("kickstart", text)          # the one command to type

    def test_a_degraded_daemon_exits_one_and_names_the_remedy(self):
        state = fresh_ok_state()
        state.update({"state": "degraded", "degraded_reason": "store-ceiling"})
        write_state(self.install_root, state)
        payload = self.payload()
        self.assertEqual(payload["exit_code"], 1)
        self.assertFalse(payload["capturing"])
        self.assertIn("store-ceiling", payload["health"]["detail"])
        self.assertIn("dhu-backupd.conf", payload["next_step"]["sentence"])

    def test_no_heartbeat_exits_two_because_the_status_is_UNKNOWN(self):
        write_state(self.install_root, None)
        payload = self.payload()
        self.assertEqual(payload["exit_code"], 2)
        self.assertEqual(payload["health"]["verdict"], "no-heartbeat")

    def test_glob_counts_appear_only_when_there_are_any(self):
        self.assertIsNone(self.payload()["exclusions"])
        state = fresh_ok_state()
        state.update({"exclude_globs": 2, "exclude_refused": 1,
                      "vault_extra_globs": 3, "vault_extra_refused": 0})
        write_state(self.install_root, state)
        payload = self.payload()
        self.assertEqual(payload["exclusions"], {"globs": 2, "refused": 1})
        self.assertEqual(payload["vault_extra"], {"globs": 3, "refused": 0})
        text = self.helper.format_status(payload)
        self.assertIn("2 glob(s) in force, 1 refused", text)

    def test_refused_globs_with_none_in_force_are_still_reported(self):
        """Every line the operator wrote was thrown out — the one case here
        worth printing, and the one a `if not globs` check would hide."""
        state = fresh_ok_state()
        state.update({"exclude_globs": 0, "exclude_refused": 4})
        write_state(self.install_root, state)
        self.assertEqual(self.payload()["exclusions"], {"globs": 0, "refused": 4})

    def test_it_never_raises_on_a_broken_install_root(self):
        for root in ("/nonexistent-xyz", "", None, 12):
            payload = self.helper.status_payload(root, platform_string="darwin")
            self.assertIn(payload["exit_code"], (1, 2), repr(root))
            self.assertTrue(self.helper.format_status(payload), repr(root))

    def test_a_garbled_heartbeat_is_unreadable_not_ok(self):
        write_state(self.install_root, "{not json")
        payload = self.payload()
        self.assertEqual(payload["health"]["verdict"], "unreadable-heartbeat")
        self.assertEqual(payload["exit_code"], 2)


class StatusCliTests(FixtureCase):
    """The subcommand, end to end, as a process."""

    def setUp(self):
        super(StatusCliTests, self).setUp()
        with open(os.path.join(self.install_root, "etc", "watchlist.conf"), "w") as handle:
            handle.write("repo  %s\n" % FIXTURE_REPO)

    def status(self, *argv):
        env = dict(os.environ, TZ="UTC")
        return subprocess.run(
            [PYTHON, "-E", "-s", "-S", HELPER, "--install-root", self.install_root,
             "status"] + list(argv), capture_output=True, text=True, env=env)

    def test_it_prints_a_verdict_a_root_and_the_budgets_and_exits_zero(self):
        done = self.status()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("dhu-backup:", done.stdout)
        self.assertIn("daemon       ok", done.stdout)
        self.assertIn("watch roots", done.stdout)
        self.assertIn("3 path(s) held", done.stdout)
        self.assertIn("store", done.stdout)
        self.assertEqual(done.stderr, "")

    def test_the_health_banner_is_not_printed_twice(self):
        """`status` states the health itself, in the same block as its answer.

        The banner as well said it twice in different words, which reads as two
        findings rather than one — the same reason `missing` suppresses it.
        """
        self.assertNotIn("!! ", self.status().stdout)

    def test_json_mode_prints_one_parseable_object_carrying_the_exit_code(self):
        done = self.status("--json")
        payload = json.loads(done.stdout)
        self.assertEqual(payload["exit_code"], done.returncode)
        self.assertEqual(payload["health"]["verdict"], "ok")
        self.assertTrue(payload["watch_roots"]["configured"])

    def test_the_exit_code_follows_the_daemon_and_not_the_command(self):
        """`status` succeeding while capture has stopped is a report nobody
        should be able to write a green monitor against."""
        write_state(self.install_root, dict(fresh_ok_state(), state="unprotected"))
        self.assertEqual(self.status().returncode, 1)
        write_state(self.install_root, None)
        self.assertEqual(self.status().returncode, 2)

    def test_it_needs_no_privilege_and_writes_nothing(self):
        before = sorted(os.listdir(os.path.join(self.install_root, "var")))
        self.status()
        self.assertEqual(sorted(os.listdir(os.path.join(self.install_root, "var"))), before)


class StatusMcpToolTests(FixtureCase):
    """The same answer, over MCP, with no second implementation behind it."""

    def setUp(self):
        super(StatusMcpToolTests, self).setUp()
        with open(os.path.join(self.install_root, "etc", "watchlist.conf"), "w") as handle:
            handle.write("repo  %s\n" % FIXTURE_REPO)

    def call_status(self):
        env = dict(os.environ, TZ="UTC")
        message = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "dhu_backup_status", "arguments": {}}}
        done = subprocess.run(
            [PYTHON, "-E", "-s", "-S", MCP, "--install-root", self.install_root],
            input=json.dumps(message) + "\n", capture_output=True, text=True, env=env)
        return json.loads(done.stdout.splitlines()[0])["result"]

    def test_it_returns_the_helper_payload_with_the_text_beside_it(self):
        result = self.call_status()
        payload = result["structuredContent"]
        self.assertEqual(payload["health"]["verdict"], "ok")
        self.assertEqual(payload["exit_code"], 0)
        self.assertIn("dhu-backup:", payload["text"])
        self.assertFalse(result["isError"])

    def test_a_stopped_daemon_is_an_ANSWER_and_not_a_protocol_error(self):
        """The answer the caller most needs must not arrive as an error a
        client might retry or drop."""
        write_state(self.install_root, dict(fresh_ok_state(), state="degraded",
                                            degraded_reason="store-ceiling"))
        result = self.call_status()
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["exit_code"], 1)

    def test_a_status_that_cannot_be_determined_is_an_error(self):
        write_state(self.install_root, None)
        result = self.call_status()
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["exit_code"], 2)

    def test_it_is_annotated_read_only(self):
        """Asserted here as well as in the annotation sweep, because this is the
        tool an agent is most likely to call unprompted."""
        spec = importlib.util.spec_from_file_location("dhu_backup_mcp_status", MCP)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        tool = [t for t in module.TOOLS if t["name"] == "dhu_backup_status"][0]
        self.assertEqual(tool["annotations"], module.READ_ONLY)


class FabricatedVersionShapeTests(FixtureCase):
    """A directory under a version-shaped name is not a version.

    An agent can name a directory in its own tree like a version key, and a
    store written before the walk refused that shape can hold it as a sibling
    of real versions. Listed as a version, its "leaf" is a directory: `log`
    showed a version dated in the future and `cat` opened a directory and
    raised. The reader now requires a regular file where the leaf should be.
    """

    def setUp(self):
        super(FabricatedVersionShapeTests, self).setUp()
        self.helper = load_helper_module()
        fake = os.path.join(self.install_root, "store", "repo", "demo-aaaaaaaa",
                            "@1800000000000000000-0123456789ab", "@%019d-0000000000ff" % T1)
        os.makedirs(fake, 0o755)
        with open(os.path.join(fake, "notes.md"), "w") as handle:
            handle.write("FAKE\n")

    def test_the_fabricated_entry_is_not_listed_and_real_entries_are_unchanged(self):
        entries, error = self.helper.load_entries(self.install_root)
        self.assertIsNone(error)
        self.assertEqual(len(entries), 4)
        for entry in entries:
            for version in entry["versions"]:
                self.assertTrue(os.path.isfile(version["path"]), version["path"])
                self.assertNotIn("@1800000000000000000", version["path"])
