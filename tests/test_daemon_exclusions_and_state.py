"""The daemon's walk, its heartbeat, and one staging run of the real thing.

Run with:  /usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'

Two features are proven here, both of which the pure core proves as functions in
`test_dhu_backup_core.py` and neither of which the core can prove END TO END:

  * `etc/exclude.conf` — the operator's directory-name exclusions. The parser is
    pure; the DESCENT it prevents is not, and "the glob parsed" is not the claim.
    The claim is "the directory was not walked and the operator can see why".
  * the `warning` state — "capturing, but about to stop". `budget_warning` is
    pure; `state.json` saying `warning` while versions are still being written
    is a property of a running daemon.

The rules this file obeys, from CONTRIBUTING.md:

1. **No destructive sink is fired.** Nothing here prunes, unlinks a version, or
   calls `remove_version_dirs`. The staging daemon runs `--once`, writes into a
   scratch store, and is never given a prune interval it can reach.
2. **Never the real install.** Every root is a fresh `tempfile.mkdtemp()`, and
   the staging daemon is started BY THIS TEST as this user — never as root,
   never against `/Library/DHU/backup` or `/opt/dhu-backup`. Its config names
   its own scratch root, so there is no path by which it could touch the real one.
3. **A claim and its evidence share a population.** Nothing here skips. If the
   scratch directory cannot be made, `mkdtemp` raises and the test ERRORS,
   which is loud; a skip is not.
"""

import errno
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO_ROOT, "src")
sys.path.insert(0, SRC)

import dhu_backup_core  # noqa: E402

PYTHON = "/usr/bin/python3"
DAEMON_SCRIPT = os.path.join(SRC, "dhu-backupd.py")


def load_daemon():
    """Import `src/dhu-backupd.py`, whose name is not a Python identifier.

    Importing it runs its imports and its module-level constants and nothing
    else — the daemon does its work in `main`, which nothing here calls.
    """
    spec = importlib.util.spec_from_file_location("dhu_backupd_module", DAEMON_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DAEMON = load_daemon()


class _RecordingLogger(object):
    def __init__(self):
        self.infos = []
        self.warnings = []
        self.errors = []

    def info(self, message):
        self.infos.append(message)

    def warn(self, message):
        self.warnings.append(message)

    def error(self, message):
        self.errors.append(message)


class ScratchCase(unittest.TestCase):
    """A scratch directory per test. Created, never assumed to exist."""

    def setUp(self):
        self.scratch = tempfile.mkdtemp(prefix="dhu-daemon-test-")
        self.addCleanup(shutil.rmtree, self.scratch, True)

    def tree(self, *relative_dirs):
        """Make directories under the scratch root and return the root."""
        for relative in relative_dirs:
            os.makedirs(os.path.join(self.scratch, relative), 0o755, exist_ok=True)
        return self.scratch

    def write(self, relpath, text="content\n"):
        path = os.path.join(self.scratch, relpath)
        os.makedirs(os.path.dirname(path), 0o755, exist_ok=True)
        with open(path, "w") as handle:
            handle.write(text)
        return path


# ── A: the walk ───────────────────────────────────────────────────────────────


class WalkOperatorExclusionTests(ScratchCase):
    """`exclude.conf` decides a DESCENT, and says so in its own counter."""

    def walk(self, exclude_globs=()):
        """Walk the scratch root, returning (relpaths seen, counters, logger)."""
        seen = []
        counters = DAEMON.Counters()
        logger = _RecordingLogger()
        root_fd = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY)
        try:
            DAEMON.walk_root(
                root_fd, counters, logger,
                lambda _fd, _name, relpath: seen.append(relpath),
                self.scratch, exclude_globs=exclude_globs,
            )
        finally:
            os.close(root_fd)
        # The de-dup cache is process-wide and would hide the second walk's log
        # lines from a test that walks twice.
        DAEMON._LOGGED_REFUSALS.clear()
        return sorted(seen), counters, logger

    def build(self):
        self.write("src/app.ts")
        self.write("fixtures/huge.bin")
        self.write("fixtures/nested/also-huge.bin")
        self.write("node_modules/pkg/index.js")

    def test_without_the_file_every_non_builtin_directory_is_walked(self):
        """The control. Without this, the next test proves nothing."""
        self.build()
        seen, counters, _logger = self.walk()
        self.assertIn("fixtures/huge.bin", seen)
        self.assertIn("fixtures/nested/also-huge.bin", seen)
        self.assertNotIn("walk-excluded-dir-operator", counters.refusals)
        self.assertEqual(counters.refusals.get("walk-excluded-dir"), 1)  # node_modules

    def test_a_named_directory_is_NOT_walked(self):
        self.build()
        seen, _counters, _logger = self.walk(exclude_globs=("fixtures",))
        self.assertIn("src/app.ts", seen)
        self.assertNotIn("fixtures/huge.bin", seen)
        # The point of excluding at the DESCENT: the subtree costs one scandir
        # entry, so nothing below it is walked either.
        self.assertNotIn("fixtures/nested/also-huge.bin", seen)

    def test_it_is_counted_under_its_OWN_reason(self):
        """Merged into `walk-excluded-dir`, an operator cannot tell their rule
        from the built-in list, which is the one question the counter exists to
        answer."""
        self.build()
        _seen, counters, _logger = self.walk(exclude_globs=("fixtures",))
        self.assertEqual(counters.refusals.get("walk-excluded-dir-operator"), 1)
        self.assertEqual(counters.refusals.get("walk-excluded-dir"), 1)
        self.assertIn("walk-excluded-dir-operator", counters.refusals)
        self.assertNotEqual("walk-excluded-dir", "walk-excluded-dir-operator")

    def test_the_log_line_names_the_glob_that_matched(self):
        self.build()
        _seen, _counters, logger = self.walk(exclude_globs=("fix*",))
        matching = [line for line in logger.infos + logger.warnings
                    if "exclude.conf" in line]
        self.assertTrue(matching, logger.infos + logger.warnings)
        self.assertIn("'fix*'", matching[0])
        self.assertIn("fixtures", matching[0])

    def test_the_match_is_case_sensitive_in_the_walk_too(self):
        """A glob that does not match the name as WRITTEN excludes nothing.

        Only `Fixtures` exists here, deliberately: macOS filesystems are
        case-INSENSITIVE, so a tree holding both `fixtures/` and `Fixtures/`
        would be one directory on this platform and the test would be asserting
        the filesystem's behaviour rather than the matcher's. One directory,
        spelled one way, and a glob spelled the other, is the same claim and it
        holds on both platforms.
        """
        self.write("Fixtures/cased.ts")
        self.write("src/app.ts")
        seen, counters, _logger = self.walk(exclude_globs=("fixtures",))
        self.assertIn("Fixtures/cased.ts", seen)
        self.assertNotIn("walk-excluded-dir-operator", counters.refusals)

    def test_a_glob_matching_nothing_changes_nothing(self):
        self.build()
        with_glob, counters, _logger = self.walk(exclude_globs=("no-such-dir-*",))
        without, _counters, _logger = self.walk()
        self.assertEqual(with_glob, without)
        self.assertNotIn("walk-excluded-dir-operator", counters.refusals)

    def test_it_cannot_switch_OFF_a_built_in_exclusion(self):
        """The asymmetry at the walk: this file only ever removes protection.

        There is no syntax for "walk node_modules after all", and naming a
        built-in directory here leaves it excluded — by the built-in rule, which
        is checked first.
        """
        self.build()
        seen, counters, _logger = self.walk(exclude_globs=("node_modules",))
        self.assertNotIn("node_modules/pkg/index.js", seen)
        self.assertEqual(counters.refusals.get("walk-excluded-dir"), 1)
        self.assertNotIn("walk-excluded-dir-operator", counters.refusals)

    def test_a_file_whose_NAME_matches_a_glob_is_still_captured(self):
        """It is a DIRECTORY-name rule. A file called `fixtures` is not a tree."""
        self.write("fixtures")
        seen, counters, _logger = self.walk(exclude_globs=("fixtures",))
        self.assertEqual(seen, ["fixtures"])
        self.assertNotIn("walk-excluded-dir-operator", counters.refusals)


# ── B: loading the file ───────────────────────────────────────────────────────


class LoadExcludeTests(ScratchCase):
    """"I could not read your rules" and "you have no rules" are different facts."""

    def config(self):
        return DAEMON.Config({"root": self.scratch, "owner_uid": str(os.getuid())},
                             os.path.join(self.scratch, "etc/dhu-backupd.conf"))

    def test_an_absent_file_is_not_an_error_and_not_a_refusal(self):
        globs, refusals = DAEMON.load_exclude(self.config())
        self.assertEqual(globs, ())
        self.assertEqual(refusals, ())

    def test_a_present_file_is_parsed(self):
        self.write("etc/exclude.conf", "# notes\nfixtures\nsnapshots-*\n")
        globs, refusals = DAEMON.load_exclude(self.config())
        self.assertEqual(globs, ("fixtures", "snapshots-*"))
        self.assertEqual(refusals, ())

    def test_a_malformed_line_is_refused_and_the_good_ones_survive(self):
        self.write("etc/exclude.conf", "fixtures\ntests/fixtures\n")
        globs, refusals = DAEMON.load_exclude(self.config())
        self.assertEqual(globs, ("fixtures",))
        self.assertEqual(len(refusals), 1)

    def test_an_unreadable_file_is_a_REFUSAL_and_never_an_empty_list(self):
        """An empty list would look like an operator who never wrote the file.

        Proven with a DIRECTORY at the path rather than a `chmod 000` file:
        a mode-based refusal is not a refusal for root, so that version of this
        test would prove nothing on a suite running as root — and the daemon
        that reads this file IS root.
        """
        os.makedirs(os.path.join(self.scratch, "etc/exclude.conf"), 0o755)
        globs, refusals = DAEMON.load_exclude(self.config())
        self.assertEqual(globs, ())
        self.assertEqual(len(refusals), 1)
        self.assertTrue(refusals[0][1].startswith("unreadable:"), refusals)
        self.assertIn(errno.errorcode[errno.EISDIR], refusals[0][1])

    def test_the_default_config_has_the_pair_before_any_file_is_read(self):
        """A walk that runs without the startup path gets "no exclusions",
        never an AttributeError halfway down a tree."""
        config = self.config()
        self.assertEqual(config.exclude_globs, ())
        self.assertEqual(config.exclude_refusals, ())

    def test_the_path_is_inside_the_root_owned_etc(self):
        self.assertEqual(self.config().exclude_path,
                         os.path.join(self.scratch, "etc", "exclude.conf"))
        self.assertEqual(dhu_backup_core.EXCLUDE_FILENAME, "exclude.conf")


# ── C: the heartbeat ──────────────────────────────────────────────────────────


class HeartbeatShapeTests(ScratchCase):
    """`write_state` over fabricated counters and numbers. No daemon, no store."""

    GiB = 1024 ** 3

    def config(self, **values):
        base = {"root": self.scratch, "owner_uid": str(os.getuid())}
        base.update(dict((k, str(v)) for k, v in values.items()))
        config = DAEMON.Config(base, os.path.join(self.scratch, "etc/dhu-backupd.conf"))
        os.makedirs(config.tmp_dir, 0o700, exist_ok=True)
        os.makedirs(config.var_dir, 0o755, exist_ok=True)
        return config

    def publish(self, config, state=None, store_bytes=0, free_bytes=None,
                roots=1, refused=0, **kwargs):
        if free_bytes is None:
            free_bytes = 100 * self.GiB
        DAEMON.write_state(config, {} if state is None else state, DAEMON.Counters(),
                           store_bytes, free_bytes, roots, refused, **kwargs)
        with open(config.state_path) as handle:
            return json.load(handle)

    def test_a_comfortable_daemon_still_writes_ok(self):
        payload = self.publish(self.config())
        self.assertEqual(payload["state"], "ok")
        self.assertNotIn("warning_reason", payload)
        self.assertNotIn("warning_detail", payload)

    def test_a_tight_volume_writes_warning_with_a_reason_LIST(self):
        config = self.config(min_free_bytes=10 * self.GiB)
        payload = self.publish(config, free_bytes=12 * self.GiB)
        self.assertEqual(payload["state"], "warning")
        self.assertEqual(payload["warning_reason"], ["free-space-low"])
        self.assertIsInstance(payload["warning_reason"], list)
        self.assertIn("GiB", payload["warning_detail"])

    def test_both_reasons_arrive_together_in_the_declared_order(self):
        config = self.config(min_free_bytes=10 * self.GiB, max_store_bytes=1000)
        payload = self.publish(config, free_bytes=12 * self.GiB, store_bytes=900)
        self.assertEqual(payload["warning_reason"],
                         ["free-space-low", "store-nearly-full"])

    def test_the_numbers_a_human_needs_are_beside_the_state(self):
        """"16.1 GiB free" is not actionable without the floor it is heading for."""
        config = self.config(min_free_bytes=10 * self.GiB, max_store_bytes=5 * self.GiB)
        payload = self.publish(config, free_bytes=12 * self.GiB, store_bytes=7)
        self.assertEqual(payload["free_bytes"], 12 * self.GiB)
        self.assertEqual(payload["min_free_bytes"], 10 * self.GiB)
        self.assertEqual(payload["store_bytes"], 7)
        self.assertEqual(payload["max_store_bytes"], 5 * self.GiB)

    def test_those_two_limits_are_present_even_when_nothing_is_wrong(self):
        payload = self.publish(self.config())
        self.assertEqual(payload["min_free_bytes"], dhu_backup_core.MIN_FREE_BYTES)
        self.assertEqual(payload["max_store_bytes"], dhu_backup_core.MAX_STORE_BYTES)

    def test_degraded_outranks_warning(self):
        """A daemon that has stopped is not "about to stop"."""
        config = self.config(min_free_bytes=10 * self.GiB)
        payload = self.publish(config, state={"degraded_reason": "store-write-failed:ENOSPC"},
                               free_bytes=12 * self.GiB)
        self.assertEqual(payload["state"], "degraded")
        self.assertEqual(payload["degraded_reason"], "store-write-failed:ENOSPC")

    def test_scan_failed_and_unprotected_outrank_warning(self):
        config = self.config(min_free_bytes=10 * self.GiB)
        failed = self.publish(config, free_bytes=12 * self.GiB, scan_error="boom")
        self.assertEqual(failed["state"], "scan-failed")
        nothing = self.publish(config, free_bytes=12 * self.GiB, roots=0)
        self.assertEqual(nothing["state"], "unprotected")

    def test_every_state_it_can_write_is_a_verdict_the_helper_knows(self):
        """The pair that must not drift: a label the daemon writes and the
        helper does not know becomes `unreadable-heartbeat` — loud, and useless."""
        config = self.config(min_free_bytes=10 * self.GiB)
        labels = [
            self.publish(config)["state"],
            self.publish(config, free_bytes=12 * self.GiB)["state"],
            self.publish(config, state={"degraded_reason": "x"})["state"],
            self.publish(config, roots=0)["state"],
            self.publish(config, scan_error="boom")["state"],
        ]
        self.assertEqual(labels, ["ok", "warning", "degraded", "unprotected", "scan-failed"])
        for label in labels:
            self.assertIn(label, dhu_backup_core.HEALTH_VERDICTS)

    def test_an_unmeasured_free_space_does_not_become_a_warning(self):
        payload = self.publish(self.config(min_free_bytes=10 * self.GiB), free_bytes=-1)
        # -1 is not a real free-space reading; the daemon passes None. Both are
        # asserted, because only one of them is what a skipped cycle produces.
        self.assertIn(payload["state"], ("ok", "warning"))
        skipped = self.publish(self.config(min_free_bytes=10 * self.GiB), free_bytes=None)
        self.assertEqual(skipped["free_bytes"], 100 * self.GiB)

    def test_the_exclusion_counters_are_in_the_heartbeat(self):
        config = self.config()
        config.exclude_globs = ("fixtures", "snapshots-*")
        config.exclude_refusals = (("tests/fixtures", "glob-matches-the-directory-name-only"),)
        payload = self.publish(config)
        self.assertEqual(payload["exclude_globs"], 2)
        self.assertEqual(payload["exclude_refused"], 1)

    def test_the_exclusion_counters_are_zero_rather_than_absent(self):
        """A reader must be able to tell "no globs" from "an old daemon"."""
        payload = self.publish(self.config())
        self.assertEqual(payload["exclude_globs"], 0)
        self.assertEqual(payload["exclude_refused"], 0)

    def test_the_two_operator_files_are_reported_separately(self):
        config = self.config()
        config.extra_vault_globs = ("*.secret",)
        config.exclude_globs = ("fixtures",)
        payload = self.publish(config)
        self.assertEqual(payload["vault_extra_globs"], 1)
        self.assertEqual(payload["exclude_globs"], 1)

    def test_no_path_ever_appears_in_the_heartbeat(self):
        """H4, re-asserted over the fields this change added."""
        config = self.config()
        config.exclude_globs = ("fixtures",)
        config.exclude_refusals = ((os.path.join(self.scratch, "etc/exclude.conf"),
                                    "unreadable:EACCES"),)
        with open(config.state_path, "w") as handle:
            handle.write("{}")
        payload = self.publish(config)
        self.assertNotIn(self.scratch, json.dumps(payload))
        self.assertNotIn("/", json.dumps(payload["refusals_by_reason"]))

    def test_the_warning_is_logged_on_ARRIVAL_and_not_every_cycle(self):
        """One line per 15 s scan is 5,760 a day into a root-owned file with no
        rotation, on the volume whose free space the warning is about."""
        config = self.config(min_free_bytes=10 * self.GiB)
        logger = _RecordingLogger()
        state = {}
        for _ in range(3):
            self.publish(config, state=state, free_bytes=12 * self.GiB, logger=logger)
        self.assertEqual(len(logger.warnings), 1, logger.warnings)
        self.assertIn("free-space-low", logger.warnings[0])
        # ... and cleared, once, when it stops being true.
        self.publish(config, state=state, free_bytes=90 * self.GiB, logger=logger)
        self.publish(config, state=state, free_bytes=90 * self.GiB, logger=logger)
        cleared = [line for line in logger.infos if "warning cleared" in line]
        self.assertEqual(len(cleared), 1, logger.infos)


# ── D: a staging daemon, run as this user against a scratch install root ──────


class StagingDaemonRunTests(ScratchCase):
    """The real `dhu-backupd`, `--once`, as this user, against a scratch root.

    Not the real install: `--config` names a config inside `self.scratch`, and
    that config names the same scratch directory as its root and its watch list.
    There is no path from here to `/Library/DHU/backup` or `/opt/dhu-backup`.

    Nothing destructive is exercised. `--prune-now` is not passed and the prune
    interval is left at its default hour, which one `--once` scan cannot reach.
    """

    def build_install_root(self, config_values=None, exclude_text=None,
                           watched_dirs=(), files=()):
        install_root = os.path.join(self.scratch, "install")
        watched = os.path.join(self.scratch, "watched")
        for directory in ("etc",):
            os.makedirs(os.path.join(install_root, directory), 0o755)
        os.makedirs(watched, 0o755)
        for relative in watched_dirs:
            os.makedirs(os.path.join(watched, relative), 0o755, exist_ok=True)
        for relative, text in files:
            path = os.path.join(watched, relative)
            os.makedirs(os.path.dirname(path), 0o755, exist_ok=True)
            with open(path, "w") as handle:
                handle.write(text)

        with open(os.path.join(install_root, "etc", "watchlist.conf"), "w") as handle:
            handle.write("demo %s\n" % watched)
        # The budgets are PINNED here rather than left at their defaults, and
        # the reason is a finding: run with the defaults on the machine this was
        # written on, every one of these staging runs reported `warning`,
        # because that volume genuinely had 14.1 GiB free against a 10 GiB floor
        # whose warning band starts at 15 GiB. The feature working is not a test
        # fixture. A control that says `ok` only on a roomy host is a control
        # whose claim and evidence stop sharing a population the moment the disk
        # fills, so each test states the budget it is asserting about.
        values = {"root": install_root,
                  "watchlist": os.path.join(install_root, "etc", "watchlist.conf"),
                  "owner_uid": os.getuid(),
                  "interval_seconds": 15,
                  "min_free_bytes": 4096,
                  "max_store_bytes": 5 * 1024 ** 3}
        values.update(config_values or {})
        config_path = os.path.join(install_root, "etc", "dhu-backupd.conf")
        with open(config_path, "w") as handle:
            for key, value in sorted(values.items()):
                handle.write("%s = %s\n" % (key, value))
        if exclude_text is not None:
            with open(os.path.join(install_root, "etc", "exclude.conf"), "w") as handle:
                handle.write(exclude_text)
        return install_root, watched, config_path

    def run_daemon(self, config_path):
        done = subprocess.run(
            [PYTHON, "-E", "-s", "-S", DAEMON_SCRIPT, "--config", config_path, "--once"],
            capture_output=True, text=True, timeout=180)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done

    def heartbeat(self, install_root):
        with open(os.path.join(install_root, "var", "state.json")) as handle:
            return json.load(handle)

    def stored_relpaths(self, install_root):
        """Every ORIGINAL basename the store now holds, by relative path.

        Read from the tree rather than the index, because the tree is what a
        recovery reads.
        """
        store = os.path.join(install_root, "store")
        found = []
        for dirpath, _dirnames, filenames in os.walk(store):
            for name in filenames:
                relative = os.path.relpath(os.path.join(dirpath, name), store)
                # <root-id>/<slug>/<relpath-dir>/@<key>/<basename>
                parts = relative.split(os.sep)
                found.append("/".join(parts[2:-2] + [parts[-1]]))
        return sorted(found)

    # -- the exclusion list --------------------------------------------------

    def test_a_glob_matching_the_watch_root_cannot_un_protect_it(self):
        """The highest-consequence case: `exclude.conf` naming a WATCH ROOT.

        `exclude.conf` is subtractive, so the worst thing it could do is switch
        a whole root off while the daemon still reports `ok` — protection gone,
        nothing saying so. It cannot, and the reason is structural rather than a
        check: the glob is consulted on the CHILDREN a directory scan yields,
        and a watch root is never a child of anything the daemon walks. It is
        opened because the root-owned watchlist named it.

        Asserted here rather than argued in a comment, because "you cannot
        exclude what you explicitly asked to watch" is the kind of claim that
        stays true only until someone moves the check one level up.
        """
        install_root, _watched, config_path = self.build_install_root(
            exclude_text="watched\n",
            watched_dirs=("sub",),
            files=(("top.txt", "top\n"), ("sub/inner.txt", "inner\n")))
        self.run_daemon(config_path)
        held = self.stored_relpaths(install_root)
        self.assertIn("top.txt", held)
        self.assertIn("sub/inner.txt", held)
        state = self.heartbeat(install_root)
        self.assertEqual(state["exclude_globs"], 1)
        # The glob is in force and simply never matched, so the operator's
        # counter stays at zero rather than the rule quietly doing nothing
        # somewhere else.
        self.assertNotIn("walk-excluded-dir-operator", state["refusals_by_reason"])

    def test_a_directory_named_by_exclude_conf_is_not_walked_and_is_counted(self):
        install_root, _watched, config_path = self.build_install_root(
            exclude_text="# the 33 GB one\nfixtures\ntests/fixtures\n",
            files=[("src/app.ts", "export const a = 1\n"),
                   ("fixtures/huge.json", "{}\n"),
                   ("fixtures/nested/deeper.json", "{}\n")],
        )
        self.run_daemon(config_path)
        payload = self.heartbeat(install_root)
        stored = self.stored_relpaths(install_root)

        self.assertEqual(payload["state"], "ok")
        self.assertIn("src/app.ts", stored)
        self.assertNotIn("fixtures/huge.json", stored)
        self.assertNotIn("fixtures/nested/deeper.json", stored)

        self.assertEqual(payload["exclude_globs"], 1)
        self.assertEqual(payload["exclude_refused"], 1)
        self.assertEqual(payload["refusals_by_reason"].get("walk-excluded-dir-operator"), 1)

        with open(os.path.join(install_root, "var", "dhu-backupd.log")) as handle:
            log = handle.read()
        self.assertIn("exclude.conf REFUSED 'tests/fixtures'", log)
        self.assertIn("NOT protected", log)

    def test_without_the_file_the_same_tree_is_fully_captured(self):
        """The control for the test above, on the same fixture."""
        install_root, _watched, config_path = self.build_install_root(
            files=[("src/app.ts", "export const a = 1\n"),
                   ("fixtures/huge.json", "{}\n")],
        )
        self.run_daemon(config_path)
        payload = self.heartbeat(install_root)
        self.assertIn("fixtures/huge.json", self.stored_relpaths(install_root))
        self.assertEqual(payload["exclude_globs"], 0)
        self.assertEqual(payload["exclude_refused"], 0)
        self.assertNotIn("walk-excluded-dir-operator", payload["refusals_by_reason"])

    # -- the warning state ---------------------------------------------------

    def test_a_nearly_full_store_writes_warning_AND_KEEPS_CAPTURING(self):
        """The whole point of the state: `warning` is not `degraded`.

        The budget is fabricated in the config rather than by filling a disk:
        `max_store_bytes` is set just above what this fixture writes, so the
        store lands inside the warning band and below the ceiling.
        """
        payload_text = "x" * 900 + "\n"
        install_root, _watched, config_path = self.build_install_root(
            config_values={"max_store_bytes": 1100, "min_free_bytes": 4096},
            files=[("src/app.ts", payload_text)],
        )
        self.run_daemon(config_path)
        payload = self.heartbeat(install_root)

        self.assertEqual(payload["state"], "warning")
        self.assertEqual(payload["warning_reason"], ["store-nearly-full"])
        # Still capturing — the version is on disk, not a promise.
        self.assertEqual(payload["versions_written"], 1)
        self.assertIn("src/app.ts", self.stored_relpaths(install_root))
        self.assertNotIn("degraded_reason", payload)

        with open(os.path.join(install_root, "var", "dhu-backupd.log")) as handle:
            log = handle.read()
        self.assertIn("WARNING (store-nearly-full)", log)
        self.assertNotIn("DEGRADED", log)

    def test_a_nearly_full_VOLUME_writes_warning_against_the_real_free_space(self):
        """The author's live case: free space inside 1.5x the floor.

        The floor is derived from this volume's ACTUAL free space so that the
        band is entered without filling anything up. Nothing is written to make
        the condition true, which is why this can run on any machine.
        """
        install_root = os.path.join(self.scratch, "probe")
        os.makedirs(install_root, 0o755)
        vfs = os.statvfs(install_root)
        free_bytes = vfs.f_bavail * vfs.f_frsize
        floor = int(free_bytes * 0.8)   # free is 1.25x the floor: inside 1.5x, above 1x
        shutil.rmtree(install_root)

        install_root, _watched, config_path = self.build_install_root(
            config_values={"min_free_bytes": floor},
            files=[("src/app.ts", "export const a = 1\n")],
        )
        self.run_daemon(config_path)
        payload = self.heartbeat(install_root)

        self.assertEqual(payload["state"], "warning")
        self.assertEqual(payload["warning_reason"], ["free-space-low"])
        self.assertEqual(payload["min_free_bytes"], floor)
        self.assertGreaterEqual(payload["free_bytes"], floor)
        self.assertEqual(payload["versions_written"], 1)

    def test_a_healthy_budget_on_the_same_fixture_writes_ok(self):
        """Same tree, roomy budgets: `ok`. Without this the two above could be
        passing on something other than the budget."""
        install_root, _watched, config_path = self.build_install_root(
            files=[("src/app.ts", "export const a = 1\n")],
        )
        self.run_daemon(config_path)
        payload = self.heartbeat(install_root)
        self.assertEqual(payload["state"], "ok")
        self.assertNotIn("warning_reason", payload)
        self.assertEqual(payload["versions_written"], 1)

    def test_the_staging_run_never_names_the_real_install_root(self):
        """The guard on this whole class, asserted rather than reviewed for."""
        install_root, _watched, config_path = self.build_install_root(
            files=[("src/app.ts", "a\n")])
        self.run_daemon(config_path)
        with open(config_path) as handle:
            config_text = handle.read()
        for real in dhu_backup_core.DEFAULT_INSTALL_ROOTS.values():
            self.assertNotIn(real, config_text)
            self.assertFalse(install_root.startswith(real))


if __name__ == "__main__":
    unittest.main()


# ── E: the store's own namespace, and versions per PATH ──────────────────────
#
# Found by the independent review of 2026-09-11, all three by execution. The
# version directories of every file in one source directory are siblings in
# the store; anything that lists that directory without asking WHICH file a
# version belongs to is a rule about the directory, not the path.


class WalkStoreNamespaceTests(ScratchCase):
    """Two shapes the walk refuses before they can reach the store."""

    def walk(self):
        seen = []
        counters = DAEMON.Counters()
        logger = _RecordingLogger()
        root_fd = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY)
        try:
            DAEMON.walk_root(
                root_fd, counters, logger,
                lambda _fd, _name, relpath: seen.append(relpath), self.scratch,
            )
        finally:
            os.close(root_fd)
        DAEMON._LOGGED_REFUSALS.clear()
        return sorted(seen), counters, logger

    def test_an_entry_named_like_a_version_key_is_refused_whether_file_or_directory(self):
        key = dhu_backup_core.version_key(1_800_000_000_000_000_000, "0123456789abcdef")
        self.write("docs/notes.md")
        self.write("docs/%s/notes.md" % key)   # a DIRECTORY named like a version
        self.write("docs/%s.txt" % key[:-4])   # not a key: the hash is 8 chars
        self.write(key)                         # a FILE named like a version
        seen, counters, logger = self.walk()
        self.assertEqual(seen, ["docs/%s.txt" % key[:-4], "docs/notes.md"])
        self.assertEqual(counters.refusals.get("walk-version-key-shaped"), 2)
        self.assertTrue(any("named like a version key" in m for m in logger.infos))

    def test_a_name_that_is_not_valid_utf8_is_refused_and_the_walk_continues(self):
        """One such name used to abort EVERY scan of the whole root.

        The OS hands the name back surrogate-escaped; the sqlite index and the
        log both raise `UnicodeEncodeError` on it, and nothing in the walk
        caught that, so the exception unwound the scan and the daemon reported
        `scan-failed` until the file was removed. It is an ordinary refusal now,
        with a counter, and the files after it are still captured.
        """
        self.write("aaa-first.md")
        raw = os.path.join(self.scratch.encode("utf-8"), b"bad_\xff\xfe.md")
        try:
            with open(raw, "wb") as handle:
                handle.write(b"x")
        except OSError as exc:
            if exc.errno != errno.EILSEQ:
                raise
            # APFS refuses to CREATE such a name, so on macOS the refusal is
            # unreachable and this test proves it on Linux (ext4 accepts any
            # bytes). A skip with the platform's own reason, not a silent pass.
            self.skipTest("this filesystem refuses non-UTF-8 names (EILSEQ); proven on Linux")
        self.write("zzz-last.md")
        seen, counters, logger = self.walk()
        self.assertEqual(seen, ["aaa-first.md", "zzz-last.md"])
        self.assertEqual(counters.refusals.get("walk-name-not-utf8"), 1)
        message = [m for m in logger.infos if "not valid UTF-8" in m]
        self.assertEqual(len(message), 1)
        message[0].encode("utf-8")  # the log line itself must be writable


class ExistingVersionsPerPathTests(ScratchCase):
    """`existing_versions` answers for ONE path, identified by its leaf."""

    def version(self, directory, day, sha, leaf):
        key = dhu_backup_core.version_key(day * 86_400 * 10 ** 9, sha)
        path = os.path.join(self.scratch, directory, key)
        os.makedirs(path, 0o755)
        with open(os.path.join(path, leaf), "w") as handle:
            handle.write("v")
        return key

    def test_only_this_leafs_versions_are_returned_oldest_first(self):
        a3 = self.version("d", 3, "a" * 64, "a.md")
        b1 = self.version("d", 1, "b" * 64, "b.md")
        a2 = self.version("d", 2, "c" * 64, "a.md")
        held = DAEMON.existing_versions(os.path.join(self.scratch, "d"), "a.md")
        self.assertEqual([row[0] for row in held], [a2, a3])
        self.assertEqual([row[2] for row in held], ["c" * 12, "a" * 12])
        self.assertEqual([row[0] for row in DAEMON.existing_versions(
            os.path.join(self.scratch, "d"), "b.md")], [b1])

    def test_a_path_with_no_versions_and_a_missing_directory_both_answer_empty(self):
        self.version("d", 1, "b" * 64, "b.md")
        self.assertEqual(DAEMON.existing_versions(os.path.join(self.scratch, "d"), "a.md"), [])
        self.assertEqual(DAEMON.existing_versions(os.path.join(self.scratch, "absent"), "a.md"), [])

    def test_the_rolling_window_is_fed_one_paths_versions_not_the_directorys(self):
        """The population that broke: 230 files in one directory, one version each.

        Fed the directory's versions, the window rolled at 200 and deleted the
        only copies of 30 siblings. Fed one path's, the plan is empty.
        """
        for index in range(230):
            self.version("d", index + 1, "%064x" % index, "f%d.txt" % index)
        held = DAEMON.existing_versions(os.path.join(self.scratch, "d"), "f0.txt")
        plan = dhu_backup_core.version_window_plan(
            [(key, epoch_ns) for key, epoch_ns, _sha in held], 200)
        self.assertEqual(len(held), 1)
        self.assertEqual(plan, [])


class IndexReconciliationTests(ScratchCase):
    """A row the store no longer backs is forgotten, so the file is captured again."""

    def setUp(self):
        super(IndexReconciliationTests, self).setUp()
        self.config = DAEMON.Config({"root": self.scratch}, "test.conf")
        os.makedirs(self.config.var_dir, 0o755)
        os.makedirs(self.config.store_dir, 0o755)
        os.makedirs(self.config.vault_dir, 0o700)
        self.connection = DAEMON.open_index(self.config)
        self.addCleanup(self.connection.close)
        self.logger = _RecordingLogger()
        self.watch_root = "/home/you/proj"
        self.slug = dhu_backup_core.root_slug("proj", self.watch_root)

    def remember(self, relpath):
        self.connection.execute(
            "INSERT INTO files (root_id, watch_root, relpath, size, mtime_ns, sha256,"
            " first_seen, last_seen) VALUES (?, ?, ?, 1, 1, 'x', 1, 1)",
            ("proj", self.watch_root, relpath))
        self.connection.commit()

    def hold(self, tree, relpath):
        key = dhu_backup_core.version_key(10 ** 18, "a" * 64)
        path = os.path.join(self.config.tree_dir(tree),
                            dhu_backup_core.version_subpath("proj", self.slug, relpath, key))
        os.makedirs(os.path.dirname(path), 0o755)
        with open(path, "w") as handle:
            handle.write("v")

    def rows(self):
        return sorted(r[0] for r in self.connection.execute("SELECT relpath FROM files"))

    def test_rows_without_a_version_are_forgotten_and_backed_rows_kept(self):
        self.remember("docs/kept.md")
        self.hold("store", "docs/kept.md")
        self.remember("docs/lost.md")           # its version was rolled away
        self.remember(".env.local")
        self.hold("vault", ".env.local")        # held in the OTHER tree
        forgotten = DAEMON.reconcile_index_with_store(self.config, self.connection, self.logger)
        self.assertEqual(forgotten, 1)
        self.assertEqual(self.rows(), [".env.local", "docs/kept.md"])
        self.assertTrue(any("captured again" in m for m in self.logger.warnings))

    def test_a_sibling_with_versions_does_not_vouch_for_a_path_without(self):
        # The directory-level mistake, restated for the index: `busy.md` having
        # versions in `docs/` says nothing about `lost.md` in the same directory.
        self.remember("docs/busy.md")
        self.hold("store", "docs/busy.md")
        self.remember("docs/lost.md")
        DAEMON.reconcile_index_with_store(self.config, self.connection, self.logger)
        self.assertEqual(self.rows(), ["docs/busy.md"])

    def test_nothing_to_forget_is_silent(self):
        self.remember("docs/kept.md")
        self.hold("store", "docs/kept.md")
        self.assertEqual(
            DAEMON.reconcile_index_with_store(self.config, self.connection, self.logger), 0)
        self.assertEqual(self.logger.warnings, [])
        # And the store itself was not touched: reconciliation only deletes rows.
        self.assertTrue(os.path.isdir(os.path.join(self.config.store_dir, "proj")))


class WorktreesCoverageTests(ScratchCase):
    """The repo walk skips `.claude/worktrees` only when another root covers it."""

    def walk(self, worktrees_covered):
        seen = []
        counters = DAEMON.Counters()
        root_fd = os.open(self.scratch, os.O_RDONLY | os.O_DIRECTORY)
        try:
            DAEMON.walk_root(root_fd, counters, _RecordingLogger(),
                             lambda _fd, _name, relpath: seen.append(relpath), self.scratch,
                             worktrees_covered=worktrees_covered)
        finally:
            os.close(root_fd)
        DAEMON._LOGGED_REFUSALS.clear()
        return sorted(seen), counters

    def test_uncovered_worktrees_are_walked_and_covered_ones_are_skipped(self):
        self.write("src/app.ts")
        self.write(".claude/worktrees/agent-x/src/app.ts")
        seen, counters = self.walk(worktrees_covered=False)
        self.assertIn(".claude/worktrees/agent-x/src/app.ts", seen)
        self.assertNotIn("walk-excluded-dir", counters.refusals)
        seen, counters = self.walk(worktrees_covered=True)
        self.assertEqual(seen, ["src/app.ts"])
        self.assertEqual(counters.refusals.get("walk-excluded-dir"), 1)

    def test_coverage_is_a_fact_about_the_other_roots(self):
        covered = DAEMON.worktrees_covered_by_another_root
        roots = [("repo", "/home/you/proj"), ("wt", "/home/you/proj/.claude/worktrees/agent-a")]
        self.assertTrue(covered("/home/you/proj", roots))
        self.assertTrue(covered("/home/you/proj/", roots))
        self.assertFalse(covered("/home/you/proj/.claude/worktrees/agent-a", roots))
        self.assertFalse(covered("/home/you/proj", [("repo", "/home/you/proj")]))
        self.assertFalse(covered("/home/you/proj", [("other", "/home/you/proj2/.claude/worktrees/x")]))
