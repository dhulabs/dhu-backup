"""Tests for `src/install.sh` and `src/uninstall.sh`.

Run with:  /usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'

Both scripts need root to do their real work, so this suite proves what CAN be
proven unprivileged, and the scripts are factored so that most of what matters
falls in that category:

  * `bash -n` on both — a syntax error in a sudo script is discovered at the
    worst possible moment otherwise;
  * the pure bash functions, SOURCED without running any of the install
    (`DHU_BACKUP_SOURCE_ONLY=1`): `render_watchlist` and its validator, and
    `watchlist_decision`, which is the whole flags/preserve/refuse precedence
    rule extracted so all four of its cases are reachable on a machine that
    already HAS an installed watchlist;
  * `--dry-run`, which is checked before the root check and prints the plan
    without touching anything. The "touches nothing" half is asserted, not
    reasoned about: `snapshot_dest` is taken around every unprivileged run,
    including the ones that are expected to refuse.

Nothing here runs an installer or an uninstaller for real, and nothing here
writes under /Library. The one thing this suite READS from the live machine is
the install surface `snapshot_dest` describes.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO_ROOT, "src")
INSTALL = os.path.join(SRC, "install.sh")
UNINSTALL = os.path.join(SRC, "uninstall.sh")
BASH = "/bin/bash"

# The suite asserts THIS platform's install surface, because that is the one the
# scripts default to when they are run here. The other platform's plan is
# asserted separately through `--dry-run --platform`, which is what that flag is
# for. Hard-coding the macOS paths made every one of these fail on Linux for a
# reason that had nothing to do with the behaviour under test.
IS_LINUX = sys.platform.startswith("linux")
DEST = "/opt/dhu-backup" if IS_LINUX else "/Library/DHU/backup"
SERVICE_FILE = ("/etc/systemd/system/dhu-backupd.service" if IS_LINUX
                else "/Library/LaunchDaemons/com.dhulabs.backup.plist")
SERVICE_NAME = "dhu-backupd" if IS_LINUX else "com.dhulabs.backup"
OTHER_PLATFORM = "darwin" if IS_LINUX else "linux"
OTHER_DEST = "/Library/DHU/backup" if IS_LINUX else "/opt/dhu-backup"
OTHER_SERVICE_FILE = ("/Library/LaunchDaemons/com.dhulabs.backup.plist" if IS_LINUX
                      else "/etc/systemd/system/dhu-backupd.service")
PLIST = SERVICE_FILE

#: `stat` is not portable, and neither is this suite's use of it. BSD takes -f
#: with %Su/%Sg/%Lp; GNU takes -c with %U/%G/%a.
STAT_FORMAT = ('stat -c "%U:%G %a %s %Y %n"' if IS_LINUX
               else 'stat -f "%Su:%Sg %Lp %z %m %N"')


def requires_non_root(test):
    """Skip a test that asserts the scripts REFUSE without root.

    Run as root it does not assert a refusal — it performs a real install or a
    real uninstall on the machine running the suite. That is exactly what it did
    the first time this suite was run inside a container (2026-09-02): the
    "refuses without root" test installed the product and the uninstall one
    removed it again. A test that becomes a destructive action when the
    environment changes is a test that must refuse to run there.
    """
    return unittest.skipIf(
        os.geteuid() == 0,
        "runs as root: this test would perform a REAL install/uninstall, not assert a refusal",
    )(test)


def run_bash(args, env=None):
    """Run /bin/bash with `args`, returning (returncode, stdout+stderr)."""
    full_env = dict(os.environ)
    # Simulate `sudo` by default: the installer has NO default uid and refuses
    # without $SUDO_UID or --owner-uid. Pass env={"SUDO_UID": None} to test
    # the no-sudo path itself.
    full_env["SUDO_UID"] = "501"
    for key, value in (env or {}).items():
        if value is None:
            full_env.pop(key, None)
        else:
            full_env[key] = value
    proc = subprocess.run(
        [BASH] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=full_env,
        timeout=120,
    )
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def call_function(script, func, *args):
    """Source `script` for its functions only, then call one of them.

    `DHU_BACKUP_SOURCE_ONLY=1` makes the script `return` before any line that
    reads or writes the machine, so this exercises the pure functions and
    nothing else. The function's own exit status is the shell's.
    """
    prog = 'DHU_BACKUP_SOURCE_ONLY=1 . "$1" || exit 99\nshift\n"$@"\n'
    return run_bash(["-c", prog, "_", script, func] + list(args))


def call_snippet(script, snippet, *args, **kwargs):
    """Source `script` for its functions only, then run `snippet` with $1.. set.

    The same trick as `call_function` with a body instead of a single name, for
    the uninstall planners: computing the plan takes two calls in one shell
    (`uninstall_state`, then `print_plan_for`), exactly as the script itself
    does it. The sourced script's own `set -euo pipefail` is in force here, so
    the snippet runs under the same shell options the real flow does.

    `env=` reaches `run_bash`, for the snippets whose behaviour depends on what
    sudo did or did not export — `$SUDO_UID` and `$SUDO_USER`.
    """
    prog = 'DHU_BACKUP_SOURCE_ONLY=1 . "$1" || exit 99\nshift\n' + snippet + "\n"
    return run_bash(["-c", prog, "_", script] + list(args), env=kwargs.get("env"))


def fabricate_install_root(case, subdirs=("bin", "etc", "store", "vault", "var")):
    """Build a throwaway directory tree shaped like an install root.

    The uninstall plan is a function of which of these five directories exist,
    so a fabricated root is a complete population for it — no machine anywhere
    needs to have DHU Backup installed for the plan to be asserted. Registered
    for cleanup on the test, so a failure mid-assertion still removes it.
    """
    base = tempfile.mkdtemp(prefix="dhu-fake-install-root-")
    case.addCleanup(shutil.rmtree, base, True)
    for sub in subdirs:
        os.makedirs(os.path.join(base, sub))
        with open(os.path.join(base, sub, "placeholder"), "w") as handle:
            handle.write("fabricated\n")
    return base


def snapshot_dest():
    """The install surface of the live machine, or None if nothing is installed.

    Used only to prove a dry run changed nothing. It covers exactly what these
    two scripts write — the top-level names under the install root, every file
    in `bin/` and `etc/` with its owner, mode, size and mtime, and the plist —
    and deliberately NOT the contents of `store/`, `vault/` or `var/`: the
    daemon writes those continuously, so including them would make this a test
    of whether a file changed on disk during the run rather than of what the
    script did.
    """
    if not os.path.isdir(DEST) and not os.path.exists(PLIST):
        return None
    script = (
        'ls -1 "$1" 2>/dev/null | sort\n'
        'for d in bin etc; do\n'
        '  find "$1/$d" -maxdepth 1 2>/dev/null | sort |'
        '    while IFS= read -r f; do ' + STAT_FORMAT + ' "$f" 2>/dev/null; done\n'
        'done\n'
        + STAT_FORMAT + ' "$2" 2>/dev/null || echo "no service file"\n'
    )
    rc, out = run_bash(["-c", script, "_", DEST, PLIST])
    return out


class SyntaxTest(unittest.TestCase):
    def test_install_sh_parses(self):
        rc, out = run_bash(["-n", INSTALL])
        self.assertEqual(rc, 0, out)

    def test_uninstall_sh_parses(self):
        rc, out = run_bash(["-n", UNINSTALL])
        self.assertEqual(rc, 0, out)

    def test_both_scripts_exist_and_are_not_empty(self):
        for path in (INSTALL, UNINSTALL):
            self.assertTrue(os.path.isfile(path), path)
            self.assertGreater(os.path.getsize(path), 500, path)

    def test_sourcing_runs_no_install_step(self):
        """Sourcing must reach the guard and stop, printing nothing."""
        rc, out = call_function(INSTALL, "true")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.strip(), "", out)


class RenderWatchlistTest(unittest.TestCase):
    """`render_watchlist` — flags in, the text of etc/watchlist.conf out."""

    def render(self, *specs):
        return call_function(INSTALL, "render_watchlist", *specs)

    def assert_refused(self, out, rc, must_name):
        self.assertNotEqual(rc, 0, "expected a refusal, got:\n" + out)
        self.assertNotEqual(rc, 99, "the script failed to source:\n" + out)
        self.assertIn(must_name, out)
        # A refusal must never emit a partial watchlist: no entry lines.
        for line in out.splitlines():
            self.assertFalse(
                re.match(r"^[a-z][a-z0-9-]*\s+/", line),
                "a refusal emitted a rendered entry: " + line,
            )

    def test_one_root_renders(self):
        rc, out = self.render("repo=/Users/someone/Projects/thing")
        self.assertEqual(rc, 0, out)
        self.assertIn("repo         /Users/someone/Projects/thing", out)

    def test_several_roots_render_in_order(self):
        rc, out = self.render("repo=/a/b", "worktrees=/a/b/wt/*", "scratch=/private/tmp/x")
        self.assertEqual(rc, 0, out)
        entries = [l for l in out.splitlines() if l and not l.startswith("#")]
        entries = [l for l in entries if l.strip()]
        self.assertEqual(
            entries,
            ["repo         /a/b", "worktrees    /a/b/wt/*", "scratch      /private/tmp/x"],
        )

    def test_rendered_text_carries_the_format_header(self):
        rc, out = self.render("repo=/a/b")
        self.assertEqual(rc, 0, out)
        self.assertIn("the ONLY source of watched roots", out)
        self.assertIn("<root-id>  <absolute-path>", out)

    def test_trailing_glob_on_last_component_is_allowed(self):
        rc, out = self.render("worktrees=/a/b/*")
        self.assertEqual(rc, 0, out)
        self.assertIn("worktrees    /a/b/*", out)

    def test_hyphenated_id_is_allowed(self):
        rc, out = self.render("dhu-backup=/a/b")
        self.assertEqual(rc, 0, out)
        self.assertIn("dhu-backup   /a/b", out)

    def test_no_specs_is_refused(self):
        rc, out = self.render()
        self.assertNotEqual(rc, 0, out)
        self.assertIn("no entries to render", out)

    def test_relative_path_is_refused(self):
        rc, out = self.render("repo=Projects/thing")
        self.assert_refused(out, rc, "repo=Projects/thing")
        self.assertIn("not absolute", out)

    def test_uppercase_id_is_refused(self):
        rc, out = self.render("Repo=/a/b")
        self.assert_refused(out, rc, "Repo=/a/b")
        self.assertIn("bad root id", out)

    def test_id_with_a_space_is_refused(self):
        rc, out = self.render("my repo=/a/b")
        self.assert_refused(out, rc, "my repo=/a/b")
        self.assertIn("bad root id", out)

    def test_id_starting_with_a_digit_is_refused(self):
        rc, out = self.render("2repo=/a/b")
        self.assert_refused(out, rc, "2repo=/a/b")
        self.assertIn("bad root id", out)

    def test_id_longer_than_32_is_refused(self):
        long_id = "a" * 33
        rc, out = self.render(long_id + "=/a/b")
        self.assert_refused(out, rc, "longer than 32")

    def test_empty_id_is_refused(self):
        rc, out = self.render("=/a/b")
        self.assert_refused(out, rc, "empty root id")

    def test_missing_equals_is_refused(self):
        rc, out = self.render("repo /a/b")
        self.assert_refused(out, rc, "repo /a/b")
        self.assertIn("expected <id>=<absolute-path>", out)

    def test_glob_not_in_the_last_component_is_refused(self):
        rc, out = self.render("worktrees=/a/*/wt")
        self.assert_refused(out, rc, "worktrees=/a/*/wt")
        self.assertIn("LAST component", out)

    def test_star_that_is_not_trailing_is_refused(self):
        rc, out = self.render("repo=/a/b*c")
        self.assert_refused(out, rc, "repo=/a/b*c")
        self.assertIn("must be TRAILING", out)

    def test_two_stars_are_refused(self):
        rc, out = self.render("repo=/a/b**")
        self.assert_refused(out, rc, "repo=/a/b**")
        self.assertIn("at most one", out)

    def test_dot_dot_component_is_refused(self):
        rc, out = self.render("repo=/a/../etc")
        self.assert_refused(out, rc, "repo=/a/../etc")
        self.assertIn("'..'", out)

    def test_duplicate_ids_are_refused(self):
        rc, out = self.render("repo=/a/b", "repo=/c/d")
        self.assert_refused(out, rc, "repo=/c/d")
        self.assertIn("duplicate root id", out)

    def test_one_bad_spec_refuses_the_whole_render(self):
        """A refusal is whole-file: the good root before it is not emitted."""
        rc, out = self.render("good=/a/b", "BAD=/c/d")
        self.assert_refused(out, rc, "BAD=/c/d")
        self.assertNotIn("good         /a/b", out)

    def test_installer_rules_are_a_subset_of_the_daemon_parser(self):
        """Anything render_watchlist emits, `parse_watchlist` must accept.

        The daemon's parser stays the authority on the format; this asserts the
        installer can never hand it a root it would then drop.
        """
        import sys

        sys.path.insert(0, SRC)
        from dhu_backup_core import parse_watchlist  # noqa: E402

        rc, out = self.render("repo=/a/b", "worktrees=/a/b/wt/*", "dhu-backup=/x/y")
        self.assertEqual(rc, 0, out)
        entries, refusals = parse_watchlist(out)
        self.assertEqual(refusals, [])
        self.assertEqual(
            entries, [("repo", "/a/b"), ("worktrees", "/a/b/wt/*"), ("dhu-backup", "/x/y")]
        )


class WatchlistDecisionTest(unittest.TestCase):
    """The precedence rule, all four combinations.

    This function exists precisely so the `refuse` case is testable on a machine
    that already has an installed watchlist — the case that matters most, since
    it is the one standing between a stranger's first install and a daemon that
    reports healthy while protecting nothing.
    """

    def decide(self, flags, existing):
        return call_function(INSTALL, "watchlist_decision", flags, existing)

    def test_flags_given_and_one_installed_uses_the_flags(self):
        rc, out = self.decide("1", "1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.strip(), "flags")

    def test_flags_given_and_none_installed_uses_the_flags(self):
        rc, out = self.decide("1", "0")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.strip(), "flags")

    def test_no_flags_and_one_installed_preserves(self):
        rc, out = self.decide("0", "1")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.strip(), "preserve")

    def test_no_flags_and_none_installed_refuses(self):
        rc, out = self.decide("0", "0")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.strip(), "refuse")

    def test_non_boolean_arguments_are_refused(self):
        rc, out = self.decide("2", "0")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("0 or 1", out)


class WatchlistEntryCountTest(unittest.TestCase):
    """A watchlist of nothing but comments protects nothing and must be seen."""

    def count(self, text):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
            fh.write(text)
            path = fh.name
        try:
            rc, out = call_function(INSTALL, "watchlist_entry_count", path)
            self.assertEqual(rc, 0, out)
            return int(out.strip())
        finally:
            os.unlink(path)

    def test_comments_only_counts_zero(self):
        self.assertEqual(self.count("# a\n\n#  b\n"), 0)

    def test_entries_are_counted(self):
        self.assertEqual(self.count("# a\nrepo /a\nwork /b\n"), 2)

    def test_missing_file_counts_zero(self):
        rc, out = call_function(INSTALL, "watchlist_entry_count", "/nonexistent/nope.conf")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.strip(), "0")


class InstallDryRunTest(unittest.TestCase):
    """`--dry-run` is checked before the root check, so it runs unprivileged."""

    def dry(self, *args):
        return run_bash([INSTALL, "--dry-run"] + list(args))

    def test_dry_run_with_roots_exits_zero_and_prints_the_plan(self):
        rc, out = self.dry("--watch", "repo=/tmp/x", "--owner-uid", "501")
        self.assertEqual(rc, 0, out)
        self.assertIn("== plan ==", out)
        self.assertIn("DRY RUN", out)

    def test_dry_run_names_the_install_root_and_the_rendered_roots(self):
        rc, out = self.dry("--watch", "repo=/tmp/x", "--watch", "other=/tmp/y/*")
        self.assertEqual(rc, 0, out)
        self.assertIn(DEST, out)
        self.assertIn(SERVICE_FILE, out)
        self.assertIn("repo         /tmp/x", out)
        self.assertIn("other        /tmp/y/*", out)

    def test_dry_run_prints_the_planned_files_with_their_modes(self):
        rc, out = self.dry("--watch", "repo=/tmp/x")
        self.assertEqual(rc, 0, out)
        for mode, dest in (
            ("0755", DEST + "/bin/dhu-backupd"),
            ("0644", DEST + "/bin/dhu_backup_core.py"),
            ("0644", DEST + "/bin/credential_patterns.py"),
            ("0755", DEST + "/bin/dhu-backup"),
            ("0644", DEST + "/bin/dhu_backup_announce.py"),
            ("0755", DEST + "/bin/dhu-backup-mcp"),
            ("0755", DEST + "/bin/dhu-backup-hook"),
        ):
            line = [l for l in out.splitlines() if l.strip().endswith("-> " + dest)]
            self.assertTrue(line, "no planned file line for " + dest)
            self.assertTrue(line[0].strip().startswith(mode), line[0])

    def test_every_installed_bin_file_is_syntax_checked_and_asserted(self):
        """The three lists must not drift apart.

        A file added to INSTALL_FILES but not to the py_compile line ships
        unchecked, and a SyntaxError under KeepAlive is a silent restart loop.
        One left out of the post-conditions ships unasserted, which is how a
        wrong owner or mode gets past the one step that exists to catch it.
        """
        with open(os.path.join(SRC, "install.sh")) as handle:
            text = handle.read()
        table = re.search(r'INSTALL_FILES="\n(.*?)\n"', text, re.S)
        self.assertTrue(table, "INSTALL_FILES table not found")
        destinations = []
        for line in table.group(1).splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2].startswith("bin/"):
                destinations.append(parts[2])
        self.assertIn("bin/credential_patterns.py", destinations)
        compile_line = re.search(r"py_compile (.*?)\nrm -rf", text, re.S)
        self.assertTrue(compile_line, "the py_compile invocation was not found")
        after = text.split("== post-conditions", 1)
        self.assertEqual(len(after), 2, "the post-conditions section was not found")
        postconditions = re.search(r"for f in (.*?); do", after[1], re.S)
        self.assertTrue(postconditions, "the post-condition loop was not found")
        for destination in destinations:
            self.assertIn(destination, compile_line.group(1), destination)
            self.assertIn(destination, postconditions.group(1), destination)

    def test_dry_run_prints_the_planned_directories_with_their_modes(self):
        rc, out = self.dry("--watch", "repo=/tmp/x")
        self.assertEqual(rc, 0, out)
        self.assertIn("0755  " + DEST + "/store", out)
        self.assertIn("0700  " + DEST + "/vault", out)
        self.assertIn("0700  " + DEST + "/var/tmp", out)

    def test_dry_run_reports_the_owner_uid_it_was_given(self):
        rc, out = self.dry("--watch", "repo=/tmp/x", "--owner-uid", "777")
        self.assertEqual(rc, 0, out)
        self.assertIn("owner uid    : 777", out)
        self.assertIn("owner_uid = 777", out)

    def test_dry_run_changes_nothing_under_the_install_root(self):
        before = snapshot_dest()
        rc, out = self.dry("--watch", "repo=/tmp/x", "--owner-uid", "501")
        self.assertEqual(rc, 0, out)
        after = snapshot_dest()
        self.assertEqual(before, after, "the dry run changed " + DEST)

    def test_dry_run_creates_no_install_root(self):
        """A dry run must not bring the install root into existence.

        This used to skip outright on a machine that already had an install
        ("this machine has a live install at ..."), which meant it ran on clean
        hosts and never on the author's. The invariant it is really asserting —
        a dry run does not CREATE the root — holds on both, and is asserted on
        both by comparing existence across the run rather than demanding a
        particular starting state.
        """
        existed = os.path.isdir(DEST)
        rc, out = self.dry("--watch", "repo=/tmp/x")
        self.assertEqual(rc, 0, out)
        self.assertEqual(os.path.isdir(DEST), existed,
                         "the dry run changed whether " + DEST + " exists")
        if not existed:
            self.assertFalse(os.path.exists(DEST))

    def test_watchlist_file_is_read_and_rendered(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
            fh.write("# a comment\n\nrepo   /tmp/a\nwork   /tmp/b/*\n")
            path = fh.name
        try:
            rc, out = self.dry("--watchlist", path)
            self.assertEqual(rc, 0, out)
            self.assertIn("repo         /tmp/a", out)
            self.assertIn("work         /tmp/b/*", out)
        finally:
            os.unlink(path)

    def test_watchlist_file_and_watch_flags_combine(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
            fh.write("repo /tmp/a\n")
            path = fh.name
        try:
            rc, out = self.dry("--watchlist", path, "--watch", "scratch=/tmp/c")
            self.assertEqual(rc, 0, out)
            self.assertIn("repo         /tmp/a", out)
            self.assertIn("scratch      /tmp/c", out)
        finally:
            os.unlink(path)

    def test_watchlist_file_with_a_bad_line_refuses_the_whole_install(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
            fh.write("repo /tmp/a\nBAD /tmp/b\n")
            path = fh.name
        try:
            rc, out = self.dry("--watchlist", path)
            self.assertEqual(rc, 2, out)
            self.assertIn("bad root id", out)
            self.assertIn("BAD", out)
        finally:
            os.unlink(path)

    def test_watchlist_file_with_no_roots_is_refused(self):
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
            fh.write("# nothing but a comment\n")
            path = fh.name
        try:
            rc, out = self.dry("--watchlist", path)
            self.assertEqual(rc, 2, out)
            self.assertIn("named no roots", out)
            self.assertIn("Nothing has been changed", out)
        finally:
            os.unlink(path)

    def test_missing_watchlist_file_is_refused(self):
        rc, out = self.dry("--watchlist", "/nonexistent/nope.conf")
        self.assertEqual(rc, 2, out)
        self.assertIn("no such watchlist file", out)


class InstallArgumentTest(unittest.TestCase):
    """Strict parsing: an unknown flag is a usage error, never ignored."""

    def test_unknown_flag_exits_2_with_usage(self):
        rc, out = run_bash([INSTALL, "--wat"])
        self.assertEqual(rc, 2, out)
        self.assertIn("unknown argument: --wat", out)
        self.assertIn("usage:", out)

    def test_bare_positional_argument_exits_2(self):
        rc, out = run_bash([INSTALL, "/tmp/x"])
        self.assertEqual(rc, 2, out)
        self.assertIn("unknown argument", out)

    def test_watch_without_a_value_exits_2(self):
        rc, out = run_bash([INSTALL, "--watch"])
        self.assertEqual(rc, 2, out)
        self.assertIn("--watch needs", out)

    def test_watchlist_without_a_value_exits_2(self):
        rc, out = run_bash([INSTALL, "--watchlist"])
        self.assertEqual(rc, 2, out)
        self.assertIn("--watchlist needs", out)

    def test_owner_uid_without_a_value_exits_2(self):
        rc, out = run_bash([INSTALL, "--owner-uid"])
        self.assertEqual(rc, 2, out)
        self.assertIn("--owner-uid needs", out)

    def test_non_numeric_owner_uid_exits_2(self):
        rc, out = run_bash([INSTALL, "--dry-run", "--watch", "repo=/tmp/x", "--owner-uid", "abc"])
        self.assertEqual(rc, 2, out)
        self.assertIn("must be a number", out)

    def test_no_owner_uid_and_no_sudo_uid_is_refused(self):
        """No default uid: a root shell without sudo has no SUDO_UID, and
        `${SUDO_UID:-501}` would silently protect the first macOS account."""
        rc, out = run_bash([INSTALL, "--dry-run", "--watch", "repo=/tmp/x"],
                           env={"SUDO_UID": None})
        self.assertEqual(rc, 2)
        self.assertIn("no $SUDO_UID", out)
        self.assertIn("--owner-uid", out)

    def test_owner_uid_zero_is_refused(self):
        """uid 0 would make admission (st_uid == owner_uid) refuse everything."""
        rc, out = run_bash([INSTALL, "--dry-run", "--watch", "repo=/tmp/x", "--owner-uid", "0"])
        self.assertEqual(rc, 2, out)
        self.assertIn("protect nothing", out)

    def test_help_exits_0_and_documents_the_flags(self):
        rc, out = run_bash([INSTALL, "--help"])
        self.assertEqual(rc, 0, out)
        for flag in ("--watch", "--watchlist", "--owner-uid", "--dry-run"):
            self.assertIn(flag, out)

    def test_invalid_root_is_refused_before_the_root_check(self):
        """A refusal a non-root user can see is a refusal they can act on."""
        rc, out = run_bash([INSTALL, "--dry-run", "--watch", "repo=relative/path"])
        self.assertEqual(rc, 2, out)
        self.assertIn("not absolute", out)
        self.assertNotIn("must run as root", out)

    @requires_non_root
    def test_real_run_without_root_refuses_and_changes_nothing(self):
        before = snapshot_dest()
        rc, out = run_bash([INSTALL, "--watch", "repo=/tmp/x"])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("must run as root", out)
        self.assertEqual(before, snapshot_dest())


#: Compute and print the plan for an install root given as `$1`, exactly the way
#: the script's own flow does it: gather the presence facts with
#: `uninstall_state`, measure the three sizes with `dir_size`, hand both to
#: `print_plan_for`. $2 loaded, $3 service-file present, $4 purge.
PLAN_SNIPPET = (
    'state="$(uninstall_state "$1")"\n'
    'print_plan_for "$1" "$state" "$2" "$3" "$4" \\\n'
    '  "$(dir_size "$1/store")" "$(dir_size "$1/vault")" "$(dir_size "$1/var")"\n'
)

#: The `--purge` without `--yes` refusal, for the same root. $2..$4 unused.
REFUSAL_SNIPPET = (
    'print_purge_refusal "$1" "$(dir_size "$1/store")" \\\n'
    '  "$(dir_size "$1/vault")" "$(dir_size "$1/var")"\n'
)


class DocumentedTestCountTest(unittest.TestCase):
    """The test count printed in the docs must be the real one.

    It rotted within a week: three files claimed 413 while the suite ran 521,
    because every commit that added tests updated none of them. A number in a
    README is a claim like any other, and an unchecked claim drifts. Checking it
    costs one discovery pass and turns "remember to update the docs" into a
    failing test that says which file to edit.
    """

    DOCS = ("README.md", "CONTRIBUTING.md", "docs/PROOFS.md")

    def test_the_docs_state_the_number_of_tests_that_actually_run(self):
        loader = unittest.TestLoader()
        suite = loader.discover(os.path.dirname(os.path.abspath(__file__)), pattern="test_*.py")
        self.assertEqual(loader.errors, [], "discovery itself failed: %s" % loader.errors)

        def count(item):
            return sum(count(child) for child in item) if hasattr(item, "__iter__") else 1

        actual = count(suite)
        for name in self.DOCS:
            path = os.path.join(REPO_ROOT, name)
            text = open(path).read()
            claimed = re.findall(r"(\d{3,})[ -]test", text)
            self.assertTrue(claimed, "%s states no test count; add one or drop it "
                                     "from DOCS here" % name)
            for number in claimed:
                self.assertEqual(
                    int(number), actual,
                    "%s claims %s tests, the suite runs %d. Update the document."
                    % (name, number, actual))


class HeartbeatTimeoutVerdictTest(unittest.TestCase):
    """A heartbeat timeout is TWO different facts, and it used to report one.

    Found on a real install: the installer waited 60s, saw no new heartbeat and
    printed "this daemon did not start". The daemon had started and was part-way
    through a first scan of a 33 GB directory inside a watch root. The operator
    was told the wrong thing and pointed at the wrong remedy — the same
    silent-fallback shape this project forbids in the daemon, one layer out: a
    report stating more than the evidence supports.
    """

    def verdict(self, loaded, pid):
        rc, out = call_snippet(INSTALL, 'heartbeat_timeout_verdict "$1" "$2"',
                               str(loaded), pid)
        self.assertEqual(rc, 0, out)
        return out.strip()

    def test_loaded_with_a_live_pid_is_a_scan_in_progress(self):
        self.assertEqual(self.verdict(1, "4242"), "still-scanning")

    def test_every_other_combination_is_a_failure_to_start(self):
        # Loaded but no pid is the launchd shape for a job that is known and
        # not running, so it belongs with the failures, not with the waits.
        for loaded, pid in ((1, ""), (0, "4242"), (0, "")):
            self.assertEqual(self.verdict(loaded, pid), "did-not-start",
                             "loaded=%s pid=%r" % (loaded, pid))

    def test_the_timeout_branch_names_the_exclusion_remedy(self):
        """The remedy for a slow first scan is a directory the operator can skip.

        Asserted because the message is the whole value of the fix: a reader who
        is told "still scanning" and not told what to do about a directory that
        should never have been walked is only half-served.
        """
        source = open(INSTALL).read()
        branch = source[source.index("no NEW heartbeat within"):]
        branch = branch[:branch.index("exit 1")]
        self.assertIn("exclude.conf", branch)
        self.assertIn("FIRST SCAN", branch)


class UninstallWatchRootsTest(unittest.TestCase):
    """`print_watch_roots_for` — the flags that make an uninstall reversible.

    `etc/watchlist.conf` is the only record of WHICH directories were protected,
    it lives in `etc/`, and every uninstall removes `etc/` while KEEPING
    `store/`. Found on the Ubuntu VM (2026-09-07): after an uninstall, a
    re-install with no `--watch` refuses with "no watch roots" — correct, since
    there is no default watchlist, but it leaves the operator holding captured
    history for directories they can no longer name. So the uninstall hands the
    list back as ready-to-paste flags.
    """

    def roots_output(self, lines):
        """Run the printer against a fabricated root whose watchlist is `lines`.

        `None` means: do not create the file at all.
        """
        base = tempfile.mkdtemp(prefix="dhu-uninstall-roots-")
        self.addCleanup(shutil.rmtree, base, True)
        os.mkdir(os.path.join(base, "etc"))
        if lines is not None:
            with open(os.path.join(base, "etc", "watchlist.conf"), "w") as handle:
                handle.write(lines)
        rc, out = call_snippet(UNINSTALL, 'print_watch_roots_for "$1"', base)
        self.assertEqual(rc, 0, out)
        return out

    def test_it_prints_each_root_as_a_watch_flag(self):
        out = self.roots_output("# a comment\nrepo       /home/a/proj\nother      /home/a/two\n")
        self.assertIn("re-create them with:", out)
        self.assertIn("--watch 'repo=/home/a/proj'", out)
        self.assertIn("--watch 'other=/home/a/two'", out)
        self.assertNotIn("# a comment", out)

    def test_a_glob_root_is_quoted_so_pasting_cannot_expand_it(self):
        """The one glob the watchlist permits is a TRAILING `*`.

        Unquoted, the shell that pastes the line would expand it against the
        pasting user's cwd, and the re-install would protect something other
        than what was protected. That is a silent substitution, so the quoting
        is asserted rather than assumed.
        """
        out = self.roots_output("worktrees  /home/a/.claude/worktrees/*\n")
        self.assertIn("--watch 'worktrees=/home/a/.claude/worktrees/*'", out)
        self.assertNotIn("--watch worktrees=", out)

    def test_an_absent_watchlist_says_so_rather_than_printing_nothing(self):
        out = self.roots_output(None)
        self.assertIn("none recorded", out)
        self.assertIn("absent", out)

    def test_a_watchlist_with_no_entries_says_so(self):
        out = self.roots_output("# every line is a comment\n\n")
        self.assertIn("none recorded", out)
        self.assertIn("names no roots", out)

    def test_the_plan_carries_the_flags_when_etc_is_present(self):
        """The printer is wired into the plan, not merely defined."""
        base = fabricate_install_root(self)
        with open(os.path.join(base, "etc", "watchlist.conf"), "w") as handle:
            handle.write("repo  /home/a/proj\n")
        rc, out = call_snippet(
            UNINSTALL,
            'state=$(uninstall_state "$1"); print_plan_for "$1" "$state" 0 0 0 1K 1K 1K',
            base)
        self.assertEqual(rc, 0, out)
        self.assertIn("--watch 'repo=/home/a/proj'", out)


class UninstallPlanTest(unittest.TestCase):
    """The uninstall PLAN, driven against a FABRICATED install root.

    These four assertions used to run the real `uninstall.sh --dry-run` and read
    whatever was in the live install root. On the author's Mac an install exists
    and the script prints its plan; on a clean machine it correctly takes the
    "nothing to uninstall" early exit and prints no plan at all, so all four
    failed on a fresh Ubuntu VM (2026-09-07) for a reason that had nothing to do
    with the behaviour under test — a claim and its evidence not sharing a
    population. `uninstall.sh` now computes its plan in functions that take the
    root as an argument, so the plan can be asserted anywhere, with or without an
    install. The end-to-end runs the real script still gets are below, and they
    assert only what is true either way.
    """

    def plan(self, root, loaded=0, service_file=0, purge=0):
        rc, out = call_snippet(UNINSTALL, PLAN_SNIPPET, root,
                               str(loaded), str(service_file), str(purge))
        self.assertNotEqual(rc, 99, "the script failed to source:\n" + out)
        self.assertEqual(rc, 0, out)
        return out

    def test_plan_for_a_full_install_lists_removals_and_keeps(self):
        root = fabricate_install_root(self)
        out = self.plan(root, loaded=1, service_file=1)
        self.assertIn("would REMOVE:", out)
        self.assertIn(SERVICE_NAME, out)
        self.assertIn(SERVICE_FILE, out)
        self.assertIn(root + "/bin", out)
        self.assertIn(root + "/etc", out)
        self.assertIn("would KEEP", out)
        for kept in (root + "/store", root + "/vault", root + "/var"):
            self.assertIn(kept, out)
        self.assertIn("sudo rm -rf " + root, out)

    def test_plan_names_the_service_stop_command_only_when_it_is_loaded(self):
        root = fabricate_install_root(self)
        stop = ("systemctl disable --now " + SERVICE_NAME + ".service" if IS_LINUX
                else "launchctl bootout system/" + SERVICE_NAME)
        self.assertIn(stop, self.plan(root, loaded=1, service_file=1))
        self.assertNotIn(stop, self.plan(root, loaded=0, service_file=0))

    def test_plan_names_only_the_directories_that_are_present(self):
        """A half-removed install: bin/ and store/ left, etc/ already gone."""
        root = fabricate_install_root(self, subdirs=("bin", "store"))
        out = self.plan(root, loaded=0, service_file=0)
        self.assertIn(root + "/bin", out)
        self.assertNotIn(root + "/etc   (dhu-backupd.conf", out)
        self.assertIn(root + "/vault  (absent)", out)
        self.assertIn(root + "/var    (absent)", out)

    def test_plan_with_purge_says_it_would_delete_rather_than_keep(self):
        root = fabricate_install_root(self)
        out = self.plan(root, loaded=1, service_file=1, purge=1)
        self.assertIn("would DELETE", out)
        self.assertIn("NOT recoverable", out)
        self.assertNotIn("would KEEP", out)
        for doomed in (root + "/store", root + "/vault", root + "/var"):
            self.assertIn(doomed, out)

    def test_purge_without_yes_refusal_names_the_data_and_changes_nothing(self):
        root = fabricate_install_root(self)
        rc, out = call_snippet(UNINSTALL, REFUSAL_SNIPPET, root, "0", "0", "0")
        self.assertEqual(rc, 0, out)
        for named in (root + "/store", root + "/vault", root + "/var"):
            self.assertIn(named, out)
        self.assertIn("--purge --yes", out)
        self.assertIn("Nothing has been changed", out)
        self.assertTrue(os.path.isdir(root + "/store"), "the refusal deleted data")

    def test_state_reports_each_directory_independently(self):
        root = fabricate_install_root(self, subdirs=("bin", "var"))
        rc, out = call_function(UNINSTALL, "uninstall_state", root)
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.strip(), "bin=1 etc=0 store=0 vault=0 var=1")

    def test_nothing_to_uninstall_is_the_clean_machine_path(self):
        """The early exit a machine with no install gets. Previously untested.

        It is reachable only when the service is not loaded, the service file is
        absent AND the root does not exist; any one of those being true flips it
        back to the plan.
        """
        missing = os.path.join(tempfile.mkdtemp(prefix="dhu-clean-"), "no-install")
        self.addCleanup(shutil.rmtree, os.path.dirname(missing), True)

        rc, _ = call_function(UNINSTALL, "uninstall_nothing_to_do", missing, "0", "0")
        self.assertEqual(rc, 0, "a clean machine must take the early exit")
        for loaded, service_file in ((1, 0), (0, 1), (1, 1)):
            rc, _ = call_function(UNINSTALL, "uninstall_nothing_to_do", missing,
                                  str(loaded), str(service_file))
            self.assertNotEqual(rc, 0, "loaded=%s service_file=%s" % (loaded, service_file))
        rc, _ = call_function(UNINSTALL, "uninstall_nothing_to_do",
                              fabricate_install_root(self), "0", "0")
        self.assertNotEqual(rc, 0, "an existing root is not nothing to uninstall")

    def test_nothing_to_uninstall_banner_names_the_absent_things(self):
        rc, out = call_function(UNINSTALL, "print_nothing_to_uninstall", "/no/such/root")
        self.assertEqual(rc, 0, out)
        self.assertIn("nothing to uninstall", out)
        self.assertIn(SERVICE_NAME, out)
        self.assertIn(SERVICE_FILE + "   (absent)", out)
        self.assertIn("/no/such/root   (absent)", out)


class UninstallTest(unittest.TestCase):
    """The real `uninstall.sh`, run end to end.

    Everything asserted here is true whether or not this machine has an install.
    Anything that depends on one is in `UninstallPlanTest` above.
    """

    def test_dry_run_exits_zero_and_prints_a_plan_or_says_there_is_nothing(self):
        """The disjunction is the assertion, deliberately.

        A dry run on a machine WITH an install prints the plan; on a clean one
        it prints the "nothing to uninstall" report. Both are correct and both
        exit 0, so asserting either one alone would be asserting this machine's
        ambient state. Which branch the text belongs to is asserted against a
        fabricated root in `UninstallPlanTest`; what this proves is that the
        real script, on whatever machine is running it, exits 0 and says one of
        the two things rather than falling through silently.
        """
        rc, out = run_bash([UNINSTALL, "--dry-run"])
        self.assertEqual(rc, 0, out)
        self.assertIn(SERVICE_NAME, out)
        self.assertIn(DEST, out)
        planned = "would REMOVE:" in out and "DRY RUN" in out
        nothing = "nothing to uninstall" in out
        self.assertTrue(planned != nothing,
                        "expected exactly one of a plan or 'nothing to "
                        "uninstall', got:\n" + out)
        if planned:
            for kept in (DEST + "/store", DEST + "/vault", DEST + "/var"):
                self.assertIn(kept, out)

    def test_dry_run_prints_the_two_deregistration_steps(self):
        rc, out = run_bash([UNINSTALL, "--dry-run"])
        self.assertEqual(rc, 0, out)
        self.assertIn("PostToolUseFailure", out)
        self.assertIn("claude mcp remove -s user dhu-backup", out)
        self.assertIn("~/.claude/settings.json", out)

    def test_dry_run_changes_nothing(self):
        before = snapshot_dest()
        rc, out = run_bash([UNINSTALL, "--dry-run"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(before, snapshot_dest())

    def test_purge_without_yes_never_deletes_whatever_this_machine_has(self):
        """Exit 2 with the refusal where there IS data, exit 0 where there is not.

        The refusal is only reachable once the "nothing to uninstall" early exit
        has been passed, so on a clean machine `--purge` correctly reports that
        there is nothing rather than refusing to delete nothing. The refusal
        TEXT is asserted against a fabricated root in `UninstallPlanTest`.
        """
        rc, out = run_bash([UNINSTALL, "--purge"])
        if "nothing to uninstall" in out:
            self.assertEqual(rc, 0, out)
        else:
            self.assertEqual(rc, 2, out)
            for named in (DEST + "/store", DEST + "/vault", DEST + "/var"):
                self.assertIn(named, out)
            self.assertIn("--purge --yes", out)
            self.assertIn("Nothing has been changed", out)

    def test_purge_without_yes_changes_nothing(self):
        before = snapshot_dest()
        run_bash([UNINSTALL, "--purge"])
        self.assertEqual(before, snapshot_dest())

    def test_purge_dry_run_exits_zero_and_never_says_it_would_keep(self):
        """`--purge --yes --dry-run` on any machine: exit 0, no "would KEEP".

        With an install it prints the DELETE plan; without one it prints the
        "nothing to uninstall" report. Neither may ever claim the history would
        be kept, which is the half of this that holds regardless.
        """
        rc, out = run_bash([UNINSTALL, "--purge", "--yes", "--dry-run"])
        self.assertEqual(rc, 0, out)
        self.assertNotIn("would KEEP", out)
        if "nothing to uninstall" not in out:
            self.assertIn("would DELETE", out)
            self.assertIn("NOT recoverable", out)

    def test_purge_dry_run_changes_nothing(self):
        before = snapshot_dest()
        run_bash([UNINSTALL, "--purge", "--yes", "--dry-run"])
        self.assertEqual(before, snapshot_dest())

    def test_unknown_flag_exits_2_with_usage(self):
        rc, out = run_bash([UNINSTALL, "--nope"])
        self.assertEqual(rc, 2, out)
        self.assertIn("unknown argument: --nope", out)
        self.assertIn("usage:", out)

    def test_help_exits_0(self):
        rc, out = run_bash([UNINSTALL, "--help"])
        self.assertEqual(rc, 0, out)
        for flag in ("--dry-run", "--purge", "--yes"):
            self.assertIn(flag, out)

    @requires_non_root
    def test_real_run_without_root_refuses_or_finds_nothing_and_changes_nothing(self):
        """The root check is reached only when there is something to remove.

        On a clean machine the script exits 0 at "nothing to uninstall" before
        it ever asks who is running it, which is right: refusing to do nothing
        for lack of privilege would be a worse answer than saying there is
        nothing to do. Either way it must not change the machine.
        """
        before = snapshot_dest()
        rc, out = run_bash([UNINSTALL])
        if "nothing to uninstall" in out:
            self.assertEqual(rc, 0, out)
        else:
            self.assertNotEqual(rc, 0, out)
            self.assertIn("must run as root", out)
        self.assertEqual(before, snapshot_dest())


class PlatformFlagTest(unittest.TestCase):
    """`--platform` on both scripts: the OTHER platform's plan, dry-run only.

    It exists so the plan a Linux host would execute can be read and asserted
    from a Mac, and vice versa. It changes the install root, the service manager
    and the service file, so a real run under it would install or remove the
    wrong platform's daemon — which is why it is an ERROR without --dry-run
    rather than a warning. A flag that is quietly ignored is a flag someone
    relies on.
    """

    def test_install_dry_run_for_the_other_platform_names_its_root(self):
        rc, out = run_bash([INSTALL, "--dry-run", "--platform", OTHER_PLATFORM,
                            "--owner-uid", "1000", "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 0, out)
        self.assertIn(OTHER_DEST, out)
        self.assertIn(OTHER_SERVICE_FILE, out)
        self.assertIn("platform     : " + OTHER_PLATFORM, out)

    def test_install_dry_run_for_linux_names_opt_and_systemctl(self):
        """Asserted by name, from either platform: this is the Linux plan."""
        rc, out = run_bash([INSTALL, "--dry-run", "--platform", "linux",
                            "--owner-uid", "1000", "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 0, out)
        self.assertIn("/opt/dhu-backup", out)
        self.assertIn("/etc/systemd/system/dhu-backupd.service", out)
        self.assertIn("systemctl", out)
        self.assertIn("0755  /opt/dhu-backup/store", out)
        self.assertIn("0700  /opt/dhu-backup/vault", out)
        self.assertNotIn("launchctl", out)

    def test_install_dry_run_for_darwin_names_library_and_launchctl(self):
        rc, out = run_bash([INSTALL, "--dry-run", "--platform", "darwin",
                            "--owner-uid", "501", "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 0, out)
        self.assertIn("/Library/DHU/backup", out)
        self.assertIn("/Library/LaunchDaemons/com.dhulabs.backup.plist", out)
        self.assertIn("launchctl", out)
        self.assertNotIn("systemctl", out)

    def test_install_dry_run_says_which_platform_this_machine_is(self):
        """The override is announced, so a plan is never mistaken for this host."""
        rc, out = run_bash([INSTALL, "--dry-run", "--platform", OTHER_PLATFORM,
                            "--owner-uid", "1000", "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 0, out)
        self.assertIn("--platform override", out)

    def test_install_platform_without_dry_run_exits_2_and_changes_nothing(self):
        before = snapshot_dest()
        rc, out = run_bash([INSTALL, "--platform", "linux", "--owner-uid", "1000",
                            "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 2, out)
        self.assertIn("only valid together with --dry-run", out)
        self.assertIn("Nothing has been changed", out)
        self.assertEqual(before, snapshot_dest())

    def test_install_rejects_an_unknown_platform(self):
        rc, out = run_bash([INSTALL, "--dry-run", "--platform", "plan9",
                            "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 2, out)
        self.assertIn("darwin or linux", out)

    def test_uninstall_dry_run_for_linux_names_the_unit_and_opt(self):
        rc, out = run_bash([UNINSTALL, "--dry-run", "--platform", "linux"])
        self.assertEqual(rc, 0, out)
        self.assertIn("/opt/dhu-backup", out)
        self.assertIn("/etc/systemd/system/dhu-backupd.service", out)
        self.assertIn("dhu-backupd", out)

    def test_uninstall_dry_run_for_darwin_names_the_plist_and_library(self):
        rc, out = run_bash([UNINSTALL, "--dry-run", "--platform", "darwin"])
        self.assertEqual(rc, 0, out)
        self.assertIn("/Library/DHU/backup", out)
        self.assertIn("com.dhulabs.backup", out)

    def test_uninstall_platform_without_dry_run_exits_2_and_changes_nothing(self):
        before = snapshot_dest()
        rc, out = run_bash([UNINSTALL, "--platform", "linux"])
        self.assertEqual(rc, 2, out)
        self.assertIn("only valid together with --dry-run", out)
        self.assertEqual(before, snapshot_dest())

    def test_uninstall_rejects_an_unknown_platform(self):
        rc, out = run_bash([UNINSTALL, "--dry-run", "--platform", "plan9"])
        self.assertEqual(rc, 2, out)
        self.assertIn("darwin or linux", out)

    def test_the_other_platforms_dry_run_changes_nothing_here(self):
        before = snapshot_dest()
        run_bash([INSTALL, "--dry-run", "--platform", OTHER_PLATFORM,
                  "--owner-uid", "1000", "--watch", "repo=/tmp/x"])
        run_bash([UNINSTALL, "--dry-run", "--platform", OTHER_PLATFORM])
        self.assertEqual(before, snapshot_dest())


class NoServiceFlagTest(unittest.TestCase):
    """`--no-service` installs the files and registers nothing.

    It exists for a container, where the daemon can be started by hand but there
    is no service manager to register with. The gate is a fact about the MACHINE
    — the absence of /run/systemd/system — not a promise from the caller, so on
    a real booted Linux host the flag refuses. On macOS it refuses outright.
    """

    def test_it_is_refused_on_macos(self):
        if IS_LINUX:
            self.skipTest("macOS-only refusal")
        rc, out = run_bash([INSTALL, "--no-service", "--owner-uid", "501",
                            "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 2, out)
        self.assertIn("Linux only", out)

    def test_it_is_refused_where_systemd_is_running(self):
        if not IS_LINUX or not os.path.isdir("/run/systemd/system"):
            self.skipTest("needs a booted systemd host")
        rc, out = run_bash([INSTALL, "--no-service", "--owner-uid", "1000",
                            "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 2, out)
        self.assertIn("systemd manager IS running", out)

    def test_it_changes_nothing_when_refused(self):
        """Only where the flag IS refused — otherwise this is a real install.

        On Linux with no systemd manager (a container) the flag is permitted by
        design, and running it here as root would install the product rather
        than assert a refusal. That is the third test in this file to have had
        that shape; the pattern is now named rather than repeated.
        """
        if IS_LINUX and not os.path.isdir("/run/systemd/system"):
            self.skipTest("--no-service is PERMITTED here; this run would be a real install")
        before = snapshot_dest()
        rc, out = run_bash([INSTALL, "--no-service", "--owner-uid", "501",
                            "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 2, out)
        self.assertEqual(before, snapshot_dest())

    def test_the_gate_is_the_absence_of_a_running_systemd(self):
        """Asserted in the source: the check must be on /run/systemd/system.

        A gate on `--dry-run`, on an environment variable, or on anything the
        caller supplies would let the flag be used on a real host, where an
        unregistered root process does not survive a reboot and none of the
        installer's post-conditions describe what is actually running.
        """
        with open(INSTALL) as handle:
            text = handle.read()
        self.assertIn("/run/systemd/system", text)
        self.assertRegex(
            text, r"systemd_is_running\(\)\s*\{\s+\[ -d /run/systemd/system \]")

    def test_a_no_service_install_never_claims_a_running_daemon(self):
        """The heartbeat wait cannot apply when nothing was started.

        With no service registered there is no process to have written a
        heartbeat, so the script must say what it did and did not prove rather
        than skipping the section quietly.
        """
        with open(INSTALL) as handle:
            text = handle.read()
        self.assertIn("no daemon was started, so there is NO heartbeat", text)


class InterpreterCheckTest(unittest.TestCase):
    """The installer asserts its interpreter before writing a service file."""

    def test_the_plan_reports_a_verdict_on_the_interpreter(self):
        rc, out = run_bash([INSTALL, "--dry-run", "--watch", "repo=/tmp/x",
                            "--owner-uid", "501"])
        self.assertEqual(rc, 0, out)
        self.assertIn("interpreter (review H2", out)
        self.assertRegex(out, r"\n  (OK|REFUSED) ")

    def test_the_plan_names_the_interpreter_it_checked(self):
        rc, out = run_bash([INSTALL, "--dry-run", "--watch", "repo=/tmp/x",
                            "--owner-uid", "501"])
        self.assertEqual(rc, 0, out)
        self.assertIn("interpreter  : /usr/bin/python3", out)

    def test_the_check_runs_before_anything_is_written(self):
        """Ordered in the source: the refusal is above the first install(1).

        A service file naming an interpreter an agent can replace cannot be
        fixed by re-running the installer — the daemon is already loaded.
        """
        with open(INSTALL) as handle:
            text = handle.read()
        refusal = text.index("refusing to install: $INTERP_REASON")
        first_write = text.index('install -d -o root -g 0 -m "$_mode"')
        self.assertLess(refusal, first_write)

    def test_it_uses_the_one_pure_function_rather_than_a_second_copy(self):
        """One rule, one place. The daemon runs the same function at startup."""
        with open(INSTALL) as handle:
            text = handle.read()
        self.assertIn("dhu_backup_core.interpreter_verdict", text)


class ProductNeutralityTest(unittest.TestCase):
    """`src/` must carry nothing from the machine it was written on.

    Every path this project ships is either a fixed install root, a documented
    placeholder, or a value the operator supplies at install time. A real home
    directory in the source is how a personal path becomes a default that a
    stranger then inherits, so it is asserted against rather than reviewed for.

    The two placeholders are `/Users/you` and `/home/you`. `/Users/fixture` is
    reserved for the test fixtures in the sibling suites and is not accepted
    here, because nothing under `src/` needs a fabricated home at all.
    """

    #: A home-directory path naming anyone. The placeholders are the only
    #: accepted spellings, and `/Users` / `/home` with no name after them (a
    #: prose mention of the directory itself) is not a match.
    HOME_PATH = re.compile(r"/(?:Users|home)/(?!you\b)[A-Za-z0-9][A-Za-z0-9._-]*")

    def src_files(self):
        for dirpath, dirnames, filenames in os.walk(SRC):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for name in sorted(filenames):
                yield os.path.join(dirpath, name)

    def test_no_real_home_directory_appears_anywhere_in_src(self):
        offenders = []
        for path in self.src_files():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()
            except (UnicodeDecodeError, OSError):
                continue
            rel = os.path.relpath(path, REPO_ROOT)
            for n, line in enumerate(lines, 1):
                if self.HOME_PATH.search(line):
                    offenders.append("%s:%d: %s" % (rel, n, line.rstrip()))
        self.assertEqual(offenders, [], "\n".join(offenders))

    def test_the_placeholder_home_is_actually_used(self):
        """A regex nothing exercises is a regex that could be wrong.

        `src/README.md` shows the install command with a watch root, so the
        placeholder has to appear somewhere in `src/` for the rule above to be
        doing any work at all.
        """
        found = False
        for path in self.src_files():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    text = fh.read()
            except (UnicodeDecodeError, OSError):
                continue
            if "/Users/you" in text or "/home/you" in text:
                found = True
                break
        self.assertTrue(found, "no placeholder home directory in src/")

    def test_the_rule_catches_a_real_home_directory(self):
        """The assertion is only worth what its regex catches."""
        for bad in ["/Users/alice/Projects/x", "/home/bob/proj", "~/x /home/carol/y"]:
            self.assertIsNotNone(self.HOME_PATH.search(bad), bad)
        for ok in ["/Users/you/Projects/x", "/home/you/proj", "/Library/DHU/backup"]:
            self.assertIsNone(self.HOME_PATH.search(ok), ok)


class ExampleWatchlistTest(unittest.TestCase):
    def test_the_personal_watchlist_is_gone(self):
        self.assertFalse(os.path.exists(os.path.join(SRC, "watchlist.conf")))

    def test_the_example_exists(self):
        self.assertTrue(os.path.isfile(os.path.join(SRC, "watchlist.conf.example")))

    def test_every_example_root_is_commented_out(self):
        """An uncommented example line would become a real watch root."""
        with open(os.path.join(SRC, "watchlist.conf.example")) as fh:
            for n, line in enumerate(fh, 1):
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    self.fail("line %d is not a comment: %s" % (n, stripped))

    def test_the_example_shows_the_three_shapes(self):
        with open(os.path.join(SRC, "watchlist.conf.example")) as fh:
            text = fh.read()
        self.assertIn("# repo ", text)
        self.assertIn("# worktrees ", text)
        self.assertIn("# scratch ", text)
        self.assertIn("$TMPDIR", text)

    def test_the_installer_does_not_install_the_example(self):
        with open(INSTALL) as fh:
            text = fh.read()
        self.assertNotIn("watchlist.conf.example\"", text)
        self.assertNotIn("$SRC/watchlist.conf", text)


if __name__ == "__main__":
    unittest.main()


class InstallStateVerdictTest(unittest.TestCase):
    """What the installer does with the heartbeat the daemon just wrote.

    Extracted from the post-install block into a pure bash function for exactly
    the reason the Python decision functions are pure: the block itself needs a
    real install, a real daemon and a real heartbeat to reach, and a guard that
    can only be tested that way is a guard that is tested rarely.
    """

    def verdict(self, label):
        code, out = call_function(INSTALL, "install_state_verdict", label)
        self.assertEqual(code, 0, out)
        return out.strip()

    def test_ok_is_ok(self):
        self.assertEqual(self.verdict("ok"), "ok")

    def test_warning_is_ACCEPTED_and_is_not_ok(self):
        """A fresh install on a nearly-full volume works, and must say so.

        Accepted, because refusing to finish an install that is working leaves a
        human deciding whether a failed installer installed anything. NOT `ok`,
        because the caller must print something other than the OK line.
        """
        self.assertEqual(self.verdict("warning"), "warning")
        self.assertNotEqual(self.verdict("warning"), self.verdict("ok"))

    def test_every_failing_state_the_daemon_can_write_is_a_failure(self):
        for label in ("degraded", "unprotected", "scan-failed"):
            self.assertEqual(self.verdict(label), "fail", label)

    def test_a_label_this_script_does_not_know_is_a_failure_not_an_ok(self):
        """The same rule the Python `health_verdict` follows, in the shell."""
        for label in ("quiescing", "warn", "WARNING", "OK", "", "ok ", "okay"):
            self.assertEqual(self.verdict(label), "fail", repr(label))

    def test_a_missing_argument_is_a_failure(self):
        code, out = run_bash(["-c",
                              'DHU_BACKUP_SOURCE_ONLY=1 . "$1" || exit 99\n'
                              'install_state_verdict\n', "_", INSTALL])
        self.assertEqual(code, 0, out)
        self.assertEqual(out.strip(), "fail")

    def test_the_verdict_has_exactly_three_outcomes(self):
        """A fourth would be a caller branch nobody wrote."""
        seen = set(self.verdict(label) for label in
                   ["ok", "warning", "degraded", "unprotected", "scan-failed",
                    "stale", "", "nonsense"])
        self.assertEqual(seen, {"ok", "warning", "fail"})


class InstallWarningBannerTest(unittest.TestCase):
    """The post-install block, read as source: which line each verdict prints."""

    def setUp(self):
        with open(INSTALL) as handle:
            self.source = handle.read()

    def test_the_bare_OK_line_is_printed_only_on_the_ok_branch(self):
        """"OK — the daemon is running and protecting the roots above" over a
        volume that will stop capture next week is the silent success this
        section exists to prevent."""
        block = self.source[self.source.index("STATE_VERDICT=$(install_state_verdict"):]
        block = block[:block.index("\n  fi\n")]
        warning_branch = block.index('if [ "$STATE_VERDICT" = "warning" ]')
        else_branch = block.index("\n    else\n", warning_branch)
        ok_line = block.index('echo "OK — the daemon is running')
        self.assertGreater(ok_line, else_branch,
                           "the OK line is reachable on the warning branch")
        self.assertLess(warning_branch, ok_line)

    def test_the_warning_branch_says_what_to_do_and_how_to_restart(self):
        self.assertIn("INSTALLED AND CAPTURING — BUT CAPTURE WILL STOP.", self.source)
        self.assertIn("min_free_bytes, max_store_bytes", self.source)
        self.assertIn("$(service_restart_hint)", self.source)

    def test_the_restart_hint_is_right_on_both_platforms(self):
        for platform, expected in (("darwin", "launchctl kickstart -k system/com.dhulabs.backup"),
                                   ("linux", "systemctl restart dhu-backupd.service")):
            code, out = call_snippet(
                INSTALL, 'set_platform "$1" >/dev/null; service_restart_hint', platform)
            self.assertEqual(code, 0, out)
            self.assertIn(expected, out)

    def test_the_state_label_sed_matches_the_shape_the_daemon_writes(self):
        """The installer parses `state.json` with `sed`, so the two have to agree
        about the shape. Asserted against a heartbeat in the daemon's own format
        (`json.dumps(..., indent=2, sort_keys=True)`), not a hand-typed line."""
        import json as _json
        base = tempfile.mkdtemp(prefix="dhu-state-shape-")
        self.addCleanup(shutil.rmtree, base, True)
        for label in ("ok", "warning", "degraded"):
            path = os.path.join(base, "state.json")
            with open(path, "w") as handle:
                handle.write(_json.dumps(
                    {"state": label, "last_scan_epoch": 1788295267,
                     "warning_reason": ["free-space-low"],
                     "warning_detail": "12.0 GiB free, and capture stops at 10.0 GiB",
                     "watch_roots": 2, "watch_roots_refused": 0},
                    indent=2, sort_keys=True) + "\n")
            code, out = run_bash([
                "-c",
                r'''sed -n 's/.*"state": *"\([a-z-]*\)".*/\1/p' "$1" | head -1''',
                "_", path])
            self.assertEqual(code, 0, out)
            self.assertEqual(out.strip(), label)

    def test_the_warning_detail_sed_extracts_the_sentence(self):
        base = tempfile.mkdtemp(prefix="dhu-detail-shape-")
        self.addCleanup(shutil.rmtree, base, True)
        path = os.path.join(base, "state.json")
        with open(path, "w") as handle:
            handle.write('{\n  "state": "warning",\n'
                         '  "warning_detail": "12.0 GiB free, and capture stops at 10.0 GiB"\n}\n')
        code, out = run_bash([
            "-c", r'''sed -n 's/.*"warning_detail": *"\([^"]*\)".*/\1/p' "$1" | head -1''',
            "_", path])
        self.assertEqual(code, 0, out)
        self.assertEqual(out.strip(), "12.0 GiB free, and capture stops at 10.0 GiB")


class ExcludeConfGuidanceTest(unittest.TestCase):
    """`etc/exclude.conf` is DOCUMENTED by the installer and never created by it."""

    def setUp(self):
        with open(INSTALL) as handle:
            self.source = handle.read()

    def test_the_installer_never_writes_the_file(self):
        """An example file in etc/ goes live the moment someone uncomments a
        line, and every line in this one removes protection."""
        for line in self.source.splitlines():
            if "exclude.conf" not in line:
                continue
            stripped = line.strip()
            # Only ever mentioned inside an echo, a comment, or the guidance.
            self.assertFalse(stripped.startswith("install "), line)
            self.assertFalse(stripped.startswith("cat >"), line)
            self.assertFalse(stripped.startswith("tee "), line)
        self.assertNotIn("exclude.conf", INSTALL_FILES_TABLE(self.source))

    def test_the_guidance_names_the_asymmetry_and_the_restart(self):
        block = self.source[self.source.index("skip a large directory inside a watch root"):]
        block = block[:block.index("check on it later")]
        self.assertIn("DIRECTORY-NAME glob per line", block)
        self.assertIn("can only ADD protection", block)
        self.assertIn("can only REMOVE it", block)
        self.assertIn("root-owned 0644", block)
        self.assertIn("$(service_restart_hint)", block)
        self.assertIn("exclude_globs", block)
        self.assertIn("walk-excluded-dir-operator", block)

    def test_it_sits_beside_the_vault_extra_guidance(self):
        self.assertLess(self.source.index("vault extra files beyond"),
                        self.source.index("skip a large directory inside a watch root"))

    def test_the_dry_run_plan_does_not_mention_creating_it(self):
        code, out = run_bash([INSTALL, "--dry-run", "--watch", "demo=/tmp/demo",
                              "--owner-uid", "501"])
        self.assertEqual(code, 0, out)
        self.assertNotIn("exclude.conf", out)


def INSTALL_FILES_TABLE(source):
    """The `INSTALL_FILES` table — the only list of things a run writes."""
    start = source.index("INSTALL_FILES=\"")
    return source[start:source.index("\"\n", start + 16)]


class ConfirmationDecisionTest(unittest.TestCase):
    """The plan is printed either way; this decides whether it is CONFRONTED.

    Not a security control — anyone typing `sudo bash install.sh` has already
    decided — but the difference between a plan that scrolls past and a plan
    somebody read. All eight combinations are reachable here because the rule
    is a pure function over three booleans; none of them needs a terminal.
    """

    def decide(self, is_tty, yes_flag, dry_run):
        rc, out = call_function(INSTALL, "confirmation_decision",
                               str(is_tty), str(yes_flag), str(dry_run))
        self.assertEqual(rc, 0, out)
        return out.strip()

    def test_a_human_at_a_terminal_is_asked(self):
        self.assertEqual(self.decide(1, 0, 0), "prompt")

    def test_the_yes_flag_skips_the_prompt(self):
        self.assertEqual(self.decide(1, 1, 0), "yes-flag")
        self.assertEqual(self.decide(0, 1, 0), "yes-flag")

    def test_a_non_terminal_stdin_proceeds_rather_than_hanging(self):
        """A prompt would hang CI and a pipe, and a `yes` read off a pipe is a
        confirmation from whatever wrote the pipe, which is not a human."""
        self.assertEqual(self.decide(0, 0, 0), "no-tty")

    def test_a_dry_run_is_never_confirmed_because_it_writes_nothing(self):
        for is_tty in (0, 1):
            for yes_flag in (0, 1):
                self.assertEqual(self.decide(is_tty, yes_flag, 1), "skip-dry-run",
                                 "tty=%s yes=%s" % (is_tty, yes_flag))

    def test_every_combination_returns_one_of_the_four_outcomes(self):
        seen = set()
        for is_tty in (0, 1):
            for yes_flag in (0, 1):
                for dry_run in (0, 1):
                    seen.add(self.decide(is_tty, yes_flag, dry_run))
        self.assertEqual(seen, {"prompt", "yes-flag", "no-tty", "skip-dry-run"})

    def test_non_boolean_arguments_are_refused(self):
        rc, out = call_function(INSTALL, "confirmation_decision", "2", "0", "0")
        self.assertNotEqual(rc, 0, out)
        self.assertIn("0 or 1", out)


class ConfirmationWiringTest(unittest.TestCase):
    """The prompt has to sit between the plan and the first write, or it is
    asking about something that has already happened."""

    def setUp(self):
        with open(INSTALL) as handle:
            self.source = handle.read()

    def test_the_confirmation_comes_after_the_plan_and_before_any_write(self):
        confirm = self.source.index('confirmation_decision "$IS_TTY"')
        plan = self.source.index("\nprint_plan\n")
        first_write = self.source.index('install -d -o root')
        self.assertLess(plan, confirm)
        self.assertLess(confirm, first_write)

    def test_it_is_reached_only_after_the_dry_run_branch_has_exited(self):
        """A dry run must not prompt: it writes nothing, so there is nothing to
        agree to, and asking would teach people to type `yes` by reflex."""
        dry_exit = self.source.index('DRY RUN — nothing was written')
        self.assertLess(dry_exit, self.source.index('confirmation_decision "$IS_TTY"'))

    def test_the_abort_says_nothing_was_changed(self):
        self.assertIn("aborted at the confirmation step. Nothing has been changed",
                      self.source)

    def test_the_non_tty_path_says_that_no_human_confirmed(self):
        """Proceeding silently would leave a transcript that cannot be told
        apart from one a human read."""
        self.assertIn("NOT confirmed by a human", self.source)

    def test_the_word_is_yes_and_not_a_keypress(self):
        self.assertIn('Type "yes" to proceed', self.source)
        self.assertIn('[ "$CONFIRM_REPLY" != "yes" ]', self.source)

    def test_the_yes_flag_is_parsed_and_documented(self):
        self.assertIn("--yes)\n      ASSUME_YES=1; shift ;;", self.source)
        rc, out = run_bash([INSTALL, "--help"])
        self.assertEqual(rc, 0, out)
        self.assertIn("--yes", out)

    def test_an_unknown_flag_is_still_refused(self):
        rc, out = run_bash([INSTALL, "--yess"])
        self.assertNotEqual(rc, 0, out)
        self.assertIn("unknown argument", out)


class WatchIdFromBasenameTest(unittest.TestCase):
    """A suggested id must survive the installer's OWN validator.

    A suggestion the installer would then refuse is worse than no suggestion:
    the operator pastes it and is told no, by the tool that offered it.
    """

    def derive(self, basename):
        rc, out = call_function(INSTALL, "watch_id_from_basename", basename)
        self.assertEqual(rc, 0, out)
        return out.strip()

    def test_it_lowercases_and_replaces_what_the_id_rule_forbids(self):
        self.assertEqual(self.derive("MyRepo"), "myrepo")
        self.assertEqual(self.derive("a.b.c"), "a-b-c")
        self.assertEqual(self.derive("my side project"), "my-side-project")

    def test_it_never_starts_with_a_non_letter(self):
        self.assertEqual(self.derive("2fast"), "fast")
        self.assertEqual(self.derive(".dotfiles"), "dotfiles")

    def test_a_name_that_sanitises_to_nothing_becomes_repo(self):
        for basename in ("___", "----", "42", ""):
            self.assertEqual(self.derive(basename), "repo", basename)

    def test_it_is_capped_at_the_validator_length(self):
        derived = self.derive("A" * 60)
        self.assertLessEqual(len(derived), 32)

    def test_every_derived_id_passes_validate_watch_entry(self):
        """The two are asserted against each other rather than read side by side."""
        for basename in ("MyRepo", "2fast", "___", "a.b.c", "----", ".dotfiles",
                         "A" * 60, "my repo", "repo!!", "-x-"):
            derived = self.derive(basename)
            rc, out = call_snippet(INSTALL,
                                   'validate_watch_entry "$1" "/tmp/x" "suggested"',
                                   derived)
            self.assertEqual(rc, 0, "%r -> %r was refused: %s" % (basename, derived, out))


class WatchSuggestionFormatTest(unittest.TestCase):
    """Paths in, ready-to-paste flags out. No filesystem involved."""

    def suggest(self, *paths):
        rc, out = call_function(INSTALL, "format_watch_suggestion", *paths)
        self.assertEqual(rc, 0, out)
        return out

    def test_each_path_becomes_a_single_quoted_watch_flag(self):
        out = self.suggest("/home/a/proj", "/home/a/other")
        self.assertIn("--watch 'proj=/home/a/proj'", out)
        self.assertIn("--watch 'other=/home/a/other'", out)
        self.assertIn("sudo bash install.sh", out)

    def test_a_path_with_a_space_is_quoted_so_pasting_cannot_split_it(self):
        out = self.suggest("/home/a/my side project")
        self.assertIn("--watch 'my-side-project=/home/a/my side project'", out)

    def test_a_glob_path_is_quoted_so_pasting_cannot_expand_it(self):
        """The same rule uninstall.sh follows, for the same reason: unquoted,
        the pasting shell would expand it against its own cwd."""
        out = self.suggest("/home/a/.claude/worktrees/*")
        self.assertIn("--watch 'worktrees=/home/a/.claude/worktrees/*'", out)
        self.assertNotIn("--watch worktrees=", out)

    def test_a_trailing_glob_takes_its_id_from_the_last_real_component(self):
        """`/home/a/worktrees/*` has the basename `*`, which sanitises to
        nothing — every glob root would otherwise be called `repo`."""
        out = self.suggest("/home/a/.claude/worktrees/*", "/home/a/hapos-task-*")
        self.assertIn("--watch 'worktrees=/home/a/.claude/worktrees/*'", out)
        self.assertIn("--watch 'hapos-task=/home/a/hapos-task-*'", out)

    def test_duplicate_ids_are_suffixed_rather_than_dropped(self):
        """render_watchlist refuses a duplicate id outright, and both
        directories are ones the operator asked about."""
        out = self.suggest("/a/api", "/b/api", "/c/API")
        self.assertIn("'api=/a/api'", out)
        self.assertIn("'api-2=/b/api'", out)
        self.assertIn("'api-3=/c/API'", out)

    def test_a_suffixed_id_still_fits_the_validator(self):
        out = self.suggest("/a/" + "N" * 40, "/b/" + "N" * 40)
        ids = re.findall(r"--watch '([a-z0-9-]+)=", out)
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)
        for identifier in ids:
            self.assertLessEqual(len(identifier), 32, identifier)

    def test_nothing_found_says_so_rather_than_printing_an_empty_command(self):
        """An empty `sudo bash install.sh` line is a command that refuses."""
        out = self.suggest()
        self.assertIn("No git working trees were found", out)
        self.assertNotIn("sudo bash install.sh --watch", out)
        self.assertIn("--watch id=/abs/path", out)


class WatchSuggestionSearchTest(unittest.TestCase):
    """The walk, against a FABRICATED home directory.

    Nothing here reads the machine's real home: the search is a function of a
    directory tree, so a fabricated one is a complete population for it.
    """

    def fabricate_home(self):
        base = tempfile.mkdtemp(prefix="dhu-suggest-home-")
        self.addCleanup(shutil.rmtree, base, True)
        return base

    def make_repo(self, home, relative, mtime=None):
        repo = os.path.join(home, relative)
        os.makedirs(os.path.join(repo, ".git"))
        if mtime is not None:
            os.utime(repo, (mtime, mtime))
        return repo

    def search(self, home, maximum=8):
        rc, out = call_function(INSTALL, "find_candidate_repos", home, str(maximum))
        self.assertEqual(rc, 0, out)
        return [line for line in out.splitlines() if line.strip()]

    def test_it_finds_working_trees_one_and_two_levels_down(self):
        home = self.fabricate_home()
        shallow = self.make_repo(home, "proj")
        deep = self.make_repo(home, "Projects/thing")
        self.assertEqual(sorted(self.search(home)), sorted([shallow, deep]))

    def test_it_does_not_go_deeper_than_two_levels(self):
        home = self.fabricate_home()
        self.make_repo(home, "a/b/c/too-deep")
        self.assertEqual(self.search(home), [])

    def test_built_in_excluded_directories_are_skipped_at_every_level(self):
        """A repository inside `node_modules` is one the daemon's walk would
        refuse to descend into anyway."""
        home = self.fabricate_home()
        self.make_repo(home, "node_modules/pkg")
        self.make_repo(home, "proj/.venv")
        keep = self.make_repo(home, "proj")
        self.assertEqual(self.search(home), [keep])

    def test_it_is_ordered_most_recently_modified_first(self):
        home = self.fabricate_home()
        old = self.make_repo(home, "old", mtime=1_600_000_000)
        new = self.make_repo(home, "new", mtime=1_700_000_000)
        middle = self.make_repo(home, "middle", mtime=1_650_000_000)
        self.assertEqual(self.search(home), [new, middle, old])

    def test_the_list_is_capped_and_the_cap_keeps_the_newest(self):
        home = self.fabricate_home()
        for index in range(6):
            self.make_repo(home, "repo%d" % index, mtime=1_600_000_000 + index)
        found = self.search(home, maximum=2)
        self.assertEqual(len(found), 2)
        self.assertEqual([os.path.basename(p) for p in found], ["repo5", "repo4"])

    def test_a_symlink_out_of_the_home_directory_is_not_followed(self):
        """`find -P`, asserted rather than assumed: a link inside the home
        directory must not lead the search into another account's tree."""
        home = self.fabricate_home()
        outside = self.fabricate_home()
        self.make_repo(outside, "secret")
        os.symlink(outside, os.path.join(home, "link"))
        self.assertEqual(self.search(home), [])

    def test_a_home_that_does_not_exist_finds_nothing_and_does_not_fail(self):
        self.assertEqual(self.search("/nonexistent-home-xyz"), [])

    def test_the_excluded_names_come_from_the_python_that_owns_the_list(self):
        """A second copy in bash would drift, and the direction it drifts in is
        suggesting a watch root inside `node_modules`."""
        rc, out = call_function(INSTALL, "builtin_excluded_dir_names")
        self.assertEqual(rc, 0, out)
        sys.path.insert(0, SRC)
        import dhu_backup_core
        self.assertEqual(sorted(out.split()),
                         sorted(dhu_backup_core.EXCLUDED_DIR_NAMES))


class WatchSuggestionWiringTest(unittest.TestCase):
    """WHERE the suggestion may appear, which is the part that matters.

    It refuses to be a default watchlist: it runs on the refusal path and under
    --dry-run, and a real install — which already knows what it is protecting —
    never calls it. A suggestion printed beside a plan about to be executed
    reads like something that was included in it.
    """

    def setUp(self):
        with open(INSTALL) as handle:
            self.source = handle.read()

    def test_the_refusal_for_want_of_watch_roots_offers_a_suggestion(self):
        branch = self.source[self.source.index("!! no watch roots:"):]
        branch = branch[:branch.index("exit 2")]
        self.assertIn("print_watch_suggestion", branch)
        # And the refusal itself is unchanged: still no default watchlist.
        self.assertIn("There is no default watchlist on purpose", branch)
        self.assertIn("Nothing has been changed", branch)

    def test_it_is_called_only_from_the_refusal_path_and_the_dry_run(self):
        calls = [line.strip() for line in self.source.splitlines()
                 if "print_watch_suggestion" in line and not line.strip().startswith("#")
                 and "print_watch_suggestion()" not in line]
        self.assertEqual(len(calls), 2, calls)
        after_dry_exit = self.source[self.source.index("# ── the PLAN is executed"):]
        self.assertNotIn("print_watch_suggestion", after_dry_exit)

    def test_a_home_that_cannot_be_resolved_says_so_rather_than_guessing(self):
        """Under sudo, $HOME is ROOT's home. Falling back to it would suggest
        root-owned directories, which the daemon admits no file from — it would
        be a watch root that protects nothing."""
        rc, out = call_snippet(INSTALL, 'print_watch_suggestion',
                               env={"SUDO_UID": "4294967000", "SUDO_USER": None})
        self.assertEqual(rc, 0, out)
        self.assertIn("No suggestion", out)
        self.assertIn("root's own home is never suggested", out)

    def test_the_dry_run_prints_candidates_and_says_a_real_run_will_ask(self):
        rc, out = run_bash([INSTALL, "--dry-run", "--watch", "repo=/tmp/x"])
        self.assertEqual(rc, 0, out)
        self.assertIn("other directories on this machine you could protect", out)
        self.assertIn("asks for the word 'yes'", out)


class SortPathsByMtimeTest(unittest.TestCase):
    """The ordering helper, and the pipefail trap it exists to avoid.

    A `| head -n` would make the whole pipeline non-zero the moment head closed
    the pipe — a failure with nothing wrong, on exactly the machine with the
    most repositories — so the cap is applied inside the sorter.
    """

    def sort(self, paths, maximum):
        prog = ('DHU_BACKUP_SOURCE_ONLY=1 . "$1" || exit 99\n'
                'printf "%s\\n" "${@:3}" | sort_paths_by_mtime_desc "$2"\n')
        rc, out = run_bash(["-c", prog, "_", INSTALL, str(maximum)] + list(paths))
        self.assertEqual(rc, 0, out)
        return [line for line in out.splitlines() if line.strip()]

    def test_a_long_list_capped_short_still_exits_zero(self):
        base = tempfile.mkdtemp(prefix="dhu-mtime-")
        self.addCleanup(shutil.rmtree, base, True)
        paths = []
        for index in range(400):
            path = os.path.join(base, "d%03d" % index)
            os.mkdir(path)
            os.utime(path, (1_600_000_000 + index, 1_600_000_000 + index))
            paths.append(path)
        found = self.sort(paths, 3)
        self.assertEqual([os.path.basename(p) for p in found],
                         ["d399", "d398", "d397"])

    def test_zero_means_no_cap(self):
        self.assertEqual(len(self.sort(["/nonexistent/a", "/nonexistent/b"], 0)), 2)


class ServiceCommandAgreementTest(unittest.TestCase):
    """`status` prints a restart command; `install.sh` prints its own copy.

    The installer cannot import a Python table, so the string exists twice —
    the same duplication `DEFAULT_INSTALL_ROOTS` has, and asserted the same
    way. A restart command naming the wrong service manager is advice that
    fails in front of an operator who is already having a bad day.
    """

    def shell_restart_hint(self, platform):
        rc, out = call_snippet(INSTALL,
                               'set_platform "$1" >/dev/null; service_restart_hint',
                               platform)
        self.assertEqual(rc, 0, out)
        return out.strip()

    def test_both_platforms_agree_with_the_python_table(self):
        sys.path.insert(0, SRC)
        import dhu_backup_core
        for platform in ("darwin", "linux"):
            self.assertEqual(self.shell_restart_hint(platform),
                             dhu_backup_core.service_restart_command(platform),
                             platform)

    def test_the_status_commands_name_the_same_service(self):
        """`service_status_hint` prints a compound for systemd, so only the
        service name is common to both spellings."""
        sys.path.insert(0, SRC)
        import dhu_backup_core
        for platform, name in (("darwin", "com.dhulabs.backup"),
                               ("linux", "dhu-backupd")):
            self.assertIn(name, dhu_backup_core.service_status_command(platform))
            rc, out = call_snippet(INSTALL,
                                   'set_platform "$1" >/dev/null; service_status_hint',
                                   platform)
            self.assertEqual(rc, 0, out)
            self.assertIn(name, out)
