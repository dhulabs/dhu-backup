"""The Linux port's decisions, proven as pure functions.

Run with:  /usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'

Everything here is provable on either platform, with no daemon running, no
store on disk and no root: which trigger a platform string selects, what the
inotify event mask constants actually are, which install root each platform
gets, what the systemd unit says, and whether a given interpreter may be
executed by a root daemon.

Three of these exist because the failure they catch is SILENT. A wrong inotify
constant is a watch that never fires, and the floor sweep hides it perfectly. A
trigger selection that falls through to poll-only still captures everything,
fifteen seconds later. An install root the installer and the daemon disagree
about produces a daemon that comes up healthy on default budgets, protecting
nothing. None of the three shows up as an error anywhere.
"""

import importlib.util
import os
import re
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO_ROOT, "src")
UNIT_FILE = os.path.join(SRC, "dhu-backupd.service")
INSTALL = os.path.join(SRC, "install.sh")
sys.path.insert(0, SRC)

import dhu_backup_core  # noqa: E402


def load_daemon():
    """Import `src/dhu-backupd.py`, whose name is not a Python identifier.

    Importing it runs its imports and its module-level constants and nothing
    else — the daemon does its work in `main`, which nothing here calls.
    """
    path = os.path.join(SRC, "dhu-backupd.py")
    spec = importlib.util.spec_from_file_location("dhu_backupd_module", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DAEMON = load_daemon()


class TriggerSelectionTests(unittest.TestCase):
    """Which trigger a `sys.platform` string selects. All three outcomes."""

    def test_darwin_selects_kqueue(self):
        self.assertEqual(dhu_backup_core.trigger_name_for_platform("darwin"), "kqueue")

    def test_linux_selects_inotify(self):
        self.assertEqual(dhu_backup_core.trigger_name_for_platform("linux"), "inotify")

    def test_legacy_linux2_selects_inotify(self):
        """`sys.platform` was `linux2` on Python 2 and some 3.x builds."""
        self.assertEqual(dhu_backup_core.trigger_name_for_platform("linux2"), "inotify")

    def test_anything_else_selects_poll_only(self):
        for platform in ("win32", "freebsd13", "openbsd7", "sunos5", "cygwin", ""):
            self.assertEqual(
                dhu_backup_core.trigger_name_for_platform(platform), "poll-only", platform)

    def test_the_three_names_are_the_only_ones(self):
        for platform in ("darwin", "linux", "linux2", "win32", "aix", ""):
            self.assertIn(dhu_backup_core.trigger_name_for_platform(platform),
                          dhu_backup_core.TRIGGER_NAMES, platform)

    def test_darwin_is_matched_exactly_not_by_prefix(self):
        """`darwin` is exact; a hypothetical `darwinish` must not get kqueue.

        The Linux arm is a PREFIX match because `linux2` is real; the macOS arm
        is not, because there is no such variant and a prefix match there would
        hand kqueue to a platform that has none.
        """
        self.assertEqual(dhu_backup_core.trigger_name_for_platform("darwin1"), "poll-only")

    def test_this_platform_gets_a_trigger_that_names_itself(self):
        """`make_trigger` returns something whose `.name` is a legal value.

        Constructed for real on the machine running the suite, so this is the
        one test here that touches a kernel interface. It never watches
        anything: `refresh` is not called, and the trigger is closed.
        """
        trigger = DAEMON.make_trigger(_QuietLogger())
        try:
            self.assertIn(trigger.name, dhu_backup_core.TRIGGER_NAMES)
            self.assertEqual(trigger.watch_failures, 0)
            self.assertEqual(trigger.directories_watched, 0)
        finally:
            trigger.close()

    def test_an_unsupported_platform_gets_poll_only_and_an_error_line(self):
        logger = _RecordingLogger()
        trigger = DAEMON.make_trigger(logger, platform_string="win32")
        try:
            self.assertIsInstance(trigger, DAEMON.PollOnlyTrigger)
            self.assertEqual(trigger.name, "poll-only")
        finally:
            trigger.close()
        self.assertTrue(any("POLL-ONLY" in line for line in logger.errors), logger.errors)
        self.assertTrue(any("win32" in line for line in logger.errors), logger.errors)

    def test_poll_only_never_wakes_early(self):
        """`wait` must consume the whole timeout and report no event.

        A trigger that returned True would make the daemon spin: the main loop
        treats True as "something changed, sweep now".
        """
        import time

        trigger = DAEMON.PollOnlyTrigger(_QuietLogger())
        started = time.time()
        woke = trigger.wait(0.3)
        elapsed = time.time() - started
        self.assertFalse(woke)
        self.assertGreaterEqual(elapsed, 0.25)
        self.assertEqual(trigger.refresh(["/tmp"]), (0, 0))
        self.assertEqual(trigger.directories_watched, 0)


class InotifyConstantTests(unittest.TestCase):
    """The event mask values are kernel ABI. Pinned, because a typo is silent.

    A wrong bit here is a watch that is never triggered by the event it was
    meant to catch. Nothing reports that: capture still happens on the floor
    sweep, at the interval, and the heartbeat still says `inotify`. These are
    the values in `include/uapi/linux/inotify.h`, identical on every Linux
    architecture since 2.6.13.
    """

    EXPECTED = {
        "IN_ATTRIB": 0x00000004,
        "IN_CLOSE_WRITE": 0x00000008,
        "IN_MOVED_FROM": 0x00000040,
        "IN_MOVED_TO": 0x00000080,
        "IN_CREATE": 0x00000100,
        "IN_DELETE": 0x00000200,
        "IN_DELETE_SELF": 0x00000400,
        "IN_MOVE_SELF": 0x00000800,
        "IN_Q_OVERFLOW": 0x00004000,
        "IN_IGNORED": 0x00008000,
        "IN_ONLYDIR": 0x01000000,
        "IN_DONT_FOLLOW": 0x02000000,
    }

    def test_every_constant_has_its_abi_value(self):
        for name, value in sorted(self.EXPECTED.items()):
            self.assertEqual(getattr(DAEMON, name), value,
                             "%s is 0x%08x, the ABI value is 0x%08x"
                             % (name, getattr(DAEMON, name), value))

    def test_the_watch_mask_contains_exactly_the_ten_intended_flags(self):
        wanted = ("IN_CREATE", "IN_DELETE", "IN_MOVED_FROM", "IN_MOVED_TO",
                  "IN_CLOSE_WRITE", "IN_ATTRIB", "IN_DELETE_SELF", "IN_MOVE_SELF",
                  "IN_ONLYDIR", "IN_DONT_FOLLOW")
        expected = 0
        for name in wanted:
            expected |= self.EXPECTED[name]
        self.assertEqual(DAEMON.INOTIFY_WATCH_MASK, expected)

    def test_the_mask_carries_close_write(self):
        """The one flag that makes Linux differ from macOS, asserted by name.

        A directory kqueue does not fire for an in-place rewrite; a directory
        inotify watch reports IN_CLOSE_WRITE for files inside it, which is why
        `echo x > f` is captured in under a second on Linux and waits for the
        floor sweep on macOS. Measured, 2026-09-02: 0.55 s in the container.
        """
        self.assertTrue(DAEMON.INOTIFY_WATCH_MASK & DAEMON.IN_CLOSE_WRITE)

    def test_the_mask_refuses_symlinks_and_non_directories(self):
        """C7, restated for the trigger: never resolve a symlink, never watch a
        non-directory. Both are flags on the add, not checks the code remembers."""
        self.assertTrue(DAEMON.INOTIFY_WATCH_MASK & DAEMON.IN_DONT_FOLLOW)
        self.assertTrue(DAEMON.INOTIFY_WATCH_MASK & DAEMON.IN_ONLYDIR)

    def test_overflow_is_not_in_the_watch_mask(self):
        """IN_Q_OVERFLOW and IN_IGNORED are RECEIVED, never requested."""
        self.assertFalse(DAEMON.INOTIFY_WATCH_MASK & DAEMON.IN_Q_OVERFLOW)
        self.assertFalse(DAEMON.INOTIFY_WATCH_MASK & DAEMON.IN_IGNORED)

    def test_the_event_header_is_sixteen_bytes(self):
        self.assertEqual(DAEMON.INOTIFY_EVENT_HEADER, 16)


class InotifyEventParsingTests(unittest.TestCase):
    """`_inotify_event_masks` — pure over a read() buffer."""

    def event(self, wd, mask, name=b""):
        padded = name + b"\0" if name else b""
        while len(padded) % 4:
            padded += b"\0"
        return (wd.to_bytes(4, sys.byteorder, signed=True)
                + mask.to_bytes(4, sys.byteorder)
                + (0).to_bytes(4, sys.byteorder)
                + len(padded).to_bytes(4, sys.byteorder)
                + padded)

    def test_an_empty_buffer_yields_nothing(self):
        self.assertEqual(DAEMON._inotify_event_masks(b""), [])

    def test_one_event_without_a_name(self):
        data = self.event(1, DAEMON.IN_CREATE)
        self.assertEqual(DAEMON._inotify_event_masks(data), [DAEMON.IN_CREATE])

    def test_several_events_with_names_of_different_lengths(self):
        data = (self.event(1, DAEMON.IN_CREATE, b"a")
                + self.event(2, DAEMON.IN_CLOSE_WRITE, b"longer-name.txt")
                + self.event(3, DAEMON.IN_Q_OVERFLOW))
        self.assertEqual(
            DAEMON._inotify_event_masks(data),
            [DAEMON.IN_CREATE, DAEMON.IN_CLOSE_WRITE, DAEMON.IN_Q_OVERFLOW])

    def test_a_truncated_trailing_event_is_dropped_not_guessed_at(self):
        """A short read must not produce a fabricated mask.

        It cannot happen with a 64 KiB buffer and it is not worth being wrong
        about: the loop stops when fewer than a header remains.
        """
        data = self.event(1, DAEMON.IN_CREATE) + b"\x01\x02\x03"
        self.assertEqual(DAEMON._inotify_event_masks(data), [DAEMON.IN_CREATE])


class InstallRootTests(unittest.TestCase):
    """One table, two entries, and the shell must agree with it."""

    def test_both_entries_exist_and_are_absolute(self):
        self.assertEqual(sorted(dhu_backup_core.DEFAULT_INSTALL_ROOTS), ["darwin", "linux"])
        self.assertEqual(dhu_backup_core.DEFAULT_INSTALL_ROOTS["darwin"], "/Library/DHU/backup")
        self.assertEqual(dhu_backup_core.DEFAULT_INSTALL_ROOTS["linux"], "/opt/dhu-backup")
        for root in dhu_backup_core.DEFAULT_INSTALL_ROOTS.values():
            self.assertTrue(root.startswith("/"), root)
            self.assertFalse(root.endswith("/"), root)

    def test_the_platform_selector_returns_the_table_entries(self):
        self.assertEqual(dhu_backup_core.install_root_for_platform("darwin"),
                         dhu_backup_core.DEFAULT_INSTALL_ROOTS["darwin"])
        for platform in ("linux", "linux2"):
            self.assertEqual(dhu_backup_core.install_root_for_platform(platform),
                             dhu_backup_core.DEFAULT_INSTALL_ROOTS["linux"], platform)

    def test_an_unknown_platform_gets_a_root_rather_than_an_exception(self):
        """It is only ever TEXT inside a printed recovery command."""
        self.assertEqual(dhu_backup_core.install_root_for_platform("win32"),
                         dhu_backup_core.DEFAULT_INSTALL_ROOTS["darwin"])

    def test_this_process_resolved_its_own_platform(self):
        self.assertEqual(dhu_backup_core.DEFAULT_INSTALL_ROOT,
                         dhu_backup_core.install_root_for_platform(sys.platform))

    def test_the_installer_shell_table_matches_the_python_table(self):
        """install.sh carries the same two roots, and must not drift.

        The installer writes `root = <DEST>` into the daemon's config; if the two
        tables disagreed, the daemon would read a config path the installer never
        wrote, fall back to its compiled defaults, and come up healthy protecting
        nothing.
        """
        with open(INSTALL) as handle:
            text = handle.read()
        block = re.search(r"platform_install_root\(\).*?\n\}", text, re.S)
        self.assertTrue(block, "platform_install_root was not found in install.sh")
        for platform, root in dhu_backup_core.DEFAULT_INSTALL_ROOTS.items():
            self.assertRegex(block.group(0), r"%s\)\s+echo %s\s*;;" % (platform, re.escape(root)))

    def test_the_daemon_default_config_path_follows_the_install_root(self):
        self.assertEqual(
            DAEMON.DEFAULT_CONFIG_PATH,
            os.path.join(dhu_backup_core.DEFAULT_INSTALL_ROOT, "etc", "dhu-backupd.conf"))


class InterpreterVerdictTests(unittest.TestCase):
    """Review H2 as a pure function: may a root daemon execute this?

    Every negative case is a REFUSAL with a reason, and both `None` uids are
    refusals rather than passes — "I could not find out who owns the thing root
    is about to execute" must never be rounded down to "fine".
    """

    def verdict(self, **kwargs):
        args = dict(path="/usr/bin/python3", is_symlink=False, link_uid=0,
                    target="/usr/bin/python3", target_uid=0)
        args.update(kwargs)
        return dhu_backup_core.interpreter_verdict(**args)

    def test_a_root_owned_regular_interpreter_is_accepted(self):
        result = self.verdict()
        self.assertTrue(result.ok)
        self.assertIn("root-owned", result.reason)

    def test_a_root_owned_symlink_to_a_root_owned_target_is_accepted(self):
        """Ubuntu's /usr/bin/python3 -> python3.12 is exactly this shape."""
        result = self.verdict(is_symlink=True, target="/usr/bin/python3.12")
        self.assertTrue(result.ok)
        self.assertIn("/usr/bin/python3.12", result.reason)

    def test_a_user_owned_interpreter_is_refused(self):
        result = self.verdict(link_uid=501, target_uid=501)
        self.assertFalse(result.ok)
        self.assertIn("501", result.reason)

    def test_a_user_owned_symlink_to_a_root_owned_target_is_refused(self):
        """The homebrew-node shape, and the one a resolved-path check misses.

        The agent owns the link, so it chooses what root executes; every check
        made on the resolved path was made on the wrong file.
        """
        result = self.verdict(is_symlink=True, link_uid=501,
                              target="/usr/bin/python3.12", target_uid=0)
        self.assertFalse(result.ok)
        self.assertIn("not root", result.reason)

    def test_a_root_owned_symlink_to_a_user_owned_target_is_refused(self):
        result = self.verdict(is_symlink=True, link_uid=0,
                              target="/home/agent/.pyenv/versions/3.12/bin/python",
                              target_uid=1000)
        self.assertFalse(result.ok)
        self.assertIn("1000", result.reason)

    def test_an_unstattable_interpreter_is_refused_not_passed(self):
        self.assertFalse(self.verdict(link_uid=None).ok)
        self.assertFalse(self.verdict(target_uid=None).ok)
        self.assertFalse(self.verdict(target=None).ok)

    def test_a_relative_or_empty_path_is_refused(self):
        for path in ("python3", "", "./python3", "../python3"):
            self.assertFalse(self.verdict(path=path).ok, path)

    def test_a_relative_resolved_target_is_refused(self):
        self.assertFalse(self.verdict(is_symlink=True, target="python3.12").ok)

    def test_every_verdict_carries_a_reason(self):
        for result in (self.verdict(), self.verdict(link_uid=501),
                       self.verdict(target_uid=None), self.verdict(path="x")):
            self.assertTrue(result.reason)
            self.assertIsInstance(result.reason, str)

    def test_this_machines_own_interpreter_is_root_owned(self):
        """Not a hypothetical: the interpreter running this suite.

        A macOS or Ubuntu system python is root-owned. If this fails, the
        machine is running the suite under a user-owned python and the daemon
        installed against it would be a root shell for any agent.
        """
        executable = sys.executable
        link_uid = os.lstat(executable).st_uid
        target = os.path.realpath(executable)
        target_uid = os.stat(target).st_uid
        result = dhu_backup_core.interpreter_verdict(
            executable, os.path.islink(executable), link_uid, target, target_uid)
        if link_uid != 0 or target_uid != 0:
            self.skipTest("this suite is running under a non-root-owned python (%s)" % executable)
        self.assertTrue(result.ok, result.reason)


class SystemdUnitTests(unittest.TestCase):
    """The unit file, read and parsed rather than eyeballed."""

    @classmethod
    def setUpClass(cls):
        with open(UNIT_FILE) as handle:
            cls.text = handle.read()
        cls.keys = {}
        section = None
        for line in cls.text.splitlines():
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1]
                continue
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, value = stripped.partition("=")
            cls.keys.setdefault((section, key.strip()), []).append(value.strip())

    def value(self, section, key):
        values = self.keys.get((section, key))
        self.assertTrue(values, "[%s] %s is missing from dhu-backupd.service" % (section, key))
        return values[0]

    def test_the_unit_file_exists_and_has_three_sections(self):
        self.assertTrue(os.path.isfile(UNIT_FILE))
        for section in ("[Unit]", "[Service]", "[Install]"):
            self.assertIn(section, self.text)

    def test_it_is_a_simple_always_restarting_service(self):
        self.assertEqual(self.value("Service", "Type"), "simple")
        self.assertEqual(self.value("Service", "Restart"), "always")
        self.assertEqual(self.value("Service", "RestartSec"), "2")
        self.assertEqual(self.value("Service", "Nice"), "10")
        self.assertEqual(self.value("Service", "LimitNOFILE"), "65536")

    def test_exec_start_is_the_absolute_root_owned_interpreter_with_all_three_flags(self):
        """-E drops PYTHON* env, -s the user site dir, -S site.py itself (H3)."""
        exec_start = self.value("Service", "ExecStart")
        self.assertEqual(
            exec_start,
            "/usr/bin/python3 -E -s -S %s/bin/dhu-backupd"
            % dhu_backup_core.DEFAULT_INSTALL_ROOTS["linux"])

    def test_it_runs_as_root(self):
        """No User= key. Root ownership of the store is the whole guarantee."""
        self.assertNotIn(("Service", "User"), self.keys)
        self.assertNotIn(("Service", "Group"), self.keys)
        self.assertNotIn(("Service", "DynamicUser"), self.keys)

    def test_the_hardening_keys_are_present(self):
        for key, want in (("NoNewPrivileges", "yes"),
                          ("ProtectSystem", "strict"),
                          ("PrivateTmp", "yes"),
                          ("ProtectKernelTunables", "yes"),
                          ("ProtectKernelModules", "yes"),
                          ("RestrictSUIDSGID", "yes")):
            self.assertEqual(self.value("Service", key), want, key)

    def test_protect_home_is_read_only_and_never_yes(self):
        """`yes` would empty every watch root under /home.

        The daemon must READ home directories — that is where the watched
        project trees are. With ProtectHome=yes the daemon sees an empty tmpfs,
        refuses every root, and reports `unprotected`: healthy, and protecting
        nothing. This is the one hardening key that can break the product.
        """
        self.assertEqual(self.value("Service", "ProtectHome"), "read-only")

    def test_the_install_root_is_the_only_writable_path(self):
        self.assertEqual(self.value("Service", "ReadWritePaths"),
                         dhu_backup_core.DEFAULT_INSTALL_ROOTS["linux"])

    def test_both_streams_append_to_the_daemon_log(self):
        """`append:` and not `file:` — a restart must not truncate the record."""
        expected = "append:%s/var/dhu-backupd.log" % dhu_backup_core.DEFAULT_INSTALL_ROOTS["linux"]
        self.assertEqual(self.value("Service", "StandardOutput"), expected)
        self.assertEqual(self.value("Service", "StandardError"), expected)

    def test_it_is_wanted_by_multi_user_target(self):
        self.assertEqual(self.value("Install", "WantedBy"), "multi-user.target")

    def test_every_path_it_names_is_under_the_linux_install_root(self):
        root = dhu_backup_core.DEFAULT_INSTALL_ROOTS["linux"]
        for other in re.findall(r"/Library/DHU\S*", self.text):
            self.fail("the unit names a macOS path: %s" % other)
        self.assertIn(root, self.text)

    def test_the_private_tmp_caveat_is_written_down(self):
        """A /tmp watch root under PrivateTmp=yes is watched in a private empty
        /tmp. Documented in the unit itself, where the person editing it looks."""
        self.assertIn("PrivateTmp", self.text)
        self.assertRegex(self.text, r"(?s)/tmp.*PrivateTmp=no|PrivateTmp=no.*?/tmp")


class ShebangPortabilityTests(unittest.TestCase):
    """Linux passes a shebang's whole tail as ONE argument; macOS splits it.

    `#!/usr/bin/python3 -E -s -S` therefore reaches python on Linux as the single
    option "-E -s -S" and it exits with `Unknown option: -`. Measured in the
    container, 2026-09-02, on `bin/dhu-backup`: every direct invocation of the
    recovery command failed. `env -S` does the splitting itself and exists,
    root-owned, on both platforms.
    """

    SCRIPTS = ("dhu-backup.py", "dhu_backup_announce.py",
               "dhu-backup-mcp.py", "dhu-backup-hook.py")

    def first_line(self, name):
        with open(os.path.join(SRC, name)) as handle:
            return handle.readline().rstrip("\n")

    def test_no_script_uses_the_macos_only_multi_flag_shebang(self):
        for name in self.SCRIPTS:
            self.assertNotEqual(self.first_line(name), "#!/usr/bin/python3 -E -s -S", name)

    def test_every_script_keeps_all_three_isolation_flags(self):
        for name in self.SCRIPTS:
            line = self.first_line(name)
            self.assertTrue(line.startswith("#!/usr/bin/env -S "), "%s: %s" % (name, line))
            for flag in ("-E", "-s", "-S"):
                self.assertIn(" %s " % flag, line + " ", "%s lost %s: %s" % (name, flag, line))

    def test_the_interpreter_after_env_is_absolute(self):
        """`env` must not do a PATH lookup for python (review H3)."""
        for name in self.SCRIPTS:
            self.assertIn("/usr/bin/python3", self.first_line(name), name)


class _QuietLogger(object):
    def info(self, _message):
        pass

    def warn(self, _message):
        pass

    def error(self, _message):
        pass


class _RecordingLogger(_QuietLogger):
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


if __name__ == "__main__":
    unittest.main()
