"""Tests for the Claude Code `PostToolUseFailure` hook (Property 4's last mile).

Run with:  /usr/bin/python3 -m unittest discover -s tests -p 'test_*.py'

The token extraction is a PURE function and is tested as one, over fabricated
strings with no filesystem. Everything else drives the hook as a real
subprocess with fabricated stdin, against the fabricated install root built by
`test_dhu_backup_announce.py` — never against `/Library/DHU/backup`.

The two properties that matter most are negative ones, and both are asserted
rather than reasoned about: the hook is SILENT for a missing file that was never
protected, and it exits 0 on every input including the ones designed to break
it. A hook that is noisy or that throws on an agent's error path is worse than
no hook, because it gets switched off.
"""

import json
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO_ROOT, "src")
sys.path.insert(0, SRC)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_dhu_backup_announce import (  # noqa: E402
    FIXTURE_REPO,
    FIXTURE_WORKTREE,
    FixtureCase,
    write_state,
)

PYTHON = "/usr/bin/python3"
HOOK = os.path.join(SRC, "dhu-backup-hook.py")


def load_hook_module():
    """Import `src/dhu-backup-hook.py` as a module; its filename has a hyphen."""
    import importlib.machinery
    import importlib.util

    spec = importlib.util.spec_from_loader(
        "dhu_backup_hook_under_test",
        importlib.machinery.SourceFileLoader("dhu_backup_hook_under_test", HOOK))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hook = load_hook_module()


# ── the pure part: which tokens in a shell command are paths ──────────────────


class TokenExtractionTests(unittest.TestCase):
    def test_a_simple_relative_path_in_a_command(self):
        self.assertEqual(hook.extract_path_tokens("cat foo/bar.md"), ["foo/bar.md"])

    def test_a_bare_command_word_is_not_a_path(self):
        self.assertEqual(hook.extract_path_tokens("ls"), [])
        self.assertEqual(hook.extract_path_tokens("make build test"), [])

    def test_two_paths_across_a_compound_command_in_order_and_deduplicated(self):
        self.assertEqual(hook.extract_path_tokens("rm -rf x && cat x/y"), ["x/y"])
        self.assertEqual(hook.extract_path_tokens("cp a/b.ts a/c.ts && cat a/b.ts"),
                         ["a/b.ts", "a/c.ts"])

    def test_a_path_quoted_inside_an_error_message(self):
        self.assertEqual(
            hook.extract_path_tokens("No such file or directory: 'a/b'"), ["a/b"])
        self.assertEqual(
            hook.extract_path_tokens('cat: "lib/x.ts": No such file or directory'),
            ["lib/x.ts"])

    def test_the_command_and_the_error_are_both_read_and_merged_in_order(self):
        self.assertEqual(
            hook.extract_path_tokens("cat lib/a.ts", "cat: lib/a.ts: No such file",
                                     "also missing: lib/b.ts"),
            ["lib/a.ts", "lib/b.ts"])

    def test_a_URL_is_NEVER_treated_as_a_path(self):
        """It has slashes and would otherwise be absolutised against cwd."""
        for text in ("curl https://example.com/a/b",
                     "fetch http://localhost:3000/api/x",
                     "git clone git+ssh://host/repo.git",
                     "see https://example.com/docs/readme.md for details"):
            self.assertEqual(hook.extract_path_tokens(text), [], text)

    def test_a_flag_is_not_a_path_even_with_a_slash_in_it(self):
        self.assertEqual(hook.extract_path_tokens("grep -r --include=*.ts x"), [])

    def test_a_bare_filename_counts_only_with_a_file_ish_suffix(self):
        self.assertEqual(hook.extract_path_tokens("cat notes.md"), ["notes.md"])
        self.assertEqual(hook.extract_path_tokens("cat notes"), [])

    def test_a_bare_slash_is_not_a_path(self):
        self.assertEqual(hook.extract_path_tokens("ls / //"), [])

    def test_non_string_inputs_are_skipped_rather_than_crashing(self):
        self.assertEqual(hook.extract_path_tokens(None, 17, [], "cat a/b.ts"), ["a/b.ts"])


class AbsolutiseTests(unittest.TestCase):
    def test_a_relative_token_is_joined_to_cwd(self):
        self.assertEqual(hook.absolutise("lib/x.ts", "/w/root"), "/w/root/lib/x.ts")

    def test_an_absolute_token_ignores_cwd(self):
        self.assertEqual(hook.absolutise("/etc/hosts", "/w/root"), "/etc/hosts")

    def test_dot_segments_are_collapsed_lexically(self):
        self.assertEqual(hook.absolutise("a/../b.ts", "/w"), "/w/b.ts")

    def test_a_tilde_is_the_shells_business_not_ours(self):
        self.assertIsNone(hook.absolutise("~/x.ts", "/w"))

    def test_a_relative_token_with_no_usable_cwd_yields_nothing(self):
        for cwd in (None, "", "relative", 17):
            self.assertIsNone(hook.absolutise("lib/x.ts", cwd), repr(cwd))

    def test_a_NUL_or_empty_token_yields_nothing(self):
        self.assertIsNone(hook.absolutise("a\x00b", "/w"))
        self.assertIsNone(hook.absolutise("", "/w"))
        self.assertIsNone(hook.absolutise(None, "/w"))

    def test_it_never_resolves_a_symlink(self):
        """C7/C8 again: the token came out of an agent's own command line.

        Matched on the CALL rather than the word: the docstring says "never
        `realpath`" and a test that fails on its own explanation is a test that
        gets deleted.
        """
        with open(os.path.join(SRC, "dhu-backup-hook.py")) as handle:
            source = handle.read()
        for forbidden in ("os.path.realpath(", "os.realpath(", "Path(", ".resolve()"):
            self.assertNotIn(forbidden, source)


class AnnouncedStatusTests(unittest.TestCase):
    def test_the_silent_statuses_are_exactly_the_unprotected_ones(self):
        import dhu_backup_core

        silent = set(dhu_backup_core.ANNOUNCE_STATUSES) - set(hook.ANNOUNCED_STATUSES)
        self.assertEqual(silent, {"not-held", "outside-watch-roots"})

    def test_every_announced_status_has_a_lead_in_line(self):
        for status in hook.ANNOUNCED_STATUSES:
            self.assertIn(status, hook.LEAD_IN)
            self.assertTrue(hook.LEAD_IN[status].startswith("dhu-backup: "))


# ── the hook as a subprocess ──────────────────────────────────────────────────


class HookSubprocessTests(FixtureCase):
    def fire(self, payload, install_root=None):
        """Run the hook with `payload` on stdin. Returns (returncode, parsed, raw)."""
        root = self.install_root if install_root is None else install_root
        done = subprocess.run(
            [PYTHON, "-E", "-s", "-S", HOOK, "--install-root", root],
            input=payload if isinstance(payload, str) else json.dumps(payload),
            capture_output=True, text=True, env=dict(os.environ, TZ="UTC"))
        parsed = json.loads(done.stdout) if done.stdout.strip() else None
        return done, parsed

    @staticmethod
    def read_failure(path, cwd=FIXTURE_REPO, tool="Read", **extra):
        payload = {"session_id": "s1", "transcript_path": "/tmp/t.jsonl", "cwd": cwd,
                   "permission_mode": "default", "hook_event_name": "PostToolUseFailure",
                   "tool_name": tool, "tool_input": {"file_path": path},
                   "tool_use_id": "tu_1", "error": "File does not exist.",
                   "tool_response": "", "is_interrupt": False}
        payload.update(extra)
        return payload

    def context(self, parsed):
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["hookSpecificOutput"]["hookEventName"],
                         "PostToolUseFailure")
        return parsed["hookSpecificOutput"]["additionalContext"]

    # -- held ----------------------------------------------------------------

    def test_a_failed_Read_of_a_held_file_returns_the_versions_and_the_command(self):
        done, parsed = self.fire(self.read_failure(FIXTURE_REPO + "/lib/heartbeat.ts"))
        self.assertEqual(done.returncode, 0)
        context = self.context(parsed)
        self.assertIn("HELD", context)
        self.assertIn("3 version(s) of lib/heartbeat.ts", context)
        self.assertIn("dhu-backup", context)
        self.assertIn("cat lib/heartbeat.ts", context)
        self.assertTrue(context.startswith("dhu-backup: the file you just failed to read"))

    def test_a_failed_Edit_of_a_held_file_also_returns_context(self):
        done, parsed = self.fire(
            self.read_failure(FIXTURE_REPO + "/lib/notes.md", tool="Edit"))
        self.assertEqual(done.returncode, 0)
        self.assertIn("HELD", self.context(parsed))

    def test_a_held_directory_is_announced_as_a_directory(self):
        done, parsed = self.fire(self.read_failure(FIXTURE_REPO + "/lib/deep"))
        self.assertEqual(done.returncode, 0)
        context = self.context(parsed)
        self.assertIn("HELD (directory)", context)
        self.assertIn("restore-dir lib/deep", context)

    def test_the_worktree_copy_wins_for_a_path_under_the_longer_root(self):
        done, parsed = self.fire(
            self.read_failure(FIXTURE_WORKTREE + "/lib/heartbeat.ts", cwd=FIXTURE_WORKTREE))
        self.assertEqual(done.returncode, 0)
        self.assertIn("--root-id worktrees", self.context(parsed))

    # -- silence -------------------------------------------------------------

    def test_a_failed_Read_of_a_NOT_HELD_file_says_nothing_at_all(self):
        """An unprotected missing file is an ordinary error, not a finding."""
        done, parsed = self.fire(self.read_failure(FIXTURE_REPO + "/lib/never-existed.ts"))
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")
        self.assertEqual(done.stderr, "")
        self.assertIsNone(parsed)

    def test_a_path_outside_every_watch_root_says_nothing(self):
        done, _parsed = self.fire(self.read_failure("/etc/definitely-not-here.conf"))
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")

    def test_a_failure_on_a_file_that_STILL_EXISTS_says_nothing(self):
        """A permission denial is not a deletion, and the mirror has no comment.

        This is what keeps the hook off every failure that is not an ENOENT.
        """
        existing = os.path.join(self.install_root, "var", "state.json")
        done, _parsed = self.fire(self.read_failure(
            existing, error="EACCES: permission denied"))
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")

    def test_an_unknown_tool_says_nothing(self):
        payload = self.read_failure(FIXTURE_REPO + "/lib/heartbeat.ts", tool="WebFetch")
        done, _parsed = self.fire(payload)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")

    def test_an_interrupt_says_nothing_even_for_a_held_file(self):
        payload = self.read_failure(FIXTURE_REPO + "/lib/heartbeat.ts", is_interrupt=True)
        done, _parsed = self.fire(payload)
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")

    # -- Bash ----------------------------------------------------------------

    def bash_failure(self, command, error="", cwd=FIXTURE_REPO, response=""):
        return {"cwd": cwd, "hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                "tool_input": {"command": command}, "error": error,
                "tool_response": response, "is_interrupt": False}

    def test_a_failed_bash_cat_of_a_held_relative_path_returns_context(self):
        done, parsed = self.fire(self.bash_failure(
            "cat lib/notes.md", "cat: lib/notes.md: No such file or directory"))
        self.assertEqual(done.returncode, 0)
        context = self.context(parsed)
        self.assertIn("HELD", context)
        self.assertIn("lib/notes.md", context)

    def test_a_bash_failure_naming_only_a_URL_says_nothing(self):
        done, _parsed = self.fire(self.bash_failure(
            "curl https://example.com/lib/heartbeat.ts", "connection refused"))
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")

    def test_two_held_paths_in_one_command_produce_two_blocks(self):
        done, parsed = self.fire(self.bash_failure(
            "cat lib/notes.md lib/heartbeat.ts",
            "cat: lib/notes.md: No such file or directory"))
        context = self.context(parsed)
        self.assertEqual(context.count("dhu-backup: HELD"), 2)
        self.assertIn("\n\n", context)

    def test_a_bash_failure_with_no_usable_cwd_says_nothing(self):
        done, _parsed = self.fire(self.bash_failure("cat lib/notes.md", cwd=None))
        self.assertEqual(done.returncode, 0)
        self.assertEqual(done.stdout, "")

    # -- vaulted and unavailable ---------------------------------------------

    def test_a_vaulted_path_is_announced_with_the_sudo_commands(self):
        done, parsed = self.fire(self.read_failure(FIXTURE_REPO + "/.env.local"))
        self.assertEqual(done.returncode, 0)
        context = self.context(parsed)
        self.assertIn("VAULTED", context)
        self.assertIn("sudo DHU_BACKUP_ALLOW_ROOT=1", context)
        self.assertNotIn("<newest>", context)

    def test_an_unreadable_store_is_announced_because_it_is_a_finding(self):
        done, parsed = self.fire(self.read_failure(FIXTURE_REPO + "/lib/heartbeat.ts"),
                                 install_root="/nonexistent-xyz")
        self.assertEqual(done.returncode, 0)
        context = self.context(parsed)
        self.assertIn("STORE UNAVAILABLE", context)
        self.assertIn("NOT the same as 'no versions'", context)

    def test_a_stale_daemon_is_carried_into_the_context(self):
        import time

        write_state(self.install_root,
                    {"state": "ok", "last_scan_epoch": int(time.time()) - 86400})
        done, parsed = self.fire(self.read_failure(FIXTURE_REPO + "/lib/heartbeat.ts"))
        self.assertEqual(done.returncode, 0)
        self.assertIn("STALE", self.context(parsed))

    # -- never breaks --------------------------------------------------------

    def test_malformed_and_empty_stdin_are_silent_and_exit_0(self):
        for raw in ("not json", "", "   \n", "[]", "null", "17", '{"a":'):
            done, _parsed = self.fire(raw)
            self.assertEqual(done.returncode, 0, repr(raw))
            self.assertEqual(done.stdout, "", repr(raw))
            self.assertEqual(done.stderr, "", repr(raw))

    def test_hostile_payload_shapes_never_raise_and_never_exit_nonzero(self):
        hostile = [
            {"tool_name": "Read"},
            {"tool_name": "Read", "tool_input": "not a dict", "cwd": FIXTURE_REPO},
            {"tool_name": "Read", "tool_input": {"file_path": 17}, "cwd": FIXTURE_REPO},
            {"tool_name": "Read", "tool_input": {"file_path": "a\x00b"}, "cwd": FIXTURE_REPO},
            {"tool_name": "Bash", "tool_input": {"command": None}, "cwd": FIXTURE_REPO},
            {"tool_name": None, "tool_input": {}, "cwd": None},
            {"tool_name": "Read", "tool_input": {"file_path": "/" * 4000},
             "cwd": FIXTURE_REPO},
        ]
        for payload in hostile:
            done, _parsed = self.fire(payload)
            self.assertEqual(done.returncode, 0, json.dumps(payload)[:80])
            self.assertEqual(done.stderr, "", json.dumps(payload)[:80])

    def test_the_hook_never_exits_2(self):
        """Exit 2 shows stderr to Claude. This hook has no such opinion."""
        for payload in ("not json", self.read_failure(FIXTURE_REPO + "/lib/heartbeat.ts"),
                        self.read_failure("/etc/nope.conf")):
            done, _parsed = self.fire(payload)
            self.assertNotEqual(done.returncode, 2)

    def test_the_output_is_a_single_parseable_json_object(self):
        done, _parsed = self.fire(self.read_failure(FIXTURE_REPO + "/lib/heartbeat.ts"))
        self.assertEqual(len(done.stdout.strip().splitlines()), 1)
        payload = json.loads(done.stdout)
        self.assertEqual(list(payload), ["hookSpecificOutput"])
        self.assertEqual(sorted(payload["hookSpecificOutput"]),
                         ["additionalContext", "hookEventName"])


class HookInstallTests(unittest.TestCase):
    def test_the_installer_installs_the_hook_and_prints_the_registration(self):
        with open(os.path.join(SRC, "install.sh")) as handle:
            source = handle.read()
        # The installed set is a `<mode> <source> <dest>` table in install.sh,
        # read by both the --dry-run plan printer and the install itself.
        self.assertRegex(source, r"(?m)^0755\s+dhu-backup-hook\.py\s+bin/dhu-backup-hook\s*$")
        self.assertIn('"$DEST/bin/dhu-backup-hook"', source)
        self.assertIn("PostToolUseFailure", source)

    def test_the_hook_shells_out_to_nothing(self):
        with open(os.path.join(SRC, "dhu-backup-hook.py")) as handle:
            source = handle.read()
        for forbidden in ("import subprocess", "os.system", "os.popen", "os.exec"):
            self.assertNotIn(forbidden, source)
