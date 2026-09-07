#!/usr/bin/env -S /usr/bin/python3 -E -s -S
# `env -S` and not a bare `#!/usr/bin/python3 -E -s -S`: LINUX passes the whole
# tail of a shebang line as ONE argument, so that spelling reaches python as the
# single option "-E -s -S" and it exits with `Unknown option: -`. macOS splits
# it and works. Measured in the container, 2026-09-02, on this file. `env -S`
# splits it itself and is present and root-owned on both platforms; the
# interpreter after it stays ABSOLUTE, so no PATH lookup is introduced and the
# three flags that drop PYTHON* env, the user site directory and site.py all
# survive (review H3).
"""DHU Backup — Claude Code `PostToolUseFailure` hook. Installed as
`bin/dhu-backup-hook`. UNPRIVILEGED.

This is Property 4's last mile. Everything else in this repo waits to be asked;
this is the piece that speaks first. When a tool call fails on a path the mirror
holds, Claude Code runs this hook and the failure itself comes back carrying the
versions and the command that reads them back — no tool had to know about
`dhu-backup`, and no agent had to read a project instructions file.

Register it in `~/.claude/settings.json` (user-wide) or a project's
`.claude/settings.json`:

    {"hooks": {"PostToolUseFailure": [{"matcher": "Read|Edit|Bash",
      "hooks": [{"type": "command", "command":
        "/usr/bin/python3 -E -s -S /Library/DHU/backup/bin/dhu-backup-hook"}]}]}}

Contract (code.claude.com/docs/en/hooks):

  in   one JSON object on stdin: session_id, transcript_path, cwd,
       permission_mode, hook_event_name, tool_name, tool_input, tool_use_id,
       error, tool_response, is_interrupt.
  out  `{"hookSpecificOutput": {"hookEventName": "PostToolUseFailure",
       "additionalContext": "<text Claude sees>"}}` on stdout, or nothing.
  exit 0 normal. 2 shows stderr to Claude but cannot block. Others ignored.

**It is silent unless it has something to say, and it always exits 0.** A hook
runs on the failure path of a tool an agent is already recovering from, so two
failure modes are worse than not having it: noise on every ordinary
file-not-found, and an exception that turns a recoverable error into a broken
hook. So `not-held` and `outside-watch-roots` produce NO output at all — an
unprotected missing file is an ordinary error — and every exception is caught,
including the ones not thought of. It never exits 2, because it has nothing to
say that is worth a stderr banner, and it never blocks anything.

It holds no privilege: it reads the world-readable store as the agent, writes
nothing, and talks to no daemon.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dhu_backup_announce  # noqa: E402
import dhu_backup_core  # noqa: E402

HOOK_EVENT = "PostToolUseFailure"

#: Statuses worth interrupting an agent for. `not-held` and
#: `outside-watch-roots` are deliberately absent: a missing file that was never
#: protected is an ordinary error, and a hook that comments on every one of them
#: is noise that gets the hook turned off. `store-unavailable` IS here, because
#: a protection that cannot be read is a finding, not a non-event.
ANNOUNCED_STATUSES = ("held", "held-directory", "vaulted", "store-unavailable")

LEAD_IN = {
    "held": "dhu-backup: the file you just failed to read is held by the root-owned mirror —",
    "held-directory": "dhu-backup: the directory you just failed to read is held by the "
                      "root-owned mirror —",
    "vaulted": "dhu-backup: the file you just failed to read is credential-class, so the "
               "mirror would hold it in the root-only vault —",
    "store-unavailable": "dhu-backup: could not determine whether the mirror holds the file "
                         "you just failed to read —",
}

#: Path-like tokens taken from one Bash command line. More than this and the
#: hook is doing a survey rather than answering a question, and each one costs a
#: store lookup on an agent's error path.
MAX_CANDIDATES = 8

TOOLS_WITH_A_FILE_PATH = ("Read", "Edit", "MultiEdit", "Write", "NotebookEdit")
TOOLS_WITH_A_COMMAND = ("Bash", "BashOutput")

_FILEISH_SUFFIX = re.compile(
    r"\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go|rs|java|kt|swift|c|h|cc|cpp|hpp|sh|bash|zsh"
    r"|json|jsonc|ya?ml|toml|ini|cfg|conf|env|md|mdx|txt|csv|tsv|sql|html|css|scss"
    r"|lock|log|plist|xml|svg|proto|graphql|prisma|tf)$", re.I)

#: A URL is not a path. `https://example.com/a/b` contains slashes and would
#: otherwise be absolutised against `cwd` and looked up, which is both wrong and
#: a way to make the hook chatty about things that were never files.
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")

_QUOTE_TRIM = "\"'`,;:()[]{}<>"


def looks_like_a_path(token):
    """Is this token worth treating as a filesystem path? PURE.

    Two ways in, both conservative: it contains a `/`, or it ends in a suffix
    that is unambiguously a file's. Bare words are rejected — a Bash command
    line is full of them, and `cat` is not a file.
    """
    if not token or _SCHEME.match(token):
        return False
    if token.startswith("-"):
        return False
    if "://" in token:
        return False
    if "/" in token:
        # `a/b` yes; a bare `/` or `//` no, and neither is `~` alone.
        return bool(token.strip("/"))
    return bool(_FILEISH_SUFFIX.search(token))


def extract_path_tokens(*texts):
    """Ordered, de-duplicated path-like tokens from a Bash command and its error.

    PURE — takes strings, returns strings, touches no filesystem. The command
    line is one source; the ERROR text is the other and often the better one,
    because "No such file or directory: 'a/b'" names the path the shell actually
    could not find, after any expansion the command line only implied.
    """
    found = []
    seen = set()
    for text in texts:
        if not isinstance(text, str):
            continue
        for raw in re.split(r"[\s]+", text):
            token = raw.strip(_QUOTE_TRIM)
            # A trailing quote inside a message like: No such file: 'a/b'
            token = token.strip(_QUOTE_TRIM)
            if not looks_like_a_path(token):
                continue
            if token not in seen:
                seen.add(token)
                found.append(token)
    return found


def absolutise(token, cwd):
    """An absolute, lexically normalised path for one token, or None. PURE.

    `os.path.normpath` only — never `realpath`. C7/C8: resolve-then-check is the
    race, and the token came out of an agent's own command line, so resolving it
    would let one planted symlink aim the lookup wherever it liked.
    """
    if not isinstance(token, str) or not token or "\x00" in token:
        return None
    if token.startswith("~"):
        # `~` is the shell's, not ours, and expanding it here would answer about
        # a different user's home than the shell meant if HOME is unset.
        return None
    if token.startswith("/"):
        return os.path.normpath(token)
    if not isinstance(cwd, str) or not cwd.startswith("/"):
        return None
    return os.path.normpath(os.path.join(cwd, token))


def candidates_for(payload):
    """Absolute paths this failure might be about. PURE apart from `lexists`.

    Only paths that are MISSING RIGHT NOW survive. A tool call can fail for many
    reasons — a permission denial, a syntax error, a timeout — and the mirror has
    nothing useful to say about a file that is sitting there. Checking existence
    is what keeps the hook quiet on every failure that is not a deletion.
    """
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    cwd = payload.get("cwd")

    tokens = []
    if tool in TOOLS_WITH_A_FILE_PATH:
        for key in ("file_path", "notebook_path", "path"):
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                tokens.append(value)
    elif tool in TOOLS_WITH_A_COMMAND:
        tokens = extract_path_tokens(tool_input.get("command"),
                                     payload.get("error"),
                                     payload.get("tool_response"))
    else:
        return []

    absolute = []
    seen = set()
    for token in tokens:
        path = absolutise(token, cwd)
        if path is None or path in seen:
            continue
        seen.add(path)
        try:
            if os.path.lexists(path):
                continue
        except (OSError, ValueError):
            continue
        absolute.append(path)
        if len(absolute) >= MAX_CANDIDATES:
            break
    return absolute


def block_for(result):
    """The text Claude sees for one announcement, or None to stay silent."""
    if result.status not in ANNOUNCED_STATUSES:
        return None
    return "%s\n%s" % (LEAD_IN[result.status], dhu_backup_announce.format_text(result))


def build_context(payload, install_root):
    """The whole `additionalContext`, or None. Never raises."""
    if payload.get("is_interrupt"):
        # The user stopped the tool. Nothing was lost, and a hook that speaks up
        # during an interrupt is arguing with the person who pressed the key.
        return None
    blocks = []
    for path in candidates_for(payload):
        result = dhu_backup_announce.announce(path, install_root=install_root)
        block = block_for(result)
        if block:
            blocks.append(block)
    return "\n\n".join(blocks) if blocks else None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    install_root = dhu_backup_core.DEFAULT_INSTALL_ROOT
    if "--install-root" in argv:
        index = argv.index("--install-root")
        if index + 1 < len(argv):
            install_root = argv[index + 1]
    try:
        raw = sys.stdin.read()
        try:
            payload = json.loads(raw) if raw.strip() else None
        except ValueError:
            # Malformed stdin is a CLASSIFIED outcome, not an internal error:
            # there is no path to look up, so there is nothing to say and
            # nothing to report. Silent, exit 0 — stderr is reserved for the
            # failures this hook could not account for.
            return 0
        if not isinstance(payload, dict):
            return 0
        context = build_context(payload, install_root)
        if context:
            json.dump({"hookSpecificOutput": {"hookEventName": HOOK_EVENT,
                                              "additionalContext": context}}, sys.stdout)
            sys.stdout.write("\n")
    except Exception as exc:            # noqa: BLE001 — the whole point
        # A hook that throws on an agent's error path makes a recoverable
        # failure worse. One line to stderr so it is findable, and exit 0 so
        # nothing downstream changes. Never exit 2: this hook has no opinion
        # strong enough to be worth a banner Claude cannot act on.
        try:
            sys.stderr.write("dhu-backup-hook: %s: %s\n" % (type(exc).__name__, exc))
        except Exception:               # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
