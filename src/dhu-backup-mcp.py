#!/usr/bin/env -S /usr/bin/python3 -E -s -S
# `env -S` and not a bare `#!/usr/bin/python3 -E -s -S`: LINUX passes the whole
# tail of a shebang line as ONE argument, so that spelling reaches python as the
# single option "-E -s -S" and it exits with `Unknown option: -`. macOS splits
# it and works. Measured in the container, 2026-09-02, on this file. `env -S`
# splits it itself and is present and root-owned on both platforms; the
# interpreter after it stays ABSOLUTE, so no PATH lookup is introduced and the
# three flags that drop PYTHON* env, the user site directory and site.py all
# survive (review H3).
"""DHU Backup — MCP server. Installed as `bin/dhu-backup-mcp`. UNPRIVILEGED.

Register it with Claude Code:

    claude mcp add dhu-backup -- /usr/bin/python3 -E -s -S \\
        /Library/DHU/backup/bin/dhu-backup-mcp

Seven tools, all of them the CLI's own code paths reached a different way:

    dhu_backup_status       is the mirror capturing, and if not what to type
    dhu_backup_missing      what the store holds for a path that is GONE
    dhu_backup_ls           which protected paths have versions
    dhu_backup_log          the versions of one path
    dhu_backup_cat          the content of one version
    dhu_backup_restore      write one version back
    dhu_backup_restore_dir  write a whole directory back, as of a time

**This adds no privilege and no new write path.** It is the same unprivileged
helper behind a different transport: it reads the world-readable store as the
caller and writes only where the caller could already write, exactly as the CLI
does. It is emphatically NOT a command channel into the daemon (review C9 anti-
pattern 3) — nothing here talks to the daemon at all, and the daemon has no
input surface to talk to. It is stdio only: no socket, no port, no listener.

The server refuses to run as root for the reason the CLI does: under sudo the
caller-supplied `into` would become an arbitrary ROOT write.

Every tool result carries the daemon's health verdict, so a tool answering
"no versions" can never be mistaken for a daemon that stopped capturing
two days ago.

Protocol: JSON-RPC 2.0 over newline-delimited stdio, MCP 2025-06-18. Stdlib only.
"""

import base64
import importlib.machinery
import importlib.util
import io
import json
import os
import sys
import time
from contextlib import redirect_stdout

VERSION = "0.1.0"
PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "dhu-backup"

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dhu_backup_core        # noqa: E402
import dhu_backup_announce    # noqa: E402


def _load_helper():
    """Import `dhu-backup` (or `dhu-backup.py`) from THIS directory as a module.

    The helper's filename has a hyphen in both the repo and the install, so it
    is not importable by name. Loading it by path — from this script's own
    directory, which is root-owned in the install (review H3) — reuses the real
    implementation rather than re-deriving it here. Nothing is renamed.
    """
    for name in ("dhu-backup", "dhu-backup.py"):
        path = os.path.join(HERE, name)
        if os.path.isfile(path):
            spec = importlib.util.spec_from_loader(
                "dhu_backup_cli", importlib.machinery.SourceFileLoader("dhu_backup_cli", path))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    raise ImportError("no dhu-backup helper beside %s" % __file__)


helper = _load_helper()


# ── argument plumbing ─────────────────────────────────────────────────────────


class Args(object):
    """The attribute bag the helper's command functions expect.

    The CLI builds this with argparse; here it is built from the tool's
    arguments. Same fields, same defaults, so the two callers reach identical
    code with identical inputs.
    """

    def __init__(self, install_root, **kwargs):
        self.install_root = install_root
        self.root_id = kwargs.get("root_id")
        self.json = False
        self.quiet = True
        self.path = kwargs.get("path")
        self.directory = kwargs.get("directory")
        self.substring = kwargs.get("substring")
        self.asof = kwargs.get("asof")
        self.version = kwargs.get("version")
        self.into = kwargs.get("into")
        # A JSON boolean or absent, and nothing else: `bool("false")` is True,
        # and this flag gates the one destructive write on the whole surface.
        # The type check lives in `_optional_bool`; this bag only stores it.
        self.overwrite = kwargs.get("overwrite") is True


def _health(install_root):
    """The daemon's verdict, on EVERY tool result.

    One of `dhu_backup_core.HEALTH_VERDICTS`, which is where the list lives —
    this function names none of them, so a state added to the daemon reaches
    every MCP tool without an edit here. `warning` ("capturing, but about to
    stop") arrives that way and is not a kind of `ok`: a caller that treats it
    as one is the caller this field exists for.
    """
    verdict = dhu_backup_announce._read_health(install_root, time.time())
    return {"verdict": verdict.verdict, "detail": verdict.detail}


def _require(arguments, name):
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError("%r is required and must be a non-empty string" % name)
    return value


def _optional(arguments, name):
    value = arguments.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("%r must be a string" % name)
    return value


def _optional_bool(arguments, name):
    """A JSON boolean, absent, or a -32602 — never a truthy string.

    `overwrite` gates the only destructive path here. `bool(value)` accepted
    the strings "false" and "no" as True, so a client that stringifies its
    booleans — LLM tool callers do — replaced an agent's intentional edit with
    the stored version while believing it had said no. The schema declares
    `boolean`; this is what makes the declaration true.
    """
    value = arguments.get(name)
    if value is None:
        return None
    if value is not True and value is not False:
        raise ValueError("%r must be a JSON boolean (true or false), not %s"
                         % (name, type(value).__name__))
    return value


# ── the seven tools ───────────────────────────────────────────────────────────


def tool_missing(install_root, arguments):
    result = dhu_backup_announce.announce(_require(arguments, "path"),
                                          install_root=install_root)
    payload = dhu_backup_announce.to_json(result)
    payload["text"] = dhu_backup_announce.format_text(result)
    return payload, result.status == "store-unavailable"


def tool_status(install_root, arguments):
    """The CLI's `status`, unchanged, as a tool.

    `is_error` is TRUE only when the status could not be determined (exit code
    2). A daemon that has stopped capturing is an ANSWER — the answer the caller
    most needs — and returning it as a protocol error would invite a client to
    retry it or to drop it on the floor.
    """
    payload = helper.status_payload(install_root)
    payload["text"] = helper.format_status(payload)
    return payload, payload["exit_code"] == 2


#: Matches one `dhu_backup_ls` result carries. The CLI streams lines and can
#: list a whole store; an MCP result is ONE JSON frame handed to a model, and
#: an unfiltered call against a real store produced a 35 MB frame of 34,649
#: matches. Past this the result says `truncated: true`, carries the full
#: `match_count`, and tells the caller to narrow the substring — the same rule
#: `_select_one` applies to its candidate list.
LS_MAX_MATCHES = 500


def tool_ls(install_root, arguments):
    args = Args(install_root, substring=_optional(arguments, "substring"),
                root_id=_optional(arguments, "root_id"))
    entries, error = helper.load_entries(install_root)
    health = _health(install_root)
    if error:
        return {"error": error, "health": health, "matches": [], "store_paths": 0,
                "match_count": 0, "truncated": False, "hint": None}, True
    matches = helper.select_entries(entries, args.substring, args.root_id)
    truncated = len(matches) > LS_MAX_MATCHES
    return {
        "error": None,
        "health": health,
        "store_paths": len(entries),
        "vault_present": helper.vault_is_present(install_root),
        "match_count": len(matches),
        "truncated": truncated,
        "hint": ("%d paths match; only the first %d are listed. Narrow the "
                 "substring (or pass root_id) to see the rest."
                 % (len(matches), LS_MAX_MATCHES)) if truncated else None,
        "matches": [
            {"relpath": e["relpath"], "root_id": e["root_id"], "slug": e["slug"],
             "watch_root": e["watch_root"],
             "origin": os.path.join(e["watch_root"], e["relpath"]),
             "versions": len(e["versions"]),
             "newest_epoch_ns": e["versions"][-1]["epoch_ns"],
             "newest_iso": helper._iso(e["versions"][-1]["epoch_ns"])}
            for e in matches[:LS_MAX_MATCHES]
        ],
    }, False


def tool_log(install_root, arguments):
    args = Args(install_root, path=_require(arguments, "path"),
                root_id=_optional(arguments, "root_id"))
    entry, _code, failure = helper._select_one(args, args.path)
    payload = {"health": _health(install_root), "path": args.path}
    if failure is not None:
        payload.update(failure)
        payload["versions"] = []
        return payload, failure["kind"] == "store-unavailable"
    payload.update({
        "error": None, "kind": "ok",
        "relpath": entry["relpath"], "root_id": entry["root_id"], "slug": entry["slug"],
        "watch_root": entry["watch_root"],
        "origin": os.path.join(entry["watch_root"], entry["relpath"]),
        "versions": [
            {"key": v["key"], "epoch_ns": v["epoch_ns"], "iso": helper._iso(v["epoch_ns"]),
             "size": v["size"], "sha": v["sha"], "store_path": v["path"]}
            for v in entry["versions"]
        ],
    })
    return payload, False


def tool_cat(install_root, arguments):
    """The content of one version.

    Written against the helper's `_select_one`/`_pick_version` rather than
    calling `command_cat`, which writes bytes to `sys.stdout.buffer` — a stream
    that does not exist once stdout is a capture buffer, and which would in any
    case be the JSON-RPC transport. Selection and `--asof` resolution are the
    helper's, unchanged.
    """
    args = Args(install_root, path=_require(arguments, "path"),
                asof=_optional(arguments, "asof"), version=_optional(arguments, "version"),
                root_id=_optional(arguments, "root_id"))
    entry, _code, failure = helper._select_one(args, args.path)
    payload = {"health": _health(install_root), "path": args.path}
    if failure is not None:
        payload.update(failure)
        return payload, failure["kind"] == "store-unavailable"

    captured = io.StringIO()
    with redirect_stdout(captured):
        version, _code = helper._pick_version(entry, args)
    if version is None:
        payload.update({"error": captured.getvalue().strip() or "no such version",
                        "kind": "no-version"})
        return payload, False

    try:
        with open(version["path"], "rb") as handle:
            raw = handle.read()
    except (IOError, OSError) as exc:
        payload.update({"error": "could not read %s: %s" % (version["path"], exc),
                        "kind": "store-unavailable"})
        return payload, True

    payload.update({
        "error": None, "kind": "ok",
        "relpath": entry["relpath"], "root_id": entry["root_id"],
        "key": version["key"], "epoch_ns": version["epoch_ns"],
        "iso": helper._iso(version["epoch_ns"]), "size": version["size"],
        "sha": version["sha"], "store_path": version["path"],
    })
    try:
        payload["content"] = raw.decode("utf-8")
        payload["encoding"] = "utf-8"
    except UnicodeDecodeError:
        # Say so in a FIELD rather than handing back mojibake that looks like
        # the file. A caller that ignores `encoding` gets base64 it cannot
        # mistake for text.
        payload["content"] = base64.b64encode(raw).decode("ascii")
        payload["encoding"] = "base64"
    return payload, False


def _run_capturing(function, args):
    """Run a helper outcome function with its printed lines captured.

    Returns `((code, kind), lines)` — whatever the function returned, plus the
    lines it printed.
    """
    captured = io.StringIO()
    with redirect_stdout(captured):
        outcome = function(args)
    return outcome, captured.getvalue().splitlines()


#: Restore kinds that mean the tool could NOT do what it was asked because of
#: the environment — the store could not be read, or the destination could not
#: be written. Those are `isError: true`. "Written beside a differing file",
#: "no version at that time" and "no such path" are ANSWERS, and stay results.
_RESTORE_ERROR_KINDS = ("store-unavailable", "destination-unwritable", "refused")


def _restore_refusal(install_root):
    """`restore_permitted` applied here too — belt and braces.

    `refuse_root` already stops this server from starting as root, so this can
    only fire if that check is ever weakened. It is the same PURE predicate the
    CLI wires in, so the two cannot drift into different answers, and the cost
    of the redundancy is one function call. C6's lesson: for the check whose
    blast radius is "the recovered file stops being protected", two independent
    refusals is the right amount.
    """
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    verdict = dhu_backup_core.restore_permitted(euid)
    if isinstance(verdict, dhu_backup_core.Refuse):
        return {"health": _health(install_root), "exit_code": 2, "lines": [verdict.reason],
                "text": verdict.reason, "error": verdict.reason, "kind": "refused"}
    return None


def tool_restore(install_root, arguments):
    refusal = _restore_refusal(install_root)
    if refusal is not None:
        return refusal, True
    args = Args(install_root, path=_require(arguments, "path"),
                asof=_optional(arguments, "asof"), version=_optional(arguments, "version"),
                into=_optional(arguments, "into"),
                overwrite=_optional_bool(arguments, "overwrite"),
                root_id=_optional(arguments, "root_id"))
    (code, kind), lines = _run_capturing(helper.restore_outcome, args)
    return {"health": _health(install_root), "exit_code": code, "kind": kind,
            "lines": lines, "text": "\n".join(lines)}, kind in _RESTORE_ERROR_KINDS


def tool_restore_dir(install_root, arguments):
    refusal = _restore_refusal(install_root)
    if refusal is not None:
        return refusal, True
    args = Args(install_root, directory=_require(arguments, "directory"),
                asof=_optional(arguments, "asof"), into=_optional(arguments, "into"),
                overwrite=_optional_bool(arguments, "overwrite"),
                root_id=_optional(arguments, "root_id"))
    (code, kind), lines = _run_capturing(helper.restore_dir_outcome, args)
    return {"health": _health(install_root), "exit_code": code, "kind": kind,
            "lines": lines, "text": "\n".join(lines)}, kind in _RESTORE_ERROR_KINDS


_PATH = {"type": "string", "description": "a path or path substring as the store holds it"}
_ASOF = {"type": "string",
         "description": "ISO timestamp or relative age (20m, 2h, 3d); the newest "
                        "version at or before it, and nothing if none qualifies"}

#: `InitializeResult.instructions` — the spec describes it as a hint a client
#: MAY add to the model's system prompt. For this server that is Property 4 at
#: the protocol level: the mirror announcing itself BEFORE a read fails, rather
#: than waiting to be asked afterwards. Omitting it left the whole point of the
#: product to be discovered.
INSTRUCTIONS = (
    "DHU Backup keeps an append-only mirror of the files a coding agent can "
    "delete, written by a root daemon that agent cannot touch.\n\n"
    "Call dhu_backup_missing FIRST whenever a file read or edit fails with "
    "\"no such file\" \u2014 before concluding the file never existed, and before "
    "reconstructing anything by hand. It takes the absolute path that failed "
    "and reports whether the mirror holds versions of it, with the exact "
    "command to read them back.\n\n"
    "dhu_backup_ls, dhu_backup_log and dhu_backup_cat only read. "
    "dhu_backup_restore and dhu_backup_restore_dir write files back where they "
    "came from; restore_dir is the one to reach for when a whole directory is "
    "gone.\n\n"
    "Every result carries the daemon's health verdict. A status of "
    "store-unavailable means the lookup could NOT be made, which is not the "
    "same fact as there being no versions \u2014 never treat it as an empty result."
)

#: `Tool.outputSchema` is deliberately NOT set, and this is the recorded reason
#: rather than an omission by default. The spec makes it a promise: "If an
#: output schema is provided: Servers MUST provide structured results that
#: conform to this schema." Every tool here returns a UNION of shapes — an ok
#: payload, and several distinct failure payloads that carry `kind` and the
#: reason — because refusing to collapse "I could not look" into "there is
#: nothing" is the point. A schema loose enough to admit all of them validates
#: nothing, and a schema tight enough to be useful would make the failure paths
#: violate a MUST. Revisit if the payloads are ever narrowed.

# ── tool annotations (MCP `ToolAnnotations`) ──────────────────────────────────
#
# All four hints are set explicitly on every tool, including the two the spec
# calls "meaningful only when `readOnlyHint == false`". That redundancy is
# deliberate. The schema's defaults are `destructiveHint: true` and
# `openWorldHint: true`, so a tool that omits them is advertising itself as
# possibly destructive and possibly reaching an open world — which was true of
# this server's four read-only tools until an external index flagged it. A
# client that reads `destructiveHint` without first checking `readOnlyHint`
# then sees the wrong answer, and "the default happened to be safe" is not a
# property worth relying on. Writing all four leaves nothing to a default.
#
# The spec is also explicit that a CLIENT must treat these as untrusted unless
# the server is trusted. That is the right posture and it is the same one this
# project takes everywhere else: these hints are a description, never a control.
# Nothing here enforces read-onlyness — the kernel does that, by owning the
# store, and `restore_permitted` refuses root regardless of what any hint says.
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False,
             "idempotentHint": True, "openWorldHint": False}
# `destructiveHint` is true for the two writers because both accept arguments
# that can REPLACE a file at the origin (`overwrite`), even though the default
# path writes beside a differing file rather than over it. Declaring the
# capability rather than the common case is the honest direction for a hint a
# client may use to decide whether to ask a human first.
WRITES = {"readOnlyHint": False, "destructiveHint": True,
          "idempotentHint": True, "openWorldHint": False}

TOOLS = [
    {
        "name": "dhu_backup_status",
        "title": 'Is the mirror capturing right now?',
        "annotations": READ_ONLY,
        "description": "Whether DHU Backup is capturing on this machine, and if not, the "
                       "one command that addresses it. Reports the daemon's health "
                       "verdict, when the last capture was, the watch roots in force "
                       "with the count of PATHS held under each, the store size and free "
                       "space against the budgets that stop capture, and the operator's "
                       "exclusion and vault-extra glob counts. `exit_code` is 0 when "
                       "capturing, 1 when not, 2 when it could not be determined.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "dhu_backup_missing",
        "title": 'What the mirror holds for a file that is gone',
        "annotations": READ_ONLY,
        "description": "Call this when a file read fails. Given the ABSOLUTE path that "
                       "is gone, say whether the root-owned mirror holds versions of it, "
                       "and give the exact command to read them back. Statuses: held, "
                       "held-directory, vaulted, not-held, outside-watch-roots, "
                       "store-unavailable. store-unavailable means the lookup could not "
                       "be made and is NOT the same as not-held.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string",
                                    "description": "the absolute path whose read failed"}},
            "required": ["path"],
        },
    },
    {
        "name": "dhu_backup_ls",
        "title": 'List protected paths that have versions',
        "annotations": READ_ONLY,
        "description": "Which protected paths have versions in the mirror. Optional "
                       "substring filter on the path relative to its watch root. At "
                       "most %d matches are returned; `match_count` is the true "
                       "total and `truncated: true` with a `hint` says to narrow the "
                       "substring when it binds." % LS_MAX_MATCHES,
        "inputSchema": {
            "type": "object",
            "properties": {
                "substring": {"type": "string", "description": "match paths containing this"},
                "root_id": {"type": "string", "description": "limit to one watch-root id"},
            },
        },
    },
    {
        "name": "dhu_backup_log",
        "title": 'Version history of one path',
        "annotations": READ_ONLY,
        "description": "Every version of one path: capture time, size, content hash and "
                       "store location.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": _PATH,
                           "root_id": {"type": "string",
                                       "description": "limit to one watch-root id"}},
            "required": ["path"],
        },
    },
    {
        "name": "dhu_backup_cat",
        "title": 'Read one stored version',
        "annotations": READ_ONLY,
        "description": "The content of one stored version. UTF-8 when it decodes, "
                       "otherwise base64 — the `encoding` field says which.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH, "asof": _ASOF,
                "version": {"type": "string", "description": "an exact version key, @<ns>-<sha>"},
                "root_id": {"type": "string", "description": "limit to one watch-root id"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "dhu_backup_restore",
        "title": 'Restore one file',
        "annotations": WRITES,
        "description": "Write one stored version back to disk. The destination is DERIVED "
                       "from the stored path plus its watch root; `into` names an "
                       "alternative base DIRECTORY, never a filename. Nothing is silently "
                       "overwritten: a differing file gets the version beside it unless "
                       "`overwrite` is set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": _PATH, "asof": _ASOF,
                "version": {"type": "string", "description": "an exact version key, @<ns>-<sha>"},
                "into": {"type": "string", "description": "restore under this base directory"},
                "overwrite": {"type": "boolean", "description": "replace a differing file"},
                "root_id": {"type": "string", "description": "limit to one watch-root id"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "dhu_backup_restore_dir",
        "title": 'Restore a whole directory as of a time',
        "annotations": WRITES,
        "description": "Write a whole directory back as of a time — the shape of the "
                       "incident this tool exists for. Paths with no version at or "
                       "before that time are reported skipped, never silently omitted.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "directory": {"type": "string",
                              "description": "the directory, relative to its watch root"},
                "asof": _ASOF,
                "into": {"type": "string", "description": "restore under this base directory"},
                "overwrite": {"type": "boolean", "description": "replace differing files"},
                "root_id": {"type": "string", "description": "limit to one watch-root id"},
            },
            "required": ["directory"],
        },
    },
]

DISPATCH = {
    "dhu_backup_status": tool_status,
    "dhu_backup_missing": tool_missing,
    "dhu_backup_ls": tool_ls,
    "dhu_backup_log": tool_log,
    "dhu_backup_cat": tool_cat,
    "dhu_backup_restore": tool_restore,
    "dhu_backup_restore_dir": tool_restore_dir,
}


# ── JSON-RPC 2.0 over newline-delimited stdio ─────────────────────────────────


def _result(request_id, payload):
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id, code, message):
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def handle(message, install_root):
    """One request in, one response out — or None for a notification.

    JSON-RPC 2.0: a request WITHOUT an `id` member is a notification and MUST
    NOT be answered, whatever its method and even when it is malformed. One
    whose `id` is present and null is a request, and is answered with that
    id. This used to answer every id-less message with `"id": null`.
    """
    if not isinstance(message, dict):
        return _error(None, -32600, "request must be a JSON object")
    is_notification = "id" not in message
    response = _handle_request(message, install_root)
    return None if is_notification else response


def _handle_request(message, install_root):
    request_id = message.get("id")
    method = message.get("method")
    if not isinstance(method, str):
        return _error(request_id, -32600, "missing method")
    params = message.get("params") or {}
    if not isinstance(params, dict):
        return _error(request_id, -32602, "params must be an object")

    if method == "initialize":
        return _result(request_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": VERSION},
            "instructions": INSTRUCTIONS,
        })
    if method in ("notifications/initialized", "initialized"):
        return None
    if method.startswith("notifications/"):
        return None
    if method == "ping":
        return _result(request_id, {})
    if method == "tools/list":
        return _result(request_id, {"tools": TOOLS})
    if method == "tools/call":
        return _call_tool(request_id, params, install_root)
    return _error(request_id, -32601, "unknown method: %s" % method)


def _call_tool(request_id, params, install_root):
    name = params.get("name")
    if not isinstance(name, str):
        # A list or an object here reached `DISPATCH.get` and died unhashable,
        # taking the transport with it. A tool name is a string or it is a
        # bad parameter.
        return _error(request_id, -32602, "tool name must be a string, not %s"
                      % type(name).__name__)
    arguments = params.get("arguments") or {}
    if not isinstance(arguments, dict):
        return _error(request_id, -32602, "arguments must be an object")
    function = DISPATCH.get(name)
    if function is None:
        return _error(request_id, -32602, "unknown tool: %r" % (name,))
    try:
        payload, is_error = function(install_root, arguments)
    except ValueError as exc:
        return _error(request_id, -32602, str(exc))
    except Exception as exc:            # noqa: BLE001
        # A tool that throws must not take the transport down with it: the
        # caller is usually an error handler already. `kind` is `internal-error`
        # and not `store-unavailable`: this handler knows nothing about the
        # store, and naming it sent readers to the wrong side of every failure
        # that was not the store's. The health field is here too — the
        # docstring's promise is EVERY result, and this was the one without.
        payload = {"error": "%s: %s" % (type(exc).__name__, exc),
                   "kind": "internal-error", "health": _health(install_root)}
        is_error = True
    return _result(request_id, {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "structuredContent": payload,
        "isError": bool(is_error),
    })


def refuse_root():
    """Same rule as the CLI, and to stderr — stdout is the protocol."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        sys.stderr.write(
            "ERROR dhu-backup-mcp must not run as root. The store is world-readable by "
            "design, so recovery needs no sudo, and under sudo the caller-supplied "
            "`into` would be an arbitrary ROOT write.\n")
        return True
    return False


def serve(stdin, stdout, install_root):
    """Newline-delimited JSON-RPC until EOF. One bad frame is one -32700.

    Frames are read as BYTES and decoded here, so a frame that is not valid
    UTF-8 is a parse error on that frame rather than a `UnicodeDecodeError`
    out of the text stream that ends the session (on macOS / Python 3.9 the
    text stdin decodes strictly). A frame nested deeply enough to exhaust the
    parser's recursion is the same parse error: `json.loads` raises
    `RecursionError`, which is not a `ValueError`.
    """
    raw = getattr(stdin, "buffer", stdin)
    for line in raw:
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError as exc:
                _emit(stdout, _error(None, -32700, "parse error: frame is not valid UTF-8 "
                                     "(%s)" % exc.reason))
                continue
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError as exc:
            response = _error(None, -32700, "parse error: %s" % exc)
        except RecursionError:
            response = _error(None, -32700, "parse error: JSON nested too deeply")
        else:
            response = handle(message, install_root)
        if response is not None:
            _emit(stdout, response)
    return 0


def _emit(stdout, response):
    stdout.write(json.dumps(response) + "\n")
    stdout.flush()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    install_root = dhu_backup_core.DEFAULT_INSTALL_ROOT
    if "--install-root" in argv:
        index = argv.index("--install-root")
        if index + 1 >= len(argv):
            sys.stderr.write("usage: dhu-backup-mcp [--install-root DIR]\n")
            return 2
        install_root = argv[index + 1]
        del argv[index:index + 2]
    if argv:
        sys.stderr.write("usage: dhu-backup-mcp [--install-root DIR]\n")
        return 2
    if refuse_root():
        return 2
    return serve(sys.stdin, sys.stdout, install_root)


if __name__ == "__main__":
    raise SystemExit(main())
