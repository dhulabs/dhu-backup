#!/bin/bash
# DHU Backup — installer. Run ONCE, by a human:
#
#     sudo bash src/install.sh --watch repo=/Users/you/Projects/my-repo
#
#   --watch <id>=<abs-path>   a directory to protect. Repeatable.
#   --watchlist <file>        the same, read from a file in watchlist format.
#                             Repeatable, and combinable with --watch.
#   --owner-uid <n>           the uid whose files are protected (default $SUDO_UID).
#   --dry-run                 print exactly what this would do and change nothing.
#                             Runnable without sudo.
#   --platform darwin|linux   plan for the OTHER platform. --dry-run ONLY.
#   --no-service              install the files but do not register a service.
#                             Linux only, and only where no systemd manager is
#                             running (a container). Refused on a real host.
#
# TWO platforms. The install ROOT is /Library/DHU/backup on macOS and
# /opt/dhu-backup on Linux — that is the product's identity on each, and it is
# not configurable. What IS configurable is which directories are WATCHED, and
# there is deliberately no default for those: see `watchlist_decision` below.
# The service is a LaunchDaemon on macOS and a systemd system unit on Linux;
# everything that differs is in `set_platform` and the four `service_*`
# functions, so the main flow below reads the same on both.
#
# On a RE-RUN with no --watch/--watchlist, the installed etc/watchlist.conf is
# kept as it is. That is what lets a wrapper script re-run this installer with no
# arguments after every code change.
#
# H9, accepted and named: this script is delivered from the agent-writable repo
# and run with sudo, so an agent could edit it before you run it. There is no way
# around that — installing a root daemon is a one-time trust transfer from a
# human. The mitigations are that it is short enough to read, it prints the
# sha256 of everything it installs, and AFTER installation nothing in the repo is
# on the trust path. Read it once before running it.
#
# Idempotent: a re-run replaces bin/ and the service file, PRESERVES an existing
# etc/dhu-backupd.conf (leaving the repo version alongside as .dist to diff) and
# an existing etc/watchlist.conf (unless you pass new roots), and NEVER touches
# var/store.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The one interpreter a root daemon may execute. Identical on both platforms and
# NOT configurable: on macOS it is the system Python, on Ubuntu the distro
# package (`apt-get install python3`). Never node, never homebrew, never pyenv —
# a user-owned binary executed by root is a root shell for any agent (review
# H2). `check_interpreter` asserts it before the service file is written.
INTERPRETER=/usr/bin/python3
# No default uid. `${SUDO_UID:-501}` would silently protect the FIRST account on
# a machine where the human is the second one, and a root shell without sudo has
# no SUDO_UID at all. Unset means refuse, below. $SUDO_UID is set by sudo on
# Linux exactly as it is on macOS.
OWNER_UID="${SUDO_UID:-}"

# ── platform ──────────────────────────────────────────────────────────────────
# TWO platforms, one script. Everything that differs between them is either in
# the table `set_platform` builds or behind one of the four `service_*`
# functions; the main flow below is platform-free. That is deliberate: a second
# copy of this installer would drift from the first, and the half that drifted
# would be the half nobody ran that day.

# `uname -s` -> the platform token used everywhere else. An unknown kernel is
# `unsupported`, which is refused loudly rather than defaulted into macOS.
platform_from_uname() {  # <uname -s>
  case "$1" in
    Darwin) echo darwin ;;
    Linux)  echo linux ;;
    *)      echo unsupported ;;
  esac
}

# The install ROOT per platform. This table is the shell's copy of
# `DEFAULT_INSTALL_ROOTS` in src/dhu_backup_core.py, and a test asserts the two
# agree: a daemon that reads its config from one path while the installer wrote
# it to another comes up with defaults and protects nothing.
platform_install_root() {  # <platform>
  case "$1" in
    darwin) echo /Library/DHU/backup ;;
    linux)  echo /opt/dhu-backup ;;
    *)      echo "unsupported platform: $1" >&2; return 2 ;;
  esac
}

# `stat` is not portable: BSD takes -f with %Su/%Sg/%Lp, GNU takes -c with
# %U/%G/%a. Both spellings are here rather than one plus a hope.
owner_mode() {  # <path> -> "<user>:<group> <octal-mode>"
  if stat -f '%Su:%Sg %Lp' "$1" 2>/dev/null; then return 0; fi
  stat -c '%U:%G %a' "$1"
}

# macOS ships `shasum`; Ubuntu ships `sha256sum` and not `shasum`.
sha256_of() {  # <file> -> first 16 hex chars
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -c1-16
  else
    sha256sum "$1" | cut -c1-16
  fi
}

# Everything the platform decides, in one place. Called once with the detected
# platform and again if --platform overrides it, so DEST and the tables are
# never stale and never half-set.
set_platform() {  # <platform>
  PLATFORM="$1"
  DEST="$(platform_install_root "$PLATFORM")" || return 2
  case "$PLATFORM" in
    darwin)
      LABEL=com.dhulabs.backup
      SERVICE_KIND=launchd
      SERVICE_FILE=/Library/LaunchDaemons/com.dhulabs.backup.plist
      SERVICE_SOURCE=com.dhulabs.backup.plist
      SERVICE_MODE=0644
      ;;
    linux)
      LABEL=dhu-backupd
      SERVICE_KIND=systemd
      SERVICE_FILE=/etc/systemd/system/dhu-backupd.service
      SERVICE_SOURCE=dhu-backupd.service
      SERVICE_MODE=0644
      ;;
    *)
      echo "!! unsupported platform: $PLATFORM (this installs on macOS and Linux)" >&2
      return 2
      ;;
  esac
  # PLIST is kept as an alias for the macOS name so the launchd sections below
  # read the way they always did.
  PLIST="$SERVICE_FILE"

# ── what gets installed, as DATA ──────────────────────────────────────────────
# One table of `<mode> <source-basename> <destination>`; a destination that does
# not start with `/` is relative to $DEST. The plan printer and the installer
# both read this table, so --dry-run cannot describe a different set of files
# from the one a real run writes. The table is data; the writes live only in the
# install branch far below.
#
# The commands are installed without the .py extension: an agent recovering its
# own work should type one word, and the daemon matches the helper. They are the
# same scripts. `dhu_backup_announce.py` keeps its extension so it stays
# importable by agent tooling (Property 4); `dhu_backup_core.py` likewise.
# `credential_patterns.py` is the credential predicate's pattern table, imported
# by `dhu_backup_core.py`. It is INSTALLED, root-owned and 0644, for the same
# reason the core is: the daemon must execute only root-owned bytes, and a
# pattern table an agent could rewrite is a pattern table that empties itself.
#
# The LAST row is the service definition, and it is the only row that differs
# between platforms: the LaunchDaemon plist on macOS, the systemd unit on Linux.
INSTALL_FILES="
0755 dhu-backupd.py          bin/dhu-backupd
0644 dhu_backup_core.py      bin/dhu_backup_core.py
0644 credential_patterns.py   bin/credential_patterns.py
0755 dhu-backup.py           bin/dhu-backup
0644 dhu_backup_announce.py  bin/dhu_backup_announce.py
0755 dhu-backup-mcp.py       bin/dhu-backup-mcp
0755 dhu-backup-hook.py      bin/dhu-backup-hook
$SERVICE_MODE $SERVICE_SOURCE $SERVICE_FILE
"

# `store/` is AGENT-READABLE (A1/R2); `vault/` is root-only (the credential
# class); `var/tmp/` is staging for atomic writes. Modes are explicit rather than
# inherited from a umask. The parent (/Library/DHU on macOS, /opt on Linux) is
# created 0755 root-owned; on Linux /opt already exists that way.
INSTALL_DIRS="
0755 $(dirname "$DEST")
0755 $DEST
0755 $DEST/bin
0755 $DEST/etc
0755 $DEST/var
0755 $DEST/store
0700 $DEST/vault
0755 $DEST/var/roots
0700 $DEST/var/tmp
"
}

# ── the four service operations, both platforms in one place ──────────────────
# The main flow calls only these. Each carries both branches so the difference
# between launchd and systemd is readable in one screen instead of scattered
# through the script.

service_loaded() {  # 0 if the service is currently loaded/known to the manager
  case "$SERVICE_KIND" in
    launchd) launchctl print "system/$LABEL" >/dev/null 2>&1 ;;
    systemd) systemctl list-unit-files "$LABEL.service" >/dev/null 2>&1 &&
             systemctl cat "$LABEL.service" >/dev/null 2>&1 ;;
  esac
}

service_stop() {  # stop it; non-zero if it is still there afterwards
  case "$SERVICE_KIND" in
    launchd)
      launchctl bootout "system/$LABEL" || return 1
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        launchctl print "system/$LABEL" >/dev/null 2>&1 || return 0
        sleep 1
      done
      launchctl print "system/$LABEL" >/dev/null 2>&1 && return 1
      return 0
      ;;
    systemd)
      systemctl stop "$LABEL.service" || return 1
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        systemctl is-active --quiet "$LABEL.service" || return 0
        sleep 1
      done
      systemctl is-active --quiet "$LABEL.service" && return 1
      return 0
      ;;
  esac
}

service_start_enabled() {  # load it AND make it survive a reboot
  case "$SERVICE_KIND" in
    launchd)
      launchctl bootstrap system "$SERVICE_FILE"
      launchctl enable "system/$LABEL" ||
        echo "!! launchctl enable failed (continuing; the job is bootstrapped)"
      ;;
    systemd)
      systemctl daemon-reload
      systemctl enable --now "$LABEL.service"
      ;;
  esac
}

service_status_hint() {  # what a human types when it did not start
  case "$SERVICE_KIND" in
    launchd) echo "launchctl print system/$LABEL" ;;
    systemd) echo "systemctl status $LABEL.service; journalctl -u $LABEL.service -n 50" ;;
  esac
}

# PURE: what a post-install heartbeat label means for this script's exit code.
# Three outcomes and no fourth, so every caller has to handle the middle one.
#
#   ok       the daemon is capturing comfortably   -> print the OK line, exit 0
#   warning  the daemon is capturing and CLOSE to a store-wide budget that will
#            stop it                               -> print the warning, exit 0
#   fail     anything else, INCLUDING a label this version of the script does
#            not know                              -> print it and exit 1
#
# `warning` exits 0 deliberately. A fresh install on a nearly-full volume works:
# refusing to finish it would leave a human deciding whether a failed installer
# had installed anything, and it teaches people to ignore the exit code. What it
# must NOT do is print the bare "OK — the daemon is running and protecting the
# roots above" line, which over a volume that will stop capture next week is
# exactly the silent success this whole section exists to prevent.
#
# An UNKNOWN label is `fail`, never `ok`: the same rule `health_verdict` follows
# in the Python. An old installer against a newer daemon says so.
install_state_verdict() {  # $1 = the "state" label from var/state.json
  case "${1:-}" in
    ok)      echo "ok" ;;
    warning) echo "warning" ;;
    *)       echo "fail" ;;
  esac
}

service_restart_hint() {  # what a human types after editing a file in etc/
  case "$SERVICE_KIND" in
    launchd) echo "sudo launchctl kickstart -k system/$LABEL" ;;
    systemd) echo "sudo systemctl restart $LABEL.service" ;;
  esac
}

# Is a systemd manager actually running? `--no-service` is gated on this being
# FALSE, which is what keeps the flag off a real host: /run/systemd/system exists
# on every booted systemd machine and exists in no container started without it.
systemd_is_running() {
  [ -d /run/systemd/system ]
}

# ── pure functions ────────────────────────────────────────────────────────────

usage() {
  cat >&2 <<USAGE
usage: sudo bash install.sh [--watch <id>=<abs-path>]... [--watchlist <file>]...
                            [--owner-uid <n>] [--dry-run]
                            [--platform darwin|linux] [--no-service]

  --watch <id>=<abs-path>  a directory to protect; repeatable.
                           <id> matches ^[a-z][a-z0-9-]*\$ (max 32).
                           <abs-path> is absolute; a single trailing '*' on the
                           LAST component is the only glob permitted.
  --watchlist <file>       roots from a file in watchlist format
                           ('<id> <abs-path>' per line, '#' comments).
                           See src/watchlist.conf.example.
  --owner-uid <n>          the uid whose files are protected. Defaults to
                           \$SUDO_UID, i.e. the human who typed sudo.
  --dry-run                print the plan and exit 0 without changing anything.
  --platform darwin|linux  print the plan for the OTHER platform. Accepted ONLY
                           together with --dry-run: it changes the install root,
                           the service manager and the service file, so a real
                           run under it would install a Linux unit on a Mac.
  --no-service             install the files and skip the service registration.
                           Linux ONLY, and only where no systemd manager is
                           running (no /run/systemd/system). It exists so the daemon can
                           be proven in a container; on a real host systemd IS
                           running, so the flag refuses.
  -h, --help               this message.

Install root: /Library/DHU/backup on macOS, /opt/dhu-backup on Linux.
This machine is $PLATFORM, so: $DEST

With no --watch/--watchlist an EXISTING $DEST/etc/watchlist.conf
is kept; if there is none, this refuses rather than installing a default.
USAGE
}

# ── the interpreter a root daemon may execute (review H2) ────────────────────
# Gathers the facts with lstat/realpath/stat and hands them to the PURE function
# `interpreter_verdict` in dhu_backup_core.py, which is the single place the
# rule is written down and the place the tests exercise it. The daemon runs the
# same function against its own interpreter at startup, so this is checked once
# at install time and again on every boot rather than only once.
#
# `/opt/homebrew/bin/node` is a user-owned symlink; a root daemon running it is
# a root shell for any agent. The Linux equivalents are a pyenv or conda python
# under a home directory, and a /usr/bin/python3 symlink an agent can repoint.
check_interpreter() {  # <interpreter-path> -> prints the reason, non-zero if refused
  /usr/bin/python3 -E -s -S -c '
import os, sys
sys.path.insert(0, sys.argv[1])
import dhu_backup_core
path = sys.argv[2]
try:
    link_uid = os.lstat(path).st_uid
    is_symlink = os.path.islink(path)
except OSError:
    link_uid, is_symlink = None, False
try:
    target = os.path.realpath(path)
    target_uid = os.stat(target).st_uid
except OSError:
    target, target_uid = None, None
verdict = dhu_backup_core.interpreter_verdict(path, is_symlink, link_uid, target, target_uid)
sys.stdout.write(verdict.reason + "\n")
sys.exit(0 if verdict.ok else 1)
' "$SRC" "$1"
}

# Validate one `<id> <path>` pair. `parse_watchlist` in src/dhu_backup_core.py is
# the AUTHORITY on the watchlist format — the daemon re-parses the installed file
# and refuses what it does not like. These checks are a deliberately STRICTER
# subset, so a root this installer accepts can never be one the daemon then
# drops: the daemon allows ^[A-Za-z0-9_-]{1,32}\$ for an id, and this requires
# lower-case because the id appears in store paths.
validate_watch_entry() {  # <id> <path> <line-for-messages>
  local id="$1" path="$2" line="$3"
  local id_re='^[a-z][a-z0-9-]*$'
  local nl='
'
  if [ -z "$id" ]; then
    echo "watchlist: empty root id in: $line" >&2; return 1
  fi
  if ! [[ $id =~ $id_re ]]; then
    echo "watchlist: bad root id '$id' (want ^[a-z][a-z0-9-]*\$) in: $line" >&2; return 1
  fi
  if [ "${#id}" -gt 32 ]; then
    echo "watchlist: root id '$id' is longer than 32 characters in: $line" >&2; return 1
  fi
  if [ -z "$path" ]; then
    echo "watchlist: empty path in: $line" >&2; return 1
  fi
  case "$path" in
    /*) ;;
    *) echo "watchlist: path is not absolute in: $line" >&2; return 1 ;;
  esac
  case "$path" in
    *"$nl"*) echo "watchlist: path contains a newline in: $line" >&2; return 1 ;;
  esac
  case "/$path/" in
    *"/../"*) echo "watchlist: path contains a '..' component in: $line" >&2; return 1 ;;
  esac
  local head="${path%/*}" last="${path##*/}" stars
  case "$head" in
    *"*"*) echo "watchlist: a glob is only allowed in the LAST component in: $line" >&2; return 1 ;;
  esac
  stars="${last//[^*]/}"
  if [ "${#stars}" -gt 1 ]; then
    echo "watchlist: at most one '*' is permitted in: $line" >&2; return 1
  fi
  if [ "${#stars}" -eq 1 ] && [ "${last%\*}" = "$last" ]; then
    echo "watchlist: the '*' must be TRAILING in: $line" >&2; return 1
  fi
  return 0
}

# Render `<id>=<path>` specs into the text of etc/watchlist.conf on stdout.
# Every spec is validated BEFORE anything is emitted, so a refusal can never
# leave a partially rendered watchlist behind.
render_watchlist() {  # <id>=<path>...
  local spec id path seen=" "
  if [ "$#" -eq 0 ]; then
    echo "watchlist: no entries to render" >&2; return 1
  fi
  for spec in "$@"; do
    case "$spec" in
      *=*) ;;
      *) echo "watchlist: expected <id>=<absolute-path> in: $spec" >&2; return 1 ;;
    esac
    id="${spec%%=*}"
    path="${spec#*=}"
    validate_watch_entry "$id" "$path" "$spec" || return 1
    case "$seen" in
      *" $id "*) echo "watchlist: duplicate root id '$id' in: $spec" >&2; return 1 ;;
    esac
    seen="$seen$id "
  done
  echo "# DHU Backup — the ONLY source of watched roots."
  echo "#"
  echo "# Written by install.sh from its --watch/--watchlist arguments. This file is"
  echo "# root-owned (0644) and is never derived from the database, an environment"
  echo "# variable, or anything an agent writes (review C5). Edit it by hand and"
  echo "# restart the daemon, or re-run install.sh with new --watch arguments."
  echo "#"
  echo "# Format:  <root-id>  <absolute-path>"
  echo "# A single trailing \`*\` on the LAST component is the only glob permitted."
  echo ""
  for spec in "$@"; do
    printf '%-12s %s\n' "${spec%%=*}" "${spec#*=}"
  done
}

# Read a file in watchlist format and emit one `<id>=<path>` per line. The file
# is normalised through the SAME validator as --watch, so a file with one bad
# line is refused whole rather than installed with that root silently missing.
# Comments in the file are NOT carried through: the installed file is rendered
# with a standard header.
watchlist_file_specs() {  # <file>
  local file="$1" raw line id path
  if [ ! -f "$file" ]; then
    echo "!! no such watchlist file: $file" >&2; return 1
  fi
  while IFS= read -r raw || [ -n "$raw" ]; do
    line=$(printf '%s' "$raw" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    [ -n "$line" ] || continue
    case "$line" in \#*) continue ;; esac
    id="${line%%[[:space:]]*}"
    path="${line#"$id"}"
    path=$(printf '%s' "$path" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [ -z "$path" ]; then
      echo "watchlist: malformed line (want '<id> <abs-path>') in: $line" >&2; return 1
    fi
    printf '%s=%s\n' "$id" "$path"
  done < "$file"
}

# The precedence rule for THIS run's watchlist, as a pure function so all four
# cases are testable without root.
#
#   flags given            -> `flags`    the command line is the source of truth
#   none, one installed    -> `preserve` today's behaviour; a re-run keeps it
#   none, none installed   -> `refuse`
#
# `refuse` rather than a default watchlist, on purpose: a default names
# directories that do not exist on this machine, so the daemon would come up
# healthy, protect nothing, and this script would print OK over an empty store.
watchlist_decision() {  # <flags-given:0|1> <existing:0|1>
  case "${1:-}${2:-}" in
    00|01|10|11) ;;
    *) echo "watchlist_decision: want two arguments, each 0 or 1" >&2; return 2 ;;
  esac
  if [ "$1" -eq 1 ]; then echo flags
  elif [ "$2" -eq 1 ]; then echo preserve
  else echo refuse
  fi
}

# How many roots a watchlist file actually names. A file of nothing but comments
# protects nothing, and must not reach the daemon as if it did.
watchlist_entry_count() {  # <file>
  local n
  [ -f "$1" ] || { echo 0; return 0; }
  n=$(grep -cE '^[[:space:]]*[^[:space:]#]' "$1" 2>/dev/null) || true
  echo "${n:-0}"
}

# The detected platform, applied before anything else so DEST, the tables and
# usage() are never unset. `--platform` re-applies it below, and only with
# --dry-run. `uname -s` is the one machine fact read above the guard line: it
# decides which strings this script talks about and changes nothing.
set_platform "$(platform_from_uname "$(uname -s)")" || {
  echo "!! $(uname -s) is not a platform this installs on (macOS and Linux)." >&2
  exit 2
}

# Tests source this script to exercise the pure functions above without running
# any part of the install:
#
#     DHU_BACKUP_SOURCE_ONLY=1 source src/install.sh
#
# EVERYTHING BELOW THIS LINE reads or changes the machine.
if [ -n "${DHU_BACKUP_SOURCE_ONLY:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

# ── arguments, parsed strictly ────────────────────────────────────────────────
DRY_RUN=0
FLAGS_GIVEN=0
NO_SERVICE=0
PLATFORM_FLAG=""
WATCH_SPECS=()

while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform)
      [ "$#" -ge 2 ] || { echo "!! --platform needs darwin or linux" >&2; usage; exit 2; }
      PLATFORM_FLAG="$2"; shift 2 ;;
    --platform=*)
      PLATFORM_FLAG="${1#--platform=}"; shift ;;
    --no-service)
      NO_SERVICE=1; shift ;;
    --watch)
      [ "$#" -ge 2 ] || { echo "!! --watch needs <id>=<abs-path>" >&2; usage; exit 2; }
      WATCH_SPECS+=("$2"); FLAGS_GIVEN=1; shift 2 ;;
    --watch=*)
      WATCH_SPECS+=("${1#--watch=}"); FLAGS_GIVEN=1; shift ;;
    --watchlist|--watchlist=*)
      case "$1" in
        --watchlist=*) WL_FILE="${1#--watchlist=}"; shift ;;
        *) [ "$#" -ge 2 ] || { echo "!! --watchlist needs a file" >&2; usage; exit 2; }
           WL_FILE="$2"; shift 2 ;;
      esac
      WL_SPECS=$(watchlist_file_specs "$WL_FILE") || exit 2
      while IFS= read -r s; do
        [ -n "$s" ] && WATCH_SPECS+=("$s")
      done <<< "$WL_SPECS"
      FLAGS_GIVEN=1 ;;
    --owner-uid)
      [ "$#" -ge 2 ] || { echo "!! --owner-uid needs a number" >&2; usage; exit 2; }
      OWNER_UID="$2"; shift 2 ;;
    --owner-uid=*)
      OWNER_UID="${1#--owner-uid=}"; shift ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "!! unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# --platform changes the install root, the service manager and the service file,
# so a REAL run under it would install a Linux unit on a Mac. It exists to let
# the other platform's plan be read and tested from here, and is therefore
# refused at parse time unless --dry-run is also given. This is an error, not a
# warning: a flag that is quietly ignored is a flag someone relies on.
if [ -n "$PLATFORM_FLAG" ]; then
  case "$PLATFORM_FLAG" in
    darwin|linux) ;;
    *) echo "!! --platform takes darwin or linux, got: $PLATFORM_FLAG" >&2; exit 2 ;;
  esac
  if [ "$DRY_RUN" -eq 0 ]; then
    echo "!! --platform is only valid together with --dry-run." >&2
    echo "   It changes the install root, the service manager and the service file," >&2
    echo "   so a real run under it would install the wrong platform's daemon." >&2
    echo "   Nothing has been changed." >&2
    exit 2
  fi
  set_platform "$PLATFORM_FLAG"
fi

# --no-service is for a container, where the files can be installed and the
# daemon started by hand but no service manager exists to register with. The
# gate is the ABSENCE of a running systemd, which is a fact about the machine
# rather than a promise from the caller: /run/systemd/system exists on every
# booted systemd host, so on a real host this refuses.
if [ "$NO_SERVICE" -eq 1 ]; then
  if [ "$PLATFORM" != linux ]; then
    echo "!! --no-service is Linux only (this platform is $PLATFORM)." >&2
    exit 2
  fi
  if systemd_is_running; then
    echo "!! --no-service is refused: a systemd manager IS running (/run/systemd/system)." >&2
    echo "   On a real host the daemon must be a registered system unit — an" >&2
    echo "   unregistered root process does not survive a reboot and is not what" >&2
    echo "   this installer's post-conditions describe. Nothing has been changed." >&2
    exit 2
  fi
fi

UID_RE='^[0-9]+$'
if [ -z "$OWNER_UID" ]; then
  echo "!! cannot tell whose files to protect: no \$SUDO_UID (not run via sudo?) and no --owner-uid." >&2
  echo "   Pass --owner-uid <n> (your uid is \`id -u\`). Nothing has been changed." >&2
  exit 2
fi
if ! [[ $OWNER_UID =~ $UID_RE ]]; then
  echo "!! --owner-uid must be a number, got: $OWNER_UID" >&2; usage; exit 2
fi
if [ "$OWNER_UID" -eq 0 ]; then
  # Admission is `st_uid == owner_uid`, so uid 0 would refuse every file the
  # human writes: a daemon that comes up healthy and protects nothing.
  echo "!! --owner-uid 0 would make the daemon refuse every file the owner writes" >&2
  echo "   (admission is st_uid == owner_uid), so it would protect nothing." >&2
  exit 2
fi

# ── the PLAN: reads only ──────────────────────────────────────────────────────
# Everything down to "the PLAN is executed" only reads. --dry-run prints the plan
# and exits BEFORE the root check, so it runs unprivileged and shares no code
# path with the writes.

while read -r _mode _src _dst; do
  [ -n "${_src:-}" ] || continue
  [ -f "$SRC/$_src" ] || { echo "missing source file: $SRC/$_src"; exit 1; }
done <<< "$INSTALL_FILES"

if [ "$FLAGS_GIVEN" -eq 1 ] && [ "${#WATCH_SPECS[@]}" -eq 0 ]; then
  echo "!! --watchlist named no roots (the file is empty or all comments)." >&2
  echo "   Nothing has been changed." >&2
  exit 2
fi

RENDERED=""
if [ "$FLAGS_GIVEN" -eq 1 ]; then
  RENDERED=$(render_watchlist "${WATCH_SPECS[@]}") || exit 2
fi

EXISTING=0
if [ -f "$DEST/etc/watchlist.conf" ]; then EXISTING=1; fi
DECISION=$(watchlist_decision "$FLAGS_GIVEN" "$EXISTING")

# Refuse BEFORE touching anything.
if [ "$DECISION" = refuse ]; then
  echo "!! no watch roots: pass --watch id=/abs/path (repeatable) or --watchlist FILE" >&2
  echo "   There is no default watchlist on purpose. A default would name" >&2
  echo "   directories that do not exist on this machine, the daemon would come up" >&2
  echo "   healthy protecting nothing, and this script would print OK over an empty" >&2
  echo "   store. See src/watchlist.conf.example. Nothing has been changed." >&2
  exit 2
fi
if [ "$DECISION" = preserve ] && [ "$(watchlist_entry_count "$DEST/etc/watchlist.conf")" -eq 0 ]; then
  echo "!! $DEST/etc/watchlist.conf names no roots, so it would protect nothing." >&2
  echo "   Pass --watch id=/abs/path (repeatable) or --watchlist FILE." >&2
  echo "   Nothing has been changed." >&2
  exit 2
fi

print_plan() {
  echo "== plan =="
  echo "  platform     : $PLATFORM ($SERVICE_KIND)$([ -n "$PLATFORM_FLAG" ] && echo "   [--platform override; this machine is $(platform_from_uname "$(uname -s)")]")"
  echo "  install root : $DEST"
  echo "  service file : $SERVICE_FILE"
  echo "  service name : $LABEL"
  echo "  owner uid    : $OWNER_UID"
  echo "  interpreter  : $INTERPRETER"
  echo "  source dir   : $SRC"
  echo
  case "$DECISION" in
    flags)
      echo "  watchlist    : WRITE $DEST/etc/watchlist.conf from the command line"
      if [ "$EXISTING" -eq 1 ]; then
        echo "                 (the existing one is kept as $DEST/etc/watchlist.conf.prev if it differs)"
      fi
      echo
      echo "--- $DEST/etc/watchlist.conf (rendered) ---"
      printf '%s\n' "$RENDERED"
      echo "--- end ---"
      ;;
    preserve)
      echo "  watchlist    : KEEP the existing $DEST/etc/watchlist.conf"
      echo "                 (pass --watch/--watchlist to replace it)"
      echo
      echo "--- $DEST/etc/watchlist.conf (existing, unchanged) ---"
      cat "$DEST/etc/watchlist.conf"
      echo "--- end ---"
      ;;
  esac
  echo "interpreter (review H2 — a root daemon executes only root-owned bytes):"
  if INTERP_REASON=$(check_interpreter "$INTERPRETER" 2>&1); then
    echo "  OK      $INTERP_REASON"
  else
    echo "  REFUSED $INTERP_REASON"
    echo "          A real run stops here rather than writing a service file that"
    echo "          would have root execute bytes an agent can replace."
  fi
  echo
  echo "directories (mode  path):"
  while read -r _mode _dir; do
    [ -n "${_dir:-}" ] || continue
    printf '  %s  %s\n' "$_mode" "$_dir"
  done <<< "$INSTALL_DIRS"
  echo
  echo "files (mode  source -> destination):"
  while read -r _mode _src _dst; do
    [ -n "${_src:-}" ] || continue
    case "$_dst" in /*) ;; *) _dst="$DEST/$_dst" ;; esac
    printf '  %s  %s -> %s\n' "$_mode" "$SRC/$_src" "$_dst"
  done <<< "$INSTALL_FILES"
  printf '  %s  %s -> %s\n' "0644" "$SRC/dhu-backupd.conf" \
    "$DEST/etc/dhu-backupd.conf (owner_uid = $OWNER_UID; an existing one is kept, repo copy left as .dist)"
  echo
  case "$SERVICE_KIND" in
    launchd)
      echo "then: launchctl bootout system/$LABEL (if loaded), bootstrap, enable, and wait"
      echo "      for a NEW heartbeat."
      ;;
    systemd)
      if [ "$NO_SERVICE" -eq 1 ]; then
        echo "then: NOTHING is registered (--no-service). Start it by hand:"
        echo "      /usr/bin/python3 -E -s -S $DEST/bin/dhu-backupd"
      else
        echo "then: systemctl stop $LABEL.service (if loaded), install $SERVICE_FILE,"
        echo "      systemctl daemon-reload, systemctl enable --now $LABEL.service, and wait"
        echo "      for a NEW heartbeat."
      fi
      ;;
  esac
}

if [ "$DRY_RUN" -eq 1 ]; then
  print_plan
  echo
  echo "DRY RUN — nothing was written. (It read the existing watchlist, if any, to show it.)"
  echo "Re-run without --dry-run, as root, to apply it."
  exit 0
fi

# ── the PLAN is executed ──────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { echo "must run as root: sudo bash $0 [--watch id=/abs/path ...]"; exit 1; }

print_plan
echo
echo "== installing DHU Backup (owner uid $OWNER_UID) =="

# Asserted BEFORE anything is written. A service file naming an interpreter an
# agent can replace is the whole threat model inverted, and it is the one
# post-condition that cannot be fixed afterwards by re-running this script.
if ! INTERP_REASON=$(check_interpreter "$INTERPRETER" 2>&1); then
  echo "!! refusing to install: $INTERP_REASON" >&2
  echo "   A root daemon must execute only root-owned bytes (review H2)." >&2
  echo "   Install the distro/system python3 and re-run. Nothing has been changed." >&2
  exit 1
fi
echo "-- interpreter: $INTERP_REASON"


# Stop an existing daemon before replacing the code it is executing. A bootout
# that FAILS is reported, not swallowed: the script would otherwise overwrite
# bin/dhu-backupd underneath a running daemon and then print sha256 lines under
# the heading "post-conditions", asserting facts about bytes on disk that a
# reader takes as facts about the running process.
if [ "$NO_SERVICE" -eq 0 ] && service_loaded; then
  echo "-- stopping the running daemon ($SERVICE_KIND: $LABEL)"
  if ! service_stop; then
    echo "!! could not stop $LABEL — refusing to replace code it is running"; exit 1
  fi
fi

while read -r _mode _dir; do
  [ -n "${_dir:-}" ] || continue
  install -d -o root -g 0 -m "$_mode" "$_dir"
done <<< "$INSTALL_DIRS"

while read -r _mode _src _dst; do
  [ -n "${_src:-}" ] || continue
  case "$_dst" in /*) ;; *) _dst="$DEST/$_dst" ;; esac
  install -o root -g 0 -m "$_mode" "$SRC/$_src" "$_dst"
done <<< "$INSTALL_FILES"

# The config carries the invoking user's uid, so a second machine or a second
# account does not silently mirror nothing. The substitution is VERIFIED: `sed`
# exits 0 when it matches nothing, and an unchanged owner_uid means the daemon
# refuses every file with `wrong-owner-uid` and protects nothing.
# Three substitutions, each VERIFIED. `sed` exits 0 when it matches nothing, so
# an unchanged owner_uid means the daemon refuses every file with
# `wrong-owner-uid` and protects nothing, and an unchanged `root`/`watchlist`
# means a Linux daemon reading /Library/DHU/backup — a second store at a path
# nothing else knows about, and a heartbeat the helper never finds.
sed -e "s/^owner_uid *= *.*/owner_uid  = $OWNER_UID/" \
    -e "s|^root *= *.*|root       = $DEST|" \
    -e "s|^watchlist *= *.*|watchlist  = $DEST/etc/watchlist.conf|" \
    "$SRC/dhu-backupd.conf" > "$DEST/etc/dhu-backupd.conf.new"
grep -q "^owner_uid  = $OWNER_UID\$" "$DEST/etc/dhu-backupd.conf.new" || {
  echo "!! owner_uid substitution did not take — refusing to install a config that would protect nothing"
  rm -f "$DEST/etc/dhu-backupd.conf.new"; exit 1; }
grep -q "^root       = $DEST\$" "$DEST/etc/dhu-backupd.conf.new" || {
  echo "!! install-root substitution did not take — refusing to install a config naming another root"
  rm -f "$DEST/etc/dhu-backupd.conf.new"; exit 1; }
grep -q "^watchlist  = $DEST/etc/watchlist.conf\$" "$DEST/etc/dhu-backupd.conf.new" || {
  echo "!! watchlist substitution did not take — refusing to install a config naming another watchlist"
  rm -f "$DEST/etc/dhu-backupd.conf.new"; exit 1; }

# An EXISTING etc/dhu-backupd.conf is never overwritten. Raising max_store_bytes
# is the documented way to recover from DEGRADED, and a later re-install silently
# reverted it. The repo copy is left alongside as .dist for the operator to diff.
if [ -f "$DEST/etc/dhu-backupd.conf" ]; then
  install -o root -g 0 -m 0644 "$DEST/etc/dhu-backupd.conf.new" "$DEST/etc/dhu-backupd.conf.dist"
  if cmp -s "$DEST/etc/dhu-backupd.conf" "$DEST/etc/dhu-backupd.conf.dist"; then
    rm -f "$DEST/etc/dhu-backupd.conf.dist"
  else
    echo "-- kept your dhu-backupd.conf; the repo version is at $DEST/etc/dhu-backupd.conf.dist (diff it)"
  fi
else
  install -o root -g 0 -m 0644 "$DEST/etc/dhu-backupd.conf.new" "$DEST/etc/dhu-backupd.conf"
fi
rm -f "$DEST/etc/dhu-backupd.conf.new"

# The watchlist, per the decision taken before anything was touched.
case "$DECISION" in
  flags)
    printf '%s\n' "$RENDERED" > "$DEST/etc/watchlist.conf.new"
    if [ -f "$DEST/etc/watchlist.conf" ] && ! cmp -s "$DEST/etc/watchlist.conf" "$DEST/etc/watchlist.conf.new"; then
      install -o root -g 0 -m 0644 "$DEST/etc/watchlist.conf" "$DEST/etc/watchlist.conf.prev"
      echo "-- your previous watchlist is kept at $DEST/etc/watchlist.conf.prev"
    fi
    install -o root -g 0 -m 0644 "$DEST/etc/watchlist.conf.new" "$DEST/etc/watchlist.conf"
    rm -f "$DEST/etc/watchlist.conf.new"
    echo "-- wrote $DEST/etc/watchlist.conf from the command line"
    ;;
  preserve)
    echo "-- kept $DEST/etc/watchlist.conf ($(watchlist_entry_count "$DEST/etc/watchlist.conf") root(s)); pass --watch to replace it"
    ;;
esac

# Left by an installer that shipped a default watchlist. Nothing produces it any
# more, and a stale .dist beside a live config invites a wrong diff.
if [ -f "$DEST/etc/watchlist.conf.dist" ]; then
  echo "-- note: $DEST/etc/watchlist.conf.dist is left over from an older installer."
  echo "   Nothing produces it now (the repo ships watchlist.conf.example and never installs it)."
  echo "   Delete it once you have taken anything you wanted from it."
fi

# Syntax-check before handing the code to launchd; a SyntaxError under KeepAlive
# is a silent restart loop.
/usr/bin/python3 -m py_compile "$DEST/bin/dhu-backupd" "$DEST/bin/dhu_backup_core.py" \
  "$DEST/bin/credential_patterns.py" \
  "$DEST/bin/dhu-backup" "$DEST/bin/dhu_backup_announce.py" "$DEST/bin/dhu-backup-mcp" \
  "$DEST/bin/dhu-backup-hook"
rm -rf "$DEST/bin/__pycache__"
# Validate the service definition before handing it to the manager. A malformed
# plist or unit under a restart policy is a silent restart loop.
case "$SERVICE_KIND" in
  launchd) plutil -lint "$SERVICE_FILE" >/dev/null ;;
  systemd)
    if command -v systemd-analyze >/dev/null 2>&1; then
      # `verify` warns about things that are not errors (a missing
      # Documentation target), so its exit status is reported and not fatal.
      systemd-analyze verify "$SERVICE_FILE" ||
        echo "!! systemd-analyze verify reported the above for $SERVICE_FILE (continuing)"
    else
      echo "-- systemd-analyze is not installed; $SERVICE_FILE was NOT syntax-checked"
    fi
    ;;
esac

# Remember the heartbeat we are about to replace. Checking only that the file
# EXISTS reads the previous daemon's heartbeat on every re-install, so a new
# dhu-backupd that dies at import would still print "OK — the daemon is running".
BEFORE_EPOCH=0
if [ -f "$DEST/var/state.json" ]; then
  BEFORE_EPOCH=$(sed -n 's/.*"last_scan_epoch": *\([0-9]*\).*/\1/p' "$DEST/var/state.json" | head -1)
  BEFORE_EPOCH=${BEFORE_EPOCH:-0}
fi

if [ "$NO_SERVICE" -eq 1 ]; then
  echo "-- --no-service: NOT registering a service (no systemd manager is running)."
  echo "   Start the daemon by hand: /usr/bin/python3 -E -s -S $DEST/bin/dhu-backupd"
else
  echo "-- loading the service ($SERVICE_KIND: $LABEL)"
  service_start_enabled
fi

echo
echo "== post-conditions, asserted not assumed =="
for f in "$DEST/bin/dhu-backupd" "$DEST/bin/dhu_backup_core.py" \
         "$DEST/bin/credential_patterns.py" "$DEST/bin/dhu-backup" \
         "$DEST/bin/dhu_backup_announce.py" "$DEST/bin/dhu-backup-mcp" \
         "$DEST/bin/dhu-backup-hook" \
         "$DEST/etc/dhu-backupd.conf" "$DEST/etc/watchlist.conf" "$PLIST"; do
  printf '%s  %s  %s\n' \
    "$(owner_mode "$f")" "$(sha256_of "$f")" "$f"
done
# Directories too. $DEST/bin's mode is what keeps the daemon's code root-only —
# Python prepends the script's own directory to sys.path — and it was the one
# the first version of this block skipped.
for d in "$(dirname "$DEST")" "$DEST" "$DEST/bin" "$DEST/etc" "$DEST/var" \
         "$DEST/store" "$DEST/vault" "$DEST/var/roots" "$DEST/var/tmp"; do
  printf '%s  %s\n' "$(owner_mode "$d")" "$d"
done
echo
echo "watch roots:"; sed -n 's/^\([a-z]\)/  \1/p' "$DEST/etc/watchlist.conf"

# Liveness, asserted rather than handed back to the human as a manual step.
if [ "$NO_SERVICE" -eq 1 ]; then
  # Said plainly rather than skipped quietly: with no service registered there
  # is no process to have written a heartbeat, so this script has proven the
  # FILES and nothing about a running daemon. Claiming otherwise here is exactly
  # the silent-OK this section exists to prevent.
  echo
  echo "-- --no-service: no daemon was started, so there is NO heartbeat to wait for."
  echo "   What is asserted above is the installed files and directories. Nothing"
  echo "   here says a daemon is running or that anything is being protected."
  echo "   Start it yourself: /usr/bin/python3 -E -s -S $DEST/bin/dhu-backupd"
  exit 0
fi
echo
echo "-- waiting for a NEW heartbeat (up to 60s; the previous one was at $BEFORE_EPOCH)"
NOW_EPOCH=0
for _ in $(seq 1 60); do
  if [ -f "$DEST/var/state.json" ]; then
    NOW_EPOCH=$(sed -n 's/.*"last_scan_epoch": *\([0-9]*\).*/\1/p' "$DEST/var/state.json" | head -1)
    NOW_EPOCH=${NOW_EPOCH:-0}
    [ "$NOW_EPOCH" -gt "$BEFORE_EPOCH" ] && break
  fi
  sleep 1
done
if [ "$NOW_EPOCH" -gt "$BEFORE_EPOCH" ]; then
  echo "STATE: $(tr -d '\n' < "$DEST/var/state.json" | cut -c1-400)"
  # "ok" or "warning" — both mean the daemon is running and capturing.
  #
  # `warning` is ACCEPTED here rather than treated as a non-OK state, and the
  # reason is that the alternative is worse: on a nearly-full volume a fresh
  # install would work perfectly and then exit 1, and the human would be left
  # deciding whether a failed installer had installed anything. Refusing to
  # finish an install that is working teaches people to ignore the exit code.
  #
  # What it must NOT do is print the bare OK line. "OK — the daemon is running
  # and protecting the roots above" over a volume that will stop capture next
  # week is precisely the silent-success this section exists to prevent, so the
  # warning is printed in its place, with what to do about it.
  STATE_LABEL=$(sed -n 's/.*"state": *"\([a-z-]*\)".*/\1/p' "$DEST/var/state.json" | head -1)
  STATE_VERDICT=$(install_state_verdict "$STATE_LABEL")
  if [ "$STATE_VERDICT" != "fail" ]; then
    # "protecting the roots above" is a claim about EVERY root listed, so the
    # heartbeat's own counts must agree with it: one refused root (a path that
    # does not exist, a component owned by someone else) is logged by the daemon
    # and counted here, and state stays "ok" because the others are fine.
    # Printing OK over that would be the silent fallback this script exists to
    # prevent.
    REFUSED=$(sed -n 's/.*"watch_roots_refused": *\([0-9]*\).*/\1/p' "$DEST/var/state.json" | head -1)
    ACTIVE=$(sed -n 's/.*"watch_roots": *\([0-9]*\).*/\1/p' "$DEST/var/state.json" | head -1)
    if [ "${REFUSED:-0}" -ne 0 ] || [ "${ACTIVE:-0}" -lt 1 ]; then
      echo "!! the daemon is running but REFUSED ${REFUSED:-?} watch root(s) and is protecting ${ACTIVE:-?}."
      echo "   Each refusal names its reason in $DEST/var/dhu-backupd.log (grep 'watch root')."
      exit 1
    fi
    if [ "$STATE_VERDICT" = "warning" ]; then
      WARN_DETAIL=$(sed -n 's/.*"warning_detail": *"\([^"]*\)".*/\1/p' "$DEST/var/state.json" | head -1)
      echo "!! INSTALLED AND CAPTURING — BUT CAPTURE WILL STOP."
      echo "   ${WARN_DETAIL:-a store-wide budget is close; see warning_reason in var/state.json}"
      echo "   ${ACTIVE} watch root(s) active, 0 refused. Everything above is installed and working."
      echo "   Capture stopping is by design and it NEVER self-heals: when a store-wide"
      echo "   budget binds, the daemon stops and keeps what it holds until a human acts."
      echo "   Act now, not then — free space on this volume, or raise the budget:"
      echo "     sudo vi $DEST/etc/dhu-backupd.conf     # min_free_bytes, max_store_bytes"
      echo "     $(service_restart_hint)"
      echo "   Watch it with: $DEST/bin/dhu-backup ls <filename>   (it banners the state)"
    else
      echo "OK — the daemon is running and protecting the roots above (${ACTIVE} active, 0 refused)."
    fi
  else
    echo "!! the daemon wrote the state '${STATE_LABEL:-<unreadable>}', which is neither"
    echo "   'ok' nor 'warning'. Check $DEST/var/dhu-backupd.log"
    exit 1
  fi
else
  echo "!! no NEW heartbeat after 60s — this daemon did not start."
  echo "   $(service_status_hint); tail $DEST/var/dhu-backupd.log"
  exit 1
fi
echo
echo "verify it as yourself (no sudo), against a file in one of the roots above:"
echo "  $DEST/bin/dhu-backup ls <filename>"
echo "  $DEST/bin/dhu-backup restore-dir <a watched directory> --asof 20m"
echo "  $DEST/bin/dhu-backup missing <an absolute path that is gone>"
echo
# NOT shipped, deliberately: an example file installed into etc/ becomes a live
# config the moment someone uncomments a line, and this one can only make the
# store hold LESS. The operator creates it or it does not exist.
echo "vault extra files beyond the built-in credential patterns (optional):"
echo "  sudo tee $DEST/etc/vault-extra.conf   # one basename glob per line, '#' comments"
echo "  e.g.  *.secret        (matched on the BASENAME only; no '/' and no '..')"
echo "  It can only ADD files to the root-only vault, never make one readable."
case "$SERVICE_KIND" in
  launchd) echo "  The daemon reads it at STARTUP: sudo launchctl kickstart -k system/$LABEL" ;;
  systemd) echo "  The daemon reads it at STARTUP: sudo systemctl restart $LABEL.service" ;;
esac
echo "  Watch var/state.json for vault_extra_globs and vault_extra_refused."
echo
# Also NOT shipped, and for a sharper version of the same reason: every line in
# this one REMOVES protection. An example file that goes live on an uncomment
# would be a directory silently stopping being protected.
echo "skip a large directory inside a watch root (optional):"
echo "  sudo tee $DEST/etc/exclude.conf   # one DIRECTORY-NAME glob per line, '#' comments"
echo "  e.g.  fixtures       (matched on the directory NAME only; no '/' and no '..')"
echo "  The opposite of vault-extra.conf: that file can only ADD protection, this"
echo "  one can only REMOVE it. It is acceptable only because it is root-owned 0644"
echo "  beside watchlist.conf, which already decides what is protected at all."
echo "  The daemon reads it at STARTUP: $(service_restart_hint)"
echo "  Watch var/state.json for exclude_globs, exclude_refused, and"
echo "  refusals_by_reason['walk-excluded-dir-operator'] — the count that proves it fired."
echo
echo "check on it later:"
case "$SERVICE_KIND" in
  launchd)
    echo "  sudo launchctl print system/$LABEL"
    echo "  sudo launchctl kickstart -k system/$LABEL     # restart after a config edit"
    ;;
  systemd)
    echo "  systemctl status $LABEL.service"
    echo "  sudo systemctl restart $LABEL.service          # restart after a config edit"
    echo "  journalctl -u $LABEL.service -n 50"
    echo "  As a non-root user, 'systemctl stop $LABEL' is refused by polkit and"
    echo "  'kill <pid>' gets EPERM. That pair is what makes the daemon untouchable."
    ;;
esac
echo
echo "change the watched directories later:"
echo "  sudo bash $0 --watch id=/abs/path --watch other=/abs/path2"
echo "  (a re-run with NO --watch keeps $DEST/etc/watchlist.conf as it is)"
echo
echo "remove it:"
echo "  sudo bash $SRC/uninstall.sh --dry-run"
echo
echo "register the MCP server with Claude Code:"
echo "  claude mcp add dhu-backup -- /usr/bin/python3 -E -s -S $DEST/bin/dhu-backup-mcp"
echo
# The hook is the only piece that cannot be turned on by this script: it lives in
# the USER's settings file, which root must not rewrite. Printed so the human
# ratifies it deliberately, once, per machine.
echo "make a failed read announce its own recovery (Property 4) — add to"
echo "~/.claude/settings.json (user-wide) or .claude/settings.json (one project):"
cat <<HOOKJSON
  {"hooks": {"PostToolUseFailure": [{"matcher": "Read|Edit|Bash",
    "hooks": [{"type": "command",
               "command": "/usr/bin/python3 -E -s -S $DEST/bin/dhu-backup-hook"}]}]}}
HOOKJSON
