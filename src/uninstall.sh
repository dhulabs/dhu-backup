#!/bin/bash
# DHU Backup — uninstaller. Run by a human:
#
#     sudo bash src/uninstall.sh --dry-run     # see the plan, change nothing
#     sudo bash src/uninstall.sh               # stop and remove the daemon
#     sudo bash src/uninstall.sh --purge --yes # ... and delete the captured history
#     bash src/uninstall.sh --dry-run --platform linux   # the OTHER platform's plan
#
# What it removes by default: the service (stopped first, then its definition
# file), and the installed code and config (bin/, etc/).
#
# TWO platforms, mirroring install.sh: /Library/DHU/backup with a LaunchDaemon on
# macOS, /opt/dhu-backup with a systemd system unit on Linux. `--platform` prints
# the other one's plan and is accepted ONLY with --dry-run.
#
# What it KEEPS by default: store/, vault/ and var/. Those are the captured
# history — the whole point of the product — and an uninstaller that deletes them
# because the operator wanted to stop the daemon has destroyed the thing it was
# protecting. --purge deletes them, and only together with --yes: the deletion is
# not recoverable and must be typed, not defaulted into.
#
# It never touches ~/.claude/settings.json or ~/.claude.json. Those are the
# USER's files; root rewriting them is exactly what install.sh refuses to do. The
# two de-registration steps are PRINTED for the human to run.
set -euo pipefail

# ── platform ──────────────────────────────────────────────────────────────────
# The same two tables install.sh uses, for the same reason: one script, both
# platforms, no second copy to drift.
platform_from_uname() {  # <uname -s>
  case "$1" in
    Darwin) echo darwin ;;
    Linux)  echo linux ;;
    *)      echo unsupported ;;
  esac
}

platform_install_root() {  # <platform>
  case "$1" in
    darwin) echo /Library/DHU/backup ;;
    linux)  echo /opt/dhu-backup ;;
    *)      echo "unsupported platform: $1" >&2; return 2 ;;
  esac
}

set_platform() {  # <platform>
  PLATFORM="$1"
  DEST="$(platform_install_root "$PLATFORM")" || return 2
  case "$PLATFORM" in
    darwin)
      LABEL=com.dhulabs.backup
      SERVICE_KIND=launchd
      SERVICE_FILE=/Library/LaunchDaemons/com.dhulabs.backup.plist
      ;;
    linux)
      LABEL=dhu-backupd
      SERVICE_KIND=systemd
      SERVICE_FILE=/etc/systemd/system/dhu-backupd.service
      ;;
    *)
      echo "!! unsupported platform: $PLATFORM (this uninstalls on macOS and Linux)" >&2
      return 2
      ;;
  esac
  PLIST="$SERVICE_FILE"
}

# The two service operations an uninstall needs. Both branches in one place, so
# the flow below is platform-free.
service_loaded() {
  case "$SERVICE_KIND" in
    launchd) launchctl print "system/$LABEL" >/dev/null 2>&1 ;;
    systemd) systemctl list-unit-files "$LABEL.service" >/dev/null 2>&1 &&
             systemctl cat "$LABEL.service" >/dev/null 2>&1 ;;
  esac
}

service_stop() {  # non-zero if it is still loaded afterwards
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
      # `disable` as well as `stop`: a unit that is merely stopped comes back at
      # the next boot, and this script's post-condition would be true today and
      # false tomorrow. `--now` covers both.
      systemctl disable --now "$LABEL.service" || return 1
      for _ in 1 2 3 4 5 6 7 8 9 10; do
        systemctl is-active --quiet "$LABEL.service" || return 0
        sleep 1
      done
      systemctl is-active --quiet "$LABEL.service" && return 1
      return 0
      ;;
  esac
}

# After the unit file is gone, systemd still holds it in memory until told.
service_reload_after_removal() {
  case "$SERVICE_KIND" in
    launchd) : ;;
    systemd) systemctl daemon-reload || true ;;
  esac
}

set_platform "$(platform_from_uname "$(uname -s)")" || {
  echo "!! $(uname -s) is not a platform this uninstalls on (macOS and Linux)." >&2
  exit 2
}

usage() {
  cat >&2 <<USAGE
usage: sudo bash uninstall.sh [--dry-run] [--purge] [--yes]
                              [--platform darwin|linux]

  --dry-run   print the plan and exit 0 without changing anything.
              Runnable without sudo.
  --purge     ALSO delete $DEST/store, vault and var —
              the captured history. Requires --yes.
  --yes       confirm --purge. Without it, --purge prints what it would
              delete and exits 2.
  --platform darwin|linux
              print the plan for the OTHER platform. --dry-run ONLY: it
              changes which install root and which service this would remove.
  -h, --help  this message.

Install root: /Library/DHU/backup on macOS, /opt/dhu-backup on Linux.
This machine is $PLATFORM, so: $DEST

Without --purge, store/, vault/ and var/ are left in place and their sizes are
printed. Removing them later is one command: sudo rm -rf $DEST
USAGE
}

# Size of a directory, or a reason it could not be measured. vault/ is 0700, so
# an unprivileged --dry-run cannot size it; that is reported, never guessed at
# and never silently printed as 0.
dir_size() {  # <dir>
  local d="$1" out
  [ -d "$d" ] || { echo "(absent)"; return 0; }
  out=$(du -sh "$d" 2>/dev/null | tail -1 | awk '{print $1}') || true
  if [ -n "${out:-}" ]; then echo "$out"; else echo "(not readable without sudo)"; fi
}

# ── the PLAN, as functions that take the install root as an ARGUMENT ──────────
# Everything the plan prints is derived from (a) the platform identity set by
# set_platform above and (b) five presence facts about an install root plus
# whether the service is loaded. The root and the facts are ARGUMENTS, never
# read from ambient state, so these same printers can be driven against a
# fabricated root — which is how the tests assert the plan text on ANY machine,
# including one that has never had an install.
#
# Before this split the uninstall tests ran the real script and asserted on
# whatever happened to be in /Library/DHU/backup on the author's Mac. That is a
# claim and its evidence not sharing a population: four of them passed here and
# failed on a clean Linux host, where the script correctly takes its "nothing to
# uninstall" early exit, for a reason that had nothing to do with the behaviour
# under test. There is deliberately NO --root flag: this script runs under sudo
# and DEST being a fixed per-platform constant is a property worth keeping.

uninstall_state() {  # <root> -> "bin=0|1 etc=0|1 store=0|1 vault=0|1 var=0|1"
  local root="$1" sub out=""
  for sub in bin etc store vault var; do
    if [ -d "$root/$sub" ]; then out="$out$sub=1 "; else out="$out$sub=0 "; fi
  done
  echo "${out% }"
}

uninstall_state_has() {  # <state> <name> -> 0 if that directory is present
  case " $1 " in *" $2=1 "*) return 0 ;; esac
  return 1
}

# True when there is nothing at all to uninstall: no service, no service file,
# no install root. This is what a clean machine gets, and it is an exit-0
# report, not a failure.
uninstall_nothing_to_do() {  # <root> <loaded 0|1> <service_file_present 0|1>
  [ "$2" -eq 0 ] && [ "$3" -eq 0 ] && [ ! -d "$1" ]
}

print_nothing_to_uninstall() {  # <root>
  echo "nothing to uninstall on $PLATFORM ($SERVICE_KIND):"
  echo "  service name : $LABEL   (not loaded)"
  echo "  service file : $SERVICE_FILE   (absent)"
  echo "  install root : $1   (absent)"
}

# The sizes are passed in rather than measured here: the main flow measures them
# ONCE, before anything is removed, so the plan and the post-conditions quote the
# same numbers instead of two different readings of a live store.
print_kept_data_for() {  # <root> <store_size> <vault_size> <var_size>
  echo "  $1/store  $2   (agent-readable captured versions)"
  echo "  $1/vault  $3   (root-only credential-class versions)"
  echo "  $1/var    $4   (index, heartbeat, log, root manifests)"
}

# The watch roots this uninstall is about to delete, as ready-to-paste flags.
#
# `etc/watchlist.conf` is the ONLY record of which directories were protected,
# it lives in `etc/`, and `etc/` is removed by every uninstall — while
# `store/` is KEPT by default. Without this the operator is left holding the
# captured history of directories they can no longer name, and a re-install
# refuses with "no watch roots" (correctly, since there is no default
# watchlist) for a reason that looks like a bug. Printing the flags costs
# nothing and is the difference between a reversible and an irreversible step.
#
# Read-only, and readable unprivileged: the file is 0644 by design. An absent
# or unreadable one is REPORTED, never passed over in silence.
print_watch_roots_for() {  # <root>
  local root="$1" file="$1/etc/watchlist.conf" flags=""
  echo "the watch roots you are about to lose (etc/ is removed; store/ is not):"
  if [ ! -f "$file" ]; then
    echo "  none recorded — $file is absent."
    return 0
  fi
  if [ ! -r "$file" ]; then
    echo "  $file is present but NOT READABLE by $(id -un), so the roots cannot be listed here."
    echo "  Read it with sudo before continuing if you want to keep them."
    return 0
  fi
  while read -r id path; do
    case "${id:-}" in ""|\#*) continue ;; esac
    [ -n "${path:-}" ] || continue
    # SINGLE-QUOTED, always. A watch root may end in a trailing `*` (the one
    # glob the watchlist permits) and may contain spaces; unquoted, the shell
    # that pastes this line would expand or split it, and the "ready to paste"
    # command would silently protect something other than what was protected.
    flags="$flags --watch '$id=$path'"
  done < "$file"
  if [ -z "$flags" ]; then
    echo "  none recorded — $file names no roots."
    return 0
  fi
  echo "  re-create them with:"
  echo "    sudo bash install.sh$flags"
}

print_plan_for() {  # <root> <state> <loaded> <service_file_present> <purge> <store_size> <vault_size> <var_size>
  local root="$1" state="$2" loaded="$3" service_file_present="$4" purge="$5"
  local store_size="$6" vault_size="$7" var_size="$8"
  echo "== plan =="
  echo "  platform     : $PLATFORM ($SERVICE_KIND)$([ -n "${PLATFORM_FLAG:-}" ] && echo "   [--platform override; this machine is $(platform_from_uname "$(uname -s)")]")"
  echo "  install root : $root"
  echo "  service name : $LABEL   (currently $([ "$loaded" -eq 1 ] && echo loaded || echo "not loaded"))"
  echo "  service file : $SERVICE_FILE   ($([ "$service_file_present" -eq 1 ] && echo present || echo absent))"
  echo
  echo "would REMOVE:"
  if [ "$loaded" -eq 1 ]; then
    case "$SERVICE_KIND" in
      launchd) echo "  launchctl bootout system/$LABEL" ;;
      systemd) echo "  systemctl disable --now $LABEL.service" ;;
    esac
  fi
  [ "$service_file_present" -eq 1 ] && echo "  $SERVICE_FILE"
  uninstall_state_has "$state" bin && echo "  $root/bin   (the daemon, the helper, the MCP server, the hook)"
  uninstall_state_has "$state" etc && echo "  $root/etc   (dhu-backupd.conf, watchlist.conf)"
  echo
  if uninstall_state_has "$state" etc; then
    print_watch_roots_for "$root"
    echo
  fi
  if [ "$purge" -eq 1 ]; then
    echo "would DELETE, because --purge (NOT recoverable):"
    print_kept_data_for "$root" "$store_size" "$vault_size" "$var_size"
  else
    echo "would KEEP (the captured history; --purge deletes it):"
    print_kept_data_for "$root" "$store_size" "$vault_size" "$var_size"
    echo
    echo "  remove them later with:  sudo rm -rf $root"
  fi
}

# The refusal --purge earns without --yes. A function for the same reason the
# plan is one: it is reachable in a test on a machine with no install.
print_purge_refusal() {  # <root> <store_size> <vault_size> <var_size>
  echo "!! --purge deletes the captured history and is NOT recoverable:"
  print_kept_data_for "$1" "$2" "$3" "$4"
  echo
  echo "   Re-run with --purge --yes if that is what you want."
  echo "   Nothing has been changed."
}

print_deregistration_for() {  # <root>
  echo
  echo "two steps this script deliberately does NOT take — they live in YOUR files,"
  echo "and root must not rewrite them:"
  echo "  1. remove the PostToolUseFailure hook entry naming $1/bin/dhu-backup-hook"
  echo "     from ~/.claude/settings.json (and any project .claude/settings.json)"
  echo "  2. claude mcp remove -s user dhu-backup"
}

# Tests source this script to exercise the helpers above without running any part
# of the uninstall:  DHU_BACKUP_SOURCE_ONLY=1 source src/uninstall.sh
# EVERYTHING BELOW THIS LINE reads or changes the machine.
if [ -n "${DHU_BACKUP_SOURCE_ONLY:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

# ── arguments, parsed strictly ────────────────────────────────────────────────
DRY_RUN=0
PURGE=0
YES=0
PLATFORM_FLAG=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --purge)   PURGE=1; shift ;;
    --yes)     YES=1; shift ;;
    --platform)
      [ "$#" -ge 2 ] || { echo "!! --platform needs darwin or linux" >&2; usage; exit 2; }
      PLATFORM_FLAG="$2"; shift 2 ;;
    --platform=*) PLATFORM_FLAG="${1#--platform=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "!! unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# Same rule as install.sh: --platform changes what would be REMOVED, so a real
# run under it would stop and delete the wrong platform's install. Refused at
# parse time rather than ignored.
if [ -n "$PLATFORM_FLAG" ]; then
  case "$PLATFORM_FLAG" in
    darwin|linux) ;;
    *) echo "!! --platform takes darwin or linux, got: $PLATFORM_FLAG" >&2; exit 2 ;;
  esac
  if [ "$DRY_RUN" -eq 0 ]; then
    echo "!! --platform is only valid together with --dry-run." >&2
    echo "   It changes which install root and which service this would remove." >&2
    echo "   Nothing has been changed." >&2
    exit 2
  fi
  set_platform "$PLATFORM_FLAG"
fi

# ── the PLAN: reads only ──────────────────────────────────────────────────────
# The facts are gathered HERE, from the real machine, and then handed to the
# printers above as arguments. This is the only place that reads $DEST.
LOADED=0
if service_loaded; then LOADED=1; fi
PLIST_PRESENT=0; [ -f "$PLIST" ] && PLIST_PRESENT=1
STATE="$(uninstall_state "$DEST")"
BIN_PRESENT=0;   uninstall_state_has "$STATE" bin   && BIN_PRESENT=1
ETC_PRESENT=0;   uninstall_state_has "$STATE" etc   && ETC_PRESENT=1
STORE_PRESENT=0; uninstall_state_has "$STATE" store && STORE_PRESENT=1
VAULT_PRESENT=0; uninstall_state_has "$STATE" vault && VAULT_PRESENT=1
VAR_PRESENT=0;   uninstall_state_has "$STATE" var   && VAR_PRESENT=1

STORE_SIZE=$(dir_size "$DEST/store")
VAULT_SIZE=$(dir_size "$DEST/vault")
VAR_SIZE=$(dir_size "$DEST/var")

# Thin wrappers so the flow below reads the same as it always did.
print_kept_data() {
  print_kept_data_for "$DEST" "$STORE_SIZE" "$VAULT_SIZE" "$VAR_SIZE"
}

print_plan() {
  print_plan_for "$DEST" "$STATE" "$LOADED" "$PLIST_PRESENT" "$PURGE" \
                 "$STORE_SIZE" "$VAULT_SIZE" "$VAR_SIZE"
}

print_deregistration() {
  print_deregistration_for "$DEST"
}

if uninstall_nothing_to_do "$DEST" "$LOADED" "$PLIST_PRESENT"; then
  print_nothing_to_uninstall "$DEST"
  print_deregistration
  exit 0
fi

# --purge is confirmed BEFORE the root check, so this refusal is reachable
# without sudo and a human can see exactly what the flag would destroy.
if [ "$PURGE" -eq 1 ] && [ "$YES" -eq 0 ]; then
  print_purge_refusal "$DEST" "$STORE_SIZE" "$VAULT_SIZE" "$VAR_SIZE" >&2
  exit 2
fi

if [ "$DRY_RUN" -eq 1 ]; then
  print_plan
  print_deregistration
  echo
  echo "DRY RUN — nothing was changed. Re-run without --dry-run, as root, to apply it."
  exit 0
fi

# ── the PLAN is executed ──────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { echo "must run as root: sudo bash $0 [--dry-run] [--purge --yes]"; exit 1; }

print_plan
echo
echo "== uninstalling DHU Backup =="

# A bootout that FAILS is fatal, the same policy install.sh uses. Deleting the
# plist and the code underneath a still-running root daemon would leave a process
# with open descriptors into a tree this script then asserts is gone.
if [ "$LOADED" -eq 1 ]; then
  echo "-- stopping $LABEL ($SERVICE_KIND)"
  if ! service_stop; then
    echo "!! could not stop $LABEL — refusing to remove code it is running"; exit 1
  fi
  echo "-- $LABEL is stopped"
fi

if [ "$PLIST_PRESENT" -eq 1 ]; then
  echo "-- removing $SERVICE_FILE"
  rm -f "$SERVICE_FILE"
  service_reload_after_removal
fi

if [ "$BIN_PRESENT" -eq 1 ]; then
  echo "-- removing $DEST/bin"
  rm -rf "$DEST/bin"
fi
if [ "$ETC_PRESENT" -eq 1 ]; then
  echo "-- removing $DEST/etc"
  rm -rf "$DEST/etc"
fi

if [ "$PURGE" -eq 1 ]; then
  echo "-- purging the captured history (--purge --yes)"
  rm -rf "$DEST/store" "$DEST/vault" "$DEST/var"
  if rmdir "$DEST" 2>/dev/null; then
    echo "-- removed the empty $DEST"
    # macOS only: /Library/DHU is this product's own directory and is removable
    # when empty. /opt on Linux belongs to the distribution and is never touched.
    if [ "$PLATFORM" = darwin ]; then
      rmdir /Library/DHU 2>/dev/null && echo "-- removed the empty /Library/DHU" || true
    fi
  else
    echo "-- left $DEST in place (not empty)"
  fi
fi

echo
echo "== post-conditions, asserted not assumed =="
if service_loaded; then
  echo "!! $LABEL is STILL loaded"; exit 1
fi
echo "  $LABEL   not loaded"
[ ! -f "$SERVICE_FILE" ] || { echo "!! $SERVICE_FILE still exists"; exit 1; }
echo "  $SERVICE_FILE   gone"
[ ! -d "$DEST/bin" ] || { echo "!! $DEST/bin still exists"; exit 1; }
echo "  $DEST/bin   gone"
[ ! -d "$DEST/etc" ] || { echo "!! $DEST/etc still exists"; exit 1; }
echo "  $DEST/etc   gone"

if [ "$PURGE" -eq 1 ]; then
  for d in "$DEST/store" "$DEST/vault" "$DEST/var"; do
    [ ! -d "$d" ] || { echo "!! $d still exists"; exit 1; }
    echo "  $d   gone"
  done
else
  # Presence is asserted only for what was there BEFORE: a machine that never
  # captured anything has no store to keep, and claiming to have kept one would
  # be a false post-condition.
  [ "$STORE_PRESENT" -eq 0 ] || [ -d "$DEST/store" ] || { echo "!! $DEST/store was removed"; exit 1; }
  [ "$VAULT_PRESENT" -eq 0 ] || [ -d "$DEST/vault" ] || { echo "!! $DEST/vault was removed"; exit 1; }
  [ "$VAR_PRESENT" -eq 0 ]   || [ -d "$DEST/var" ]   || { echo "!! $DEST/var was removed"; exit 1; }
  echo
  echo "  KEPT (the captured history):"
  print_kept_data
  echo "  remove them with:  sudo rm -rf $DEST"
fi

print_deregistration
echo
echo "OK — the daemon is stopped and removed. Nothing is protecting anything now."
