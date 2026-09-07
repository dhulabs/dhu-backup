#!/bin/bash
# DHU Backup — the Linux port, proven by execution inside a container.
#
# DEVELOPER TOOLING. It is not installed, it is not on the daemon's trust path,
# and nothing in the product reads it.
#
# Run it from the Mac (or any Docker host):
#
#     docker run --rm -v "$PWD:/src:ro" ubuntu:24.04 bash /src/src/tools/linux-smoke.sh
#
# The repo is mounted READ-ONLY and copied to /work inside the container, so
# nothing this script does can reach the host's checkout. Nothing else from the
# host is mounted.
#
# WHAT THIS CANNOT PROVE, said here rather than left to be inferred: a plain
# container has no systemd, so the unit file, `systemctl enable --now`, polkit's
# refusal of a non-root `systemctl stop`, and every `ProtectSystem` /
# `ProtectHome` / `PrivateTmp` key are NOT exercised here. Those need a real
# Ubuntu host or VM. What IS proven here is the daemon itself on Linux: the
# inotify trigger, its measured latencies, the admission guards, the split
# store/vault, the kernel refusing an unprivileged agent every write to the
# store, and the unprivileged recovery CLI.
#
# Exits non-zero if any expectation fails; every check prints PASS or FAIL.
set -uo pipefail

SRCDIR=/src
WORK=/work
DEST=/opt/dhu-backup
AGENT=agent
AGENT_UID=1000
PROJ=/home/$AGENT/proj
FAILURES=0
DAEMON_PID=""

say()  { printf '\n== %s ==\n' "$*"; }
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }

check() {  # <description> <command...> — passes when the command succeeds
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}

refute() {  # <description> <command...> — passes when the command FAILS
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$what (it SUCCEEDED and must not)"; else pass "$what"; fi
}

as_agent() { su "$AGENT" -s /bin/bash -c "$1"; }

# Seconds, to two decimals, since a recorded `date +%s.%N`.
since() { awk -v s="$1" 'BEGIN { "date +%s.%N" | getline n; printf "%.2f", n - s }'; }

# Wait until `test -e <path>` is true, up to <seconds>. Prints the elapsed time
# and returns non-zero on timeout. This is the MEASUREMENT: nothing here claims
# a latency it did not wait for.
wait_for_path() {  # <glob-command> <seconds>
  local probe="$1" limit="$2" start elapsed
  start=$(date +%s.%N)
  while :; do
    if eval "$probe" >/dev/null 2>&1; then
      elapsed=$(since "$start"); echo "$elapsed"; return 0
    fi
    elapsed=$(awk -v s="$start" 'BEGIN { "date +%s.%N" | getline n; print (n - s) }')
    if awk -v e="$elapsed" -v l="$limit" 'BEGIN { exit !(e > l) }'; then
      echo "$(since "$start")"; return 1
    fi
    sleep 0.1
  done
}

# ── the container ────────────────────────────────────────────────────────────
say "container"
echo "kernel : $(uname -srm)"
echo "distro : $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "systemd: $([ -d /run/systemd/system ] && echo running || echo "NOT running (no unit can be tested here)")"

say "installing python3"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq python3 >/dev/null 2>&1
if ! command -v /usr/bin/python3 >/dev/null 2>&1; then
  echo "FATAL: /usr/bin/python3 is not installed; nothing below can run."
  exit 1
fi
echo "python : $(/usr/bin/python3 -V 2>&1) at /usr/bin/python3"
echo "link   : $(stat -c '%U:%G %a' /usr/bin/python3) /usr/bin/python3 -> $(readlink -f /usr/bin/python3)"
echo "target : $(stat -c '%U:%G %a' "$(readlink -f /usr/bin/python3)")"
echo "         (a root daemon executes only root-owned bytes — review H2)"

say "the unprivileged user the agent lane stands in for"
# Ubuntu 24.04 ships a stock `ubuntu` account AT uid 1000, so uid 1000 is taken
# before this script starts. It is removed rather than worked around: the point
# of the run is a uid-1000 unprivileged account standing in for the agent lane,
# and a different uid would not be the same test. This is a throwaway container.
if id -u "$AGENT" >/dev/null 2>&1; then
  echo "  $AGENT already exists"
else
  EXISTING=$(getent passwd "$AGENT_UID" | cut -d: -f1 || true)
  if [ -n "${EXISTING:-}" ]; then
    echo "  uid $AGENT_UID is held by '$EXISTING' (Ubuntu's stock account); removing it"
    userdel -r "$EXISTING" 2>/dev/null || userdel "$EXISTING"
  fi
  useradd -m -u "$AGENT_UID" -s /bin/bash "$AGENT" || {
    echo "FATAL: could not create $AGENT"; exit 1; }
fi
mkdir -p "$PROJ"
chown -R "$AGENT:$AGENT" "/home/$AGENT"
echo "user   : $AGENT (uid $(id -u "$AGENT")), project $PROJ"

# The repo is mounted read-only; work from a copy so nothing can reach the host.
rm -rf "$WORK"; mkdir -p "$WORK"
cp -a "$SRCDIR"/. "$WORK"/
echo "repo   : copied $SRCDIR (read-only mount) -> $WORK"

# ── the installer's plan ─────────────────────────────────────────────────────
say "install.sh --dry-run --platform linux (unprivileged plan)"
if su "$AGENT" -s /bin/bash -c "bash $WORK/src/install.sh --dry-run --platform linux \
      --owner-uid $AGENT_UID --watch repo=$PROJ" > /tmp/plan.txt 2>&1; then
  sed -n '1,10p' /tmp/plan.txt
  echo "  ..."
  grep -E 'systemd|dhu-backupd.service|interpreter' /tmp/plan.txt | head -8
  pass "the plan printed and exited 0, run as $AGENT with no sudo"
else
  cat /tmp/plan.txt
  fail "install.sh --dry-run --platform linux"
fi
check "the plan names /opt/dhu-backup"                 grep -q "/opt/dhu-backup" /tmp/plan.txt
check "the plan names the systemd unit path"           grep -q "/etc/systemd/system/dhu-backupd.service" /tmp/plan.txt
check "the plan names systemctl"                       grep -q "systemctl" /tmp/plan.txt

say "--platform without --dry-run is refused at parse time"
if bash "$WORK/src/install.sh" --platform linux --watch "repo=$PROJ" --owner-uid "$AGENT_UID" \
     >/tmp/refuse.txt 2>&1; then
  fail "--platform without --dry-run exited 0"
else
  rc=$?
  [ "$rc" -eq 2 ] && pass "--platform without --dry-run exits 2" \
                  || fail "--platform without --dry-run exited $rc, want 2"
fi

say "--no-service is gated on systemd being ABSENT"
if [ -d /run/systemd/system ]; then
  echo "  systemd IS running here, so --no-service must refuse:"
  refute "--no-service refused on a systemd host" \
    bash "$WORK/src/install.sh" --no-service --watch "repo=$PROJ" --owner-uid "$AGENT_UID"
else
  echo "  no systemd manager here, so --no-service is permitted (this is the container case)."
fi

# ── the real install, minus the service ──────────────────────────────────────
say "install.sh --no-service (root, no systemd in this container)"
if bash "$WORK/src/install.sh" --no-service --owner-uid "$AGENT_UID" --watch "repo=$PROJ" \
     > /tmp/install.txt 2>&1; then
  grep -E '^(--|OK|  root|interpreter|  0[0-7])' /tmp/install.txt | head -30
  pass "install.sh --no-service exited 0"
else
  tail -40 /tmp/install.txt
  fail "install.sh --no-service"
fi
check "the config names the Linux install root" grep -q "^root       = $DEST\$" "$DEST/etc/dhu-backupd.conf"
check "the config names the installed watchlist" grep -q "^watchlist  = $DEST/etc/watchlist.conf\$" "$DEST/etc/dhu-backupd.conf"
check "the config carries the owner uid"        grep -q "^owner_uid  = $AGENT_UID\$" "$DEST/etc/dhu-backupd.conf"
check "the unit file was installed"             test -f /etc/systemd/system/dhu-backupd.service
echo "unit   : $(stat -c '%U:%G %a' /etc/systemd/system/dhu-backupd.service) /etc/systemd/system/dhu-backupd.service"
echo "         (installed and asserted; NOT loaded — there is no systemd here)"

# ── the daemon ───────────────────────────────────────────────────────────────
say "starting the daemon as root (by hand; systemd would do this on a real host)"
/usr/bin/python3 -E -s -S "$DEST/bin/dhu-backupd" --interval 15 \
  >> "$DEST/var/dhu-backupd.log" 2>&1 &
DAEMON_PID=$!
echo "pid    : $DAEMON_PID"
for _ in $(seq 1 30); do
  [ -f "$DEST/var/state.json" ] && break
  sleep 1
done
check "the daemon published a heartbeat" test -f "$DEST/var/state.json"
TRIGGER=$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["trigger"])' "$DEST/var/state.json" 2>/dev/null || echo "?")
[ "$TRIGGER" = inotify ] && pass "heartbeat trigger == inotify" || fail "heartbeat trigger == $TRIGGER, want inotify"
grep -m1 "max_user_watches" "$DEST/var/dhu-backupd.log" || true
grep -m1 "directory trigger:" "$DEST/var/dhu-backupd.log" || true
grep -m1 "interpreter:" "$DEST/var/dhu-backupd.log" || true

# ── capture latency, MEASURED ────────────────────────────────────────────────
say "capture latency, measured (not claimed)"
# Versions of one basename anywhere in a tree. The store layout is
# <tree>/<root-id>/<slug>/<relpath-dir>/@<capture>-<sha>/<ORIGINAL BASENAME>, and
# for a file at the root of the watch root there is no <relpath-dir> at all — so
# this counts by finding the leaf rather than by guessing at the depth.
versions_of() {  # <tree-dir> <basename> -> count
  find "$1" -type f -name "$2" 2>/dev/null | wc -l | tr -d ' '
}

NEW="$PROJ/note.md"
as_agent "echo 'version one' > $NEW"
T_NEW=$(wait_for_path "[ \$(find $DEST/store -type f -name note.md 2>/dev/null | wc -l) -ge 1 ]" 30)
if [ "$(versions_of "$DEST/store" note.md)" -ge 1 ]; then
  pass "a NEW file was captured in ${T_NEW}s (inotify IN_CREATE)"
  find "$DEST/store" -type f -name note.md | head -1
else
  fail "a NEW file was not captured within 30s (waited ${T_NEW}s)"
fi

V1=$(versions_of "$DEST/store" note.md)
as_agent "echo 'version two, rewritten in place' > $NEW"
T_EDIT=$(wait_for_path "[ \$(find $DEST/store -type f -name note.md 2>/dev/null | wc -l) -gt $V1 ]" 30)
V2=$(versions_of "$DEST/store" note.md)
if [ "$V2" -gt "$V1" ]; then
  pass "an IN-PLACE rewrite made a 2nd version in ${T_EDIT}s"
  echo "      macOS waits for the 15 s floor sweep here (a directory kqueue does not"
  echo "      fire for a rewrite). Linux reports IN_CLOSE_WRITE on the directory"
  echo "      watch, so this is the measured difference between the two ports."
else
  fail "an in-place rewrite produced no new version within 30s (waited ${T_EDIT}s)"
fi

# ── the admission guards ─────────────────────────────────────────────────────
say "a hard link to a root-owned file is refused (review C6)"
# TWO layers, and they are different layers. Linux's fs.protected_hardlinks
# stops an unprivileged user from linking a file they can neither read nor write
# — a kernel control macOS does not have, where `ln /etc/sudoers ./notes.md`
# SUCCEEDS as the owner (executed on the Mac, nlink went to 3). Under it the C6
# primitive is blocked before the daemon ever sees the file. That is a stronger
# position, not a reason to drop the daemon's own guard, so the guard is proven
# separately below against a link the kernel does allow.
echo "sysctl : fs.protected_hardlinks=$(cat /proc/sys/fs/protected_hardlinks 2>/dev/null || echo '?')"
if as_agent "ln /etc/shadow $PROJ/shadow-link.md" 2>/tmp/lnerr.txt; then
  fail "the kernel ALLOWED a link to /etc/shadow (fs.protected_hardlinks is off)"
else
  pass "the kernel refused a link to /etc/shadow: $(tr -d '\n' < /tmp/lnerr.txt | tail -c 80)"
fi

# A root-owned file the agent IS permitted to link (0666, so it has read+write
# permission on it), placed inside the watched tree. This is the shape the
# daemon must refuse on its own: an innocent basename over an inode root owns.
printf 'root-owned content the agent must never read back out of the store\n' \
  > "$PROJ/root-owned.txt"
chown root:root "$PROJ/root-owned.txt"
chmod 0666 "$PROJ/root-owned.txt"
if as_agent "ln $PROJ/root-owned.txt $PROJ/innocent.md"; then
  echo "link   : innocent.md -> nlink $(stat -c '%h' "$PROJ/innocent.md"), owner $(stat -c '%U' "$PROJ/innocent.md")"
  sleep 20
  refute "the hard link was NOT captured into the readable store" \
    bash -c "find $DEST/store -type f -name innocent.md | grep -q ."
  refute "its root-owned CONTENT is nowhere in the readable store" \
    bash -c "grep -rq 'agent must never read back' $DEST/store"
  if grep -qE "hardlink-nlink|wrong-owner-uid" "$DEST/var/dhu-backupd.log"; then
    pass "the daemon logged the refusal with its reason:"
    grep -hoE "(hardlink-nlink=[0-9]+|wrong-owner-uid[^ ]*)" "$DEST/var/dhu-backupd.log" |
      sort -u | head -3
  else
    fail "no hardlink-nlink / wrong-owner-uid refusal in the log"
  fi
  REASONS=$(/usr/bin/python3 -c '
import json, sys
r = json.load(open(sys.argv[1]))["refusals_by_reason"]
print(" ".join("%s=%d" % kv for kv in sorted(r.items())) or "(none)")' "$DEST/var/state.json")
  echo "heartbeat refusals_by_reason: $REASONS"
else
  fail "could not create the hard link the guard is meant to refuse"
fi

say "a credential-class file goes to the root-only vault, never the store"
as_agent "printf 'SECRET=hunter2\n' > $PROJ/.env.local"
sleep 20
refute "'.env.local' is NOT in the agent-readable store" \
  bash -c "find $DEST/store -name .env.local | grep -q ."
check "'.env.local' IS in the root-only vault" \
  bash -c "find $DEST/vault -name .env.local | grep -q ."
echo "vault  : $(stat -c '%U:%G %a' "$DEST/vault")  (0700 root — unreadable by $AGENT)"

# ── the kernel refuses the agent every write ─────────────────────────────────
say "as $AGENT, with no sudo: every write to the mirror is refused by the KERNEL"
refute "cannot create a file in store/"        as_agent "touch $DEST/store/x"
refute "cannot rm -rf store/"                  as_agent "rm -rf $DEST/store"
refute "cannot overwrite the daemon's code"    as_agent "echo x > $DEST/bin/dhu-backupd"
# Against a version that DEMONSTRABLY exists — an empty find would exit 0 and
# this check would pass without having tried anything.
CAPTURED=$(find "$DEST/store" -type f -name note.md | head -1)
if [ -n "${CAPTURED:-}" ]; then
  echo "      target: $CAPTURED  ($(stat -c '%U:%G %a' "$CAPTURED"))"
  refute "cannot overwrite a captured version"  as_agent "echo x > '$CAPTURED'"
  refute "cannot unlink a captured version"     as_agent "rm -f '$CAPTURED'"
  check  "the captured version is still there"  test -f "$CAPTURED"
else
  fail "no captured version to attack (capture failed above)"
fi
refute "cannot read the vault"                 as_agent "ls $DEST/vault"
refute "cannot edit the watchlist"             as_agent "echo 'evil /' >> $DEST/etc/watchlist.conf"
refute "cannot edit the systemd unit"          as_agent "echo x >> /etc/systemd/system/dhu-backupd.service"
if [ -n "$DAEMON_PID" ]; then
  refute "cannot kill the daemon (EPERM)"      as_agent "kill -TERM $DAEMON_PID"
  sleep 1
  check  "the daemon is still running"         kill -0 "$DAEMON_PID"
fi

# ── recovery, as the agent, no sudo ──────────────────────────────────────────
say "recovery as $AGENT — no sudo, no human"
echo "--- dhu-backup ls note ---"
as_agent "$DEST/bin/dhu-backup ls note" 2>&1 | head -8
as_agent "rm -f $NEW"
echo "--- dhu-backup missing $NEW ---"
as_agent "$DEST/bin/dhu-backup missing $NEW" 2>&1 | head -12
echo "--- dhu-backup restore ---"
as_agent "$DEST/bin/dhu-backup --root-id repo restore note.md" 2>&1 | head -6
if as_agent "test -f $NEW"; then
  pass "the deleted file was restored by the unprivileged helper"
  echo "      content: $(cat "$NEW")"
  echo "      owner  : $(stat -c '%U:%G' "$NEW")"
else
  fail "restore did not put the file back"
fi
echo "--- dhu-backup missing on a VAULTED path ---"
as_agent "$DEST/bin/dhu-backup missing $PROJ/.env.local" 2>&1 | head -10

# ── the heartbeat ────────────────────────────────────────────────────────────
say "the heartbeat"
/usr/bin/python3 -m json.tool "$DEST/var/state.json"
STATE=$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["state"])' "$DEST/var/state.json")
FAILS=$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["trigger_watch_failures"])' "$DEST/var/state.json")
INTERP=$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["interpreter_root_owned"])' "$DEST/var/state.json")
[ "$STATE" = ok ] && pass "state == ok" || fail "state == $STATE, want ok"
[ "$FAILS" = 0 ] && pass "trigger_watch_failures == 0" || fail "trigger_watch_failures == $FAILS, want 0"
[ "$INTERP" = True ] && pass "interpreter_root_owned == true" || fail "interpreter_root_owned == $INTERP"

# ── the unit tests, on Linux ─────────────────────────────────────────────────
say "the unit suite, under this container's python3"
# The suite's own result is a CHECK, not decoration. It is run from the copy, as
# root, so the two "refuses without root" tests skip themselves rather than
# performing a real install here.
( cd "$WORK" && /usr/bin/python3 -m unittest discover -s tests -p 'test_*.py' > /tmp/suite.txt 2>&1 )
SUITE_RC=$?
tail -4 /tmp/suite.txt
if [ "$SUITE_RC" -eq 0 ]; then
  pass "the unit suite is green on Linux"
else
  grep -E "^(FAIL|ERROR):" /tmp/suite.txt | head -10
  fail "the unit suite is not green on Linux"
fi

# ── the uninstaller ──────────────────────────────────────────────────────────
say "uninstall.sh, for real, on Linux"
if [ -n "$DAEMON_PID" ]; then kill "$DAEMON_PID" 2>/dev/null || true; sleep 1; fi
DAEMON_PID=""
STORE_BEFORE=$(find "$DEST/store" -type f | wc -l | tr -d ' ')
echo "store  : $STORE_BEFORE captured file(s) before uninstalling"
echo "--- uninstall.sh --dry-run, as $AGENT (no sudo) ---"
as_agent "bash $WORK/src/uninstall.sh --dry-run" 2>&1 | sed -n '1,14p'
if bash "$WORK/src/uninstall.sh" > /tmp/uninstall.txt 2>&1; then
  grep -E '^(--|  |OK)' /tmp/uninstall.txt | head -20
  pass "uninstall.sh exited 0"
else
  tail -30 /tmp/uninstall.txt
  fail "uninstall.sh"
fi
refute "bin/ is gone"                  test -d "$DEST/bin"
refute "etc/ is gone"                  test -d "$DEST/etc"
refute "the systemd unit file is gone" test -f /etc/systemd/system/dhu-backupd.service
check  "store/ was KEPT"               test -d "$DEST/store"
check  "vault/ was KEPT"               test -d "$DEST/vault"
check  "var/ was KEPT"                 test -d "$DEST/var"
STORE_AFTER=$(find "$DEST/store" -type f | wc -l | tr -d ' ')
if [ "$STORE_AFTER" -eq "$STORE_BEFORE" ]; then
  pass "every captured file survived the uninstall ($STORE_AFTER)"
else
  fail "the uninstall lost captured files: $STORE_BEFORE -> $STORE_AFTER"
fi

# ── done ─────────────────────────────────────────────────────────────────────
say "what this run did NOT prove"
cat <<'NOTPROVEN'
  * the systemd unit actually loading (`systemctl enable --now dhu-backupd`)
  * polkit refusing a non-root `systemctl stop dhu-backupd`
  * ProtectSystem=strict / ProtectHome=read-only / PrivateTmp taking effect
  * survival across a reboot
  There is no systemd manager in a plain container, so all four need a real
  Ubuntu host or VM. Everything above is the daemon itself, which is the half a
  container CAN prove.
NOTPROVEN

if [ -n "$DAEMON_PID" ]; then kill "$DAEMON_PID" 2>/dev/null || true; fi

say "result"
if [ "$FAILURES" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
  exit 0
fi
echo "$FAILURES CHECK(S) FAILED"
exit 1
