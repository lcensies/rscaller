#!/usr/bin/env bash
# Run integration tests: kmod on remote VM, rsbeacon on localhost
set -euo pipefail
REMOTE="${1:-${REMOTE:-dev-vm-rscaller}}"
REMOTE_DIR="/home/ubuntu/rscaller"
BEACON_HOST="${BEACON_HOST:-127.0.0.1}"
BEACON_PORT="${BEACON_PORT:-9999}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0

run_test() {
  local name="$1"; local cmd="$2"; local where="${3:-remote}"
  printf "  %-50s " "$name ..."
  if [ "$where" = "local" ]; then
    if eval "$cmd" > /tmp/rscaller_test_output 2>&1; then
      echo "PASS"; PASS=$((PASS+1))
    else
      echo "FAIL"; cat /tmp/rscaller_test_output | head -10; FAIL=$((FAIL+1))
    fi
  else
    if ssh "$REMOTE" "$cmd" > /tmp/rscaller_test_output 2>&1; then
      echo "PASS"; PASS=$((PASS+1))
    else
      echo "FAIL"; cat /tmp/rscaller_test_output | head -10; FAIL=$((FAIL+1))
    fi
  fi
}

echo "=== rscaller integration tests ==="
echo "Remote:  $REMOTE"
echo "Beacon:  $BEACON_HOST:$BEACON_PORT (running locally)"
echo ""

# --- Kmod ---
echo "-- Kmod --"
run_test "kmod_ko_exists"       "ls $REMOTE_DIR/kmod/rscaller.ko"
ssh "$REMOTE" "sudo rmmod rscaller 2>/dev/null || true"
run_test "kmod_load"            "cd $REMOTE_DIR/kmod && sudo insmod rscaller.ko"
run_test "kmod_in_lsmod"        "lsmod | grep rscaller"
run_test "proc_entry_exists"    "ls /proc/rscaller"
run_test "dmesg_init"           "sudo dmesg | tail -30 | grep -i 'rscaller'"

# --- Start local rsbeacon ---
echo ""
echo "-- Local rsbeacon (localhost:$BEACON_PORT) --"
pkill rsbeacon 2>/dev/null || true
"$REPO_ROOT/target/release/rsbeacon" --listen "${BEACON_HOST}:${BEACON_PORT}" &
BEACON_PID=$!
trap "kill \$BEACON_PID 2>/dev/null || true; ssh '$REMOTE' 'pkill rsclient 2>/dev/null; sudo rmmod rscaller 2>/dev/null' 2>/dev/null || true" EXIT
sleep 0.5
run_test "rsbeacon_listening"   "ss -tlnp | grep $BEACON_PORT" "local"

# --- Start rsclient relay on remote ---
echo ""
echo "-- rsclient relay (remote -> local beacon) --"
ssh "$REMOTE" "pkill rsclient 2>/dev/null || true"
# Resolve local IP reachable from remote
LOCAL_IP="$(ssh "$REMOTE" "getent hosts $(hostname) 2>/dev/null | awk '{print \$1}' | head -1" 2>/dev/null || echo "$BEACON_HOST")"
echo "  (local IP seen from remote: $LOCAL_IP)"
ssh "$REMOTE" "source ~/.cargo/env 2>/dev/null; sudo $REMOTE_DIR/target/release/rsclient \
  --beacon '${LOCAL_IP}:${BEACON_PORT}' \
  --proc-path /proc/rscaller > /tmp/rsclient.log 2>&1 &"
sleep 1
run_test "rsclient_running"     "pgrep -fa rsclient | grep -v grep"

# --- Trigger syscall interception ---
echo ""
echo "-- Syscall forwarding --"
run_test "trigger_kill_sig0"    "kill -0 \$\$"  # kill(self, 0): intercepted by kmod
sleep 0.5
run_test "dmesg_intercept"      "sudo dmesg | tail -50 | grep -iE '(rscaller|handle_syscall|intercept|syscall)'"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
