#!/usr/bin/env bash
# Run integration tests: kmod on REMOTE, rsclient on CLIENT (defaults to REMOTE), rsbeacon on localhost
set -euo pipefail
REMOTE="${1:-${REMOTE:-dev-vm-rscaller}}"
BECOME_PASS="${2:-${BECOME_PASS:-}}"
# CLIENT runs rsclient; defaults to REMOTE if not set
CLIENT="${CLIENT:-$REMOTE}"
REMOTE_DIR="/home/ubuntu/rscaller"
BEACON_HOST="${BEACON_HOST:-127.0.0.1}"
BEACON_PORT="${BEACON_PORT:-9999}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0

# Load .env if present (supports BECOME_PASS=...)
if [[ -f "$REPO_ROOT/.env" ]]; then
  # shellcheck disable=SC1091
  set -o allexport; source "$REPO_ROOT/.env"; set +o allexport
fi

# For remote sudo: either plain sudo or password-piped sudo -S
if [[ -n "$BECOME_PASS" ]]; then
  SUDO="echo $(printf '%q' "$BECOME_PASS") | sudo -S"
else
  SUDO="sudo"
fi

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
echo "Client:  $CLIENT"
echo "Beacon:  $BEACON_HOST:$BEACON_PORT (running locally)"
echo ""

# --- Kmod ---
echo "-- Kmod --"
run_test "kmod_ko_exists"       "ls $REMOTE_DIR/kmod/rscaller.ko"
# Kill rsclient first (prevents use_count leak mid-syscall), then rmmod
ssh "$REMOTE" "
  pkill -9 rsclient 2>/dev/null || true
  sleep 0.5
  if lsmod | grep -q '^rscaller'; then
    $SUDO rmmod rscaller 2>/dev/null || $SUDO rmmod -f rscaller 2>/dev/null || true
    for i in \$(seq 1 20); do
      lsmod | grep -q '^rscaller' || break
      sleep 0.5
    done
  fi
"
run_test "kmod_load"            "cd $REMOTE_DIR/kmod && $SUDO insmod rscaller.ko"
run_test "kmod_in_lsmod"        "lsmod | grep rscaller"
run_test "proc_entry_exists"    "ls /proc/rscaller"
run_test "dmesg_init"           "$SUDO dmesg | grep -i 'rscaller'"

# --- Start local rsbeacon + SSH tunnel so VM can reach it ---
echo ""
echo "-- Local rsbeacon (localhost:$BEACON_PORT, tunnelled to $CLIENT) --"
pkill rsbeacon 2>/dev/null || true
"$REPO_ROOT/target/release/rsbeacon" --listen "127.0.0.1:${BEACON_PORT}" &
BEACON_PID=$!
# Forward BEACON_PORT on the VM back to localhost here via reverse tunnel
ssh -N -R "${BEACON_PORT}:127.0.0.1:${BEACON_PORT}" "$CLIENT" &
TUNNEL_PID=$!
trap "kill \$BEACON_PID \$TUNNEL_PID 2>/dev/null || true
  ssh '$CLIENT' 'pkill -9 rsclient 2>/dev/null || true' 2>/dev/null || true
  sleep 0.5
  ssh '$REMOTE' '$SUDO rmmod rscaller 2>/dev/null || $SUDO rmmod -f rscaller 2>/dev/null || true' 2>/dev/null || true" EXIT
sleep 1
run_test "rsbeacon_listening"   "ss -tlnp | grep $BEACON_PORT" "local"

# --- Start rsclient relay on CLIENT ---
echo ""
echo "-- rsclient relay ($CLIENT -> tunnel:$BEACON_PORT) --"
ssh "$CLIENT" "pkill -9 rsclient 2>/dev/null || true"
# Copy CA cert to CLIENT so rsclient can verify rsbeacon's TLS cert
CA_PEM="$(find "$REPO_ROOT/target/release/build" -name "ca.pem" 2>/dev/null | head -1)"
if [[ -n "$CA_PEM" ]]; then
  scp -q "$CA_PEM" "$CLIENT:/tmp/rscaller-ca.pem"
  CA_CERT_ARG="--ca-cert /tmp/rscaller-ca.pem"
else
  CA_CERT_ARG=""
fi
ssh "$CLIENT" "nohup $REMOTE_DIR/target/release/rsclient \
  --beacon '127.0.0.1:${BEACON_PORT}' \
  $CA_CERT_ARG \
  --proc-path /proc/rscaller > /tmp/rsclient.log 2>&1 &"
sleep 1
run_test "rsclient_running"     "pgrep -fa rsclient | grep -v grep"

# --- Trigger syscall interception ---
echo ""
echo "-- Syscall forwarding --"
if ! ssh "$CLIENT" "pgrep -fa rsclient | grep -v grep" > /dev/null 2>&1; then
  echo "  (skipping — rsclient not running)"
  FAIL=$((FAIL+2))
else
  run_test "trigger_kill_sig0"    "timeout 5 kill -0 \$\$"  # kill(self, 0): intercepted by kmod
  sleep 0.5
  run_test "dmesg_intercept"      "$SUDO dmesg | tail -50 | grep -iE '(rscaller|handle_syscall|intercept|syscall)'"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
