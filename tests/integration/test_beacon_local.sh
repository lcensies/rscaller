#!/usr/bin/env bash
set -euo pipefail
REPO="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$REPO"

echo "=== Test: beacon unit tests + local roundtrip ==="
cargo build -p rsbeacon 2>/dev/null

# Start beacon on a random-ish port (avoid conflicts)
PORT=19998
pkill -f "rsbeacon.*$PORT" 2>/dev/null || true
./target/debug/rsbeacon --listen "127.0.0.1:$PORT" &
BEACON_PID=$!
trap "kill $BEACON_PID 2>/dev/null || true" EXIT
sleep 0.3

ss -tlnp | grep "$PORT" >/dev/null || { echo "FAIL: beacon not listening on $PORT"; exit 1; }

cargo test -p rsbeacon -- --test-output immediate 2>&1 | \
  grep -E "^test |^running [0-9]|test result:"

echo "PASS"
