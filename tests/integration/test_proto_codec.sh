#!/usr/bin/env bash
set -euo pipefail
REPO="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
cd "$REPO"

echo "=== Test: rscaller-proto codec roundtrip ==="
cargo test -p rscaller-proto -- --test-output immediate 2>&1 | \
  grep -E "^test |^running [0-9]|test result:"
echo "PASS"
