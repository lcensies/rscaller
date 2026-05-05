#!/usr/bin/env bash
# Install all build dependencies on the remote rscaller VM
set -euo pipefail
REMOTE="${1:-${REMOTE:-dev-vm-rscaller}}"

echo "=== Installing build dependencies on $REMOTE ==="
ssh "$REMOTE" bash <<'ENDSSH'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -qq
sudo apt-get install -y build-essential linux-headers-$(uname -r) \
  linux-tools-$(uname -r) linux-tools-common \
  bpftool pkg-config libssl-dev curl git 2>&1 | tail -5

if ! command -v cargo &>/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable 2>&1 | tail -5
fi

source "$HOME/.cargo/env" 2>/dev/null || true

echo "gcc: $(gcc --version | head -1)"
echo "cargo: $(cargo --version 2>/dev/null || echo 'not found')"
echo "kernel headers: $(ls /lib/modules/$(uname -r)/build 2>/dev/null && echo 'present' || echo 'missing')"
ENDSSH
