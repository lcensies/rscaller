#!/usr/bin/env bash
# Deploy rscaller to the remote kmod VM
set -euo pipefail
REMOTE="${1:-${REMOTE:-dev-vm-rscaller}}"
REMOTE_DIR="/home/ubuntu/rscaller"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Deploying rscaller to $REMOTE:$REMOTE_DIR ==="

echo "--- Syncing files ---"
rsync -avz --delete \
  --exclude='.git/' \
  --exclude='target/' \
  --exclude='kmod/*.ko' \
  --exclude='kmod/*.o' \
  --exclude='kmod/*.mod*' \
  --exclude='kmod/modules.order' \
  --exclude='kmod/Module.symvers' \
  --exclude='kmod/.tmp_versions/' \
  --exclude='vms/' \
  --exclude='.workmux-prompts/' \
  --exclude='certs/' \
  --exclude='lib/khook/' \
  "$REPO_ROOT/" "$REMOTE:$REMOTE_DIR/"

echo "--- Initializing submodules on remote ---"
ssh "$REMOTE" "cd $REMOTE_DIR && git submodule update --init lib/khook 2>/dev/null || true"

echo "--- Building kmod on remote ---"
ssh "$REMOTE" "cd $REMOTE_DIR && make kmod 2>&1"

echo "--- Building Rust workspace on remote ---"
ssh "$REMOTE" "source ~/.cargo/env 2>/dev/null; cd $REMOTE_DIR && cargo build --workspace --release 2>&1 | tail -20"

echo "=== Deploy complete ==="
echo "Load kmod:  ssh $REMOTE 'cd $REMOTE_DIR/kmod && sudo insmod rscaller.ko'"
echo "Run tests:  REMOTE=$REMOTE make test-remote"
