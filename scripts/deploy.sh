#!/usr/bin/env bash
# deploy.sh — alias for bootstrap.sh (rsync + build only, skips apt/rust install)
#
# Usage: bash scripts/deploy.sh [SSH_HOST] [REMOTE_DIR]
# For first-time setup use bootstrap.sh instead.

set -euo pipefail
REMOTE="${1:-${REMOTE:-rscaller}}"
REMOTE_DIR="${2:-/home/ubuntu/rscaller}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

step() { echo ""; echo "==> $*"; }
ok()   { echo "    [ok] $*"; }

step "Syncing repo to $REMOTE:$REMOTE_DIR"
rsync -az --delete \
  --exclude='.git/' \
  --exclude='target/' \
  --exclude='kmod/*.ko' \
  --exclude='kmod/*.o' \
  --exclude='kmod/*.mod.c' \
  --exclude='kmod/*.symvers' \
  --exclude='kmod/modules.order' \
  --exclude='kmod/.tmp_versions/' \
  --exclude='vms/' \
  --exclude='.workmux-prompts/' \
  --exclude='certs/' \
  --exclude='lib/khook/' \
  "$REPO_ROOT/" "$REMOTE:$REMOTE_DIR/"
ok "rsync done"

step "Generating kmod headers + building kmod + Rust workspace on $REMOTE"
ssh "$REMOTE" "bash -s" << ENDSSH
set -euo pipefail
source "\$HOME/.cargo/env" 2>/dev/null || true
cd "$REMOTE_DIR"

# Regenerate C headers
cargo run -p codegen --release -- \
  --tbl-dir files --forwarded files/forwarded_syscalls --out kmod 2>&1 | grep -v '^warning' || true

# Build kmod
cd kmod && make clean 2>/dev/null || true && make all 2>&1 | grep -E 'error:|LD \[M\]|Error [0-9]'
ls -lh rscaller.ko && cd ..

# Build Rust workspace
cargo build --workspace --release 2>&1 | grep -E '^error|Finished'
ls -lh target/release/rsclient target/release/rsbeacon
ENDSSH
ok "all built"

echo ""
echo "==> Deploy done. Load kmod:"
echo "    ssh $REMOTE 'cd $REMOTE_DIR/kmod && sudo insmod rscaller.ko'"
