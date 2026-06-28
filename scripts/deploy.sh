#!/usr/bin/env bash
# deploy.sh — alias for bootstrap.sh (rsync + build only, skips apt/rust install)
#
# Usage: bash scripts/deploy.sh [SSH_HOST] [REMOTE_DIR]
# For first-time setup use bootstrap.sh instead.

set -euo pipefail
REMOTE="${1:-${REMOTE:-rscaller}}"
REMOTE_DIR="${2:-/home/ubuntu/rscaller}"
BECOME_PASS="${BECOME_PASS:-ubuntu}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

step() { echo ""; echo "==> $*"; }
ok()   { echo "    [ok] $*"; }

# Ensure passwordless sudo on remote so subsequent steps (tracefs, insmod) work unattended.
step "Configuring NOPASSWD sudo on $REMOTE"
ssh "$REMOTE" "echo ${BECOME_PASS} | sudo -S bash -c \
  'echo ubuntu ALL=\(ALL\) NOPASSWD: ALL > /etc/sudoers.d/99-rscaller-nopasswd && \
   chmod 440 /etc/sudoers.d/99-rscaller-nopasswd'" 2>/dev/null || true
ok "sudoers done"

step "Syncing repo source to $REMOTE:$REMOTE_DIR"
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
  --exclude='lib/khook/.git/' \
  "$REPO_ROOT/" "$REMOTE:$REMOTE_DIR/"
ok "rsync done"

step "Building Rust workspace on $REMOTE (release)"
ssh "$REMOTE" "source \$HOME/.cargo/env 2>/dev/null; \
  cd $REMOTE_DIR && \
  cargo build --workspace --release --exclude rscfuse 2>&1 | grep -E '^error|Finished'"
ok "remote build done"

echo ""
echo "==> Deploy done."
echo "    To build and load kmod: ssh $REMOTE 'cd $REMOTE_DIR/kmod && make all && sudo insmod rscaller.ko'"
