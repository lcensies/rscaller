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

step() {
	echo ""
	echo "==> $*"
}
ok() { echo "    [ok] $*"; }

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

step "Syncing relay artifacts to /var/lib/libvirt/images/rscaller-relay on $REMOTE"
ssh "$REMOTE" "sudo mkdir -p /var/lib/libvirt/images/rscaller-relay && \
  sudo rsync -a --checksum $REMOTE_DIR/qemu-relay-artifacts/ /var/lib/libvirt/images/rscaller-relay/ && \
  sudo chmod 644 /var/lib/libvirt/images/rscaller-relay/*"
ok "relay artifacts done"

step "Installing build dependencies on $REMOTE"
ssh "$REMOTE" "sudo apt-get install -y libfuse3-dev libvirt-dev 2>&1 | tail -3" || true
ok "apt done"

step "Building Rust workspace on $REMOTE (release)"
ssh "$REMOTE" "source \$HOME/.cargo/env 2>/dev/null; \
  cd $REMOTE_DIR && \
  cargo build --workspace --release --features rsc/relay 2>&1 | grep -E '^error|Finished'"
ok "remote build done"

echo ""
echo "==> Deploy done. Binaries are in $REMOTE_DIR/target/release/ on $REMOTE."
echo "    Next: 'make deploy-beacon' to push rsbeacon to the beacon VM."
echo "    Or:   'make test-vm NO_DEPLOY=1' to run the E2E test suite."
