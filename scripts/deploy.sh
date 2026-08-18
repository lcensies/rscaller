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
# --checksum, not mtime: the VM clock can run ahead of the host (snapshot
# reverts + lab NTP), and mtime-skipped files then silently no-op the build.
rsync -az --checksum --delete \
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
# apt-get update first: after a baseline revert the index is stale and pinned
# package versions 404.
ssh "$REMOTE" "sudo apt-get update -qq 2>&1 | tail -1; sudo apt-get install -y libfuse3-dev libvirt-dev 2>&1 | tail -3" || true
# rscfuse mounts with allow_other (QEMU relay user needs it) — requires
# user_allow_other in /etc/fuse.conf. Idempotent; same step as bootstrap.sh.
ssh "$REMOTE" "grep -q '^user_allow_other' /etc/fuse.conf 2>/dev/null || echo 'user_allow_other' | sudo tee -a /etc/fuse.conf >/dev/null"
ok "apt done"

step "Building Rust workspace on $REMOTE (release)"
# pipefail so a failed cargo build aborts the deploy instead of leaving a
# stale binary in place while "Deploy done" prints.
ssh "$REMOTE" "source \$HOME/.cargo/env 2>/dev/null; \
  cd $REMOTE_DIR && \
  set -o pipefail && \
  cargo build --workspace --release --features rsc/relay 2>&1 | grep -E '^error|Finished'"
ok "remote build done"

step "Fetching built artifacts back to host cache (vms/bin/)"
# The per-test snapshot reverts wipe binaries back to whatever the baseline
# captured. Caching them host-side lets conftest re-push after every revert,
# so baselines never need re-baking for code changes.
mkdir -p "$REPO_ROOT/vms/bin"
rsync -az --checksum \
	"$REMOTE:$REMOTE_DIR/target/release/rsc" \
	"$REMOTE:$REMOTE_DIR/target/release/rsclient" \
	"$REMOTE:$REMOTE_DIR/target/release/rsbeacon" \
	"$REPO_ROOT/vms/bin/"
ok "host cache updated"

echo ""
echo "==> Deploy done. Binaries are in $REMOTE_DIR/target/release/ on $REMOTE."
echo "    Next: 'make deploy-beacon' to push rsbeacon to the beacon VM."
echo "    Or:   'make test-vm NO_DEPLOY=1' to run the E2E test suite."
