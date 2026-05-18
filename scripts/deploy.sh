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

# Build local binaries first so rsbeacon is always fresh on the host side.
step "Building local Rust workspace (rsbeacon + rsclient, skip rscaller-run)"
cd "$REPO_ROOT"
cargo build --workspace --release --exclude rscaller-run 2>&1 | grep -E '^error|Finished'
ok "local build done"

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

step "Fetching tracefs format files from $REMOTE"
TRACEFS_TMP="$(mktemp -d)"
trap 'rm -rf "$TRACEFS_TMP"' EXIT
ssh -n "$REMOTE" "sudo mountpoint -q /sys/kernel/tracing || sudo mount -t tracefs nodev /sys/kernel/tracing"
while IFS= read -r syscall; do
    syscall="${syscall%%#*}"
    syscall="${syscall// /}"
    [[ -z "$syscall" ]] && continue
    mkdir -p "$TRACEFS_TMP/sys_enter_${syscall}"
    ssh -n "$REMOTE" "sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_${syscall}/format" \
        > "$TRACEFS_TMP/sys_enter_${syscall}/format" 2>/dev/null || true
done < "$REPO_ROOT/files/forwarded_syscalls"
ok "tracefs fetched to $TRACEFS_TMP"

step "Generating kmod headers + building kmod + Rust workspace on $REMOTE"
# Codegen is run locally so the freshly-fetched tracefs snapshot drives the
# generated metadata; the produced syscalls.c / handler_wrappers.h get rsync'd
# in the next step (we re-sync after codegen).
cargo run -p codegen --release -- \
  --tbl-dir files --forwarded files/forwarded_syscalls \
  --tracefs-dir "$TRACEFS_TMP" \
  --out kmod 2>&1 | grep -v '^warning' || true
ok "codegen done"

step "Re-syncing regenerated kmod sources to $REMOTE"
rsync -az \
  "$REPO_ROOT/kmod/handler_wrappers.h" \
  "$REPO_ROOT/kmod/syscalls.c" \
  "$REMOTE:$REMOTE_DIR/kmod/"
ok "rsync (codegen output) done"

ssh "$REMOTE" "bash -s" << ENDSSH
set -euo pipefail
source "\$HOME/.cargo/env" 2>/dev/null || true
cd "$REMOTE_DIR"

# Build kmod
cd kmod && make all 2>&1 | grep -E 'error:|LD \[M\]|Error [0-9]'
ls -lh rscaller.ko && cd ..

# Build Rust workspace (includes rscaller-run on remote)
cargo build --workspace --release 2>&1 | grep -E '^error|Finished'
ls -lh target/release/rsclient target/release/rsbeacon target/release/rscaller-run
ENDSSH
ok "all built"

echo ""
echo "==> Deploy done. Load kmod:"
echo "    ssh $REMOTE 'cd $REMOTE_DIR/kmod && sudo insmod rscaller.ko'"
