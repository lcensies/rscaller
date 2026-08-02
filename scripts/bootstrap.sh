#!/usr/bin/env bash
# bootstrap.sh — full VM setup + deploy + build in one shot
#
# Usage:
#   bash scripts/bootstrap.sh [SSH_HOST] [REMOTE_DIR]
#
# Defaults:
#   SSH_HOST   = rscaller        (SSH alias in ~/.ssh/config)
#   REMOTE_DIR = /home/ubuntu/rscaller
#
# What it does:
#   1. Install system deps on remote VM (apt-get)
#   2. Install Rust toolchain (if missing)
#   3. Rsync this repo to remote
#   4. Init khook submodule on remote (cloned from GitHub)
#   5. Generate kmod C headers (tools/codegen)
#   6. Build kernel module
#   7. Build Rust workspace (rsbeacon + rsclient)
#
# Re-runnable: safe to run again after partial failure.

set -euo pipefail

REMOTE="${1:-${REMOTE:-rscaller}}"
REMOTE_DIR="${2:-/home/ubuntu/rscaller}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KHOOK_URL="https://github.com/lcensies/khook"

step() {
	echo ""
	echo "==> $*"
}
ok() { echo "    [ok] $*"; }
fail() {
	echo "    [FAIL] $*" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# 1. System dependencies
# ---------------------------------------------------------------------------
step "Installing system deps on $REMOTE"
ssh "$REMOTE" 'bash -s' <<'ENDSSH'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

KERNEL="$(uname -r)"
PKGS=(
  build-essential gcc make git curl
  pkg-config libssl-dev
  "linux-headers-${KERNEL}"
  # XDP/eBPF toolchain (beacon-smoltcp-xdp-netstack net backend):
  #   clang/llvm  — compile bpf/*.c to BPF bytecode (clang -target bpf)
  #   libbpf-dev  — vmlinux.h / bpf_helpers.h and friends for the XDP program
  #   libelf-dev  — BPF object (ELF) loading support
  #   bpftool     — inspect/debug loaded XDP programs and maps
  clang llvm libbpf-dev libelf-dev bpftool
  # libvirt SDK for qemu-vdw-core relay VM provisioning
  libvirt-dev
)

# Check which are missing
MISSING=()
for pkg in "${PKGS[@]}"; do
  dpkg -s "$pkg" &>/dev/null || MISSING+=("$pkg")
done

if [ ${#MISSING[@]} -gt 0 ]; then
  echo "  Installing: ${MISSING[*]}"
  sudo apt-get update -qq
  sudo apt-get install -y "${MISSING[@]}" 2>&1 | grep -E '^Setting up|^Unpacking|error' || true
else
  echo "  All packages already installed."
fi

echo "  gcc:     $(gcc --version | head -1)"
echo "  headers: $(ls /lib/modules/${KERNEL}/build/Makefile 2>/dev/null && echo present || echo MISSING)"
ENDSSH
ok "system deps"

# ---------------------------------------------------------------------------
# 1.5 libvirt/FUSE config for qemu-relay
# ---------------------------------------------------------------------------
step "Configuring libvirt/FUSE for qemu-relay on $REMOTE"
ssh "$REMOTE" 'bash -s' <<'ENDSSH'
set -euo pipefail
CHANGED=0
# rsc relay attaches rscfuse-backed disks to a local VM. AppArmor's per-VM
# profile generator cannot open FUSE paths, so domain start fails unless
# libvirt's security driver is disabled.
if ! sudo grep -q '^security_driver = "none"' /etc/libvirt/qemu.conf 2>/dev/null; then
  if sudo grep -qE '^#?security_driver' /etc/libvirt/qemu.conf; then
    sudo sed -i -E 's/^#?security_driver.*/security_driver = "none"/' /etc/libvirt/qemu.conf
  else
    echo 'security_driver = "none"' | sudo tee -a /etc/libvirt/qemu.conf >/dev/null
  fi
  CHANGED=1
fi
# Non-root `rsc fuse` mounts need allow_other so the QEMU process user can
# open the FUSE-backed disk.
if ! grep -q '^user_allow_other' /etc/fuse.conf 2>/dev/null; then
  echo 'user_allow_other' | sudo tee -a /etc/fuse.conf >/dev/null
fi
if [ "$CHANGED" -eq 1 ]; then
  sudo systemctl restart libvirtd
fi
ENDSSH
ok "libvirt/FUSE config"

# ---------------------------------------------------------------------------
# 2. Rust toolchain
# ---------------------------------------------------------------------------
step "Checking Rust on $REMOTE"
ssh "$REMOTE" 'bash -s' <<'ENDSSH'
set -euo pipefail
source "$HOME/.cargo/env" 2>/dev/null || true
if command -v cargo &>/dev/null; then
  echo "  cargo $(cargo --version)"
else
  echo "  Installing Rust (stable)..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --no-modify-path 2>&1 | tail -3
  source "$HOME/.cargo/env"
  echo "  cargo $(cargo --version)"
fi
ENDSSH
ok "Rust toolchain"

# ---------------------------------------------------------------------------
# 3. Rsync repo
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# 4. khook submodule
# ---------------------------------------------------------------------------
step "Initializing khook submodule on $REMOTE"
ssh "$REMOTE" "bash -s" <<ENDSSH
set -euo pipefail
KHOOK_DIR="$REMOTE_DIR/lib/khook"
if [ ! -f "\$KHOOK_DIR/Makefile.khook" ]; then
  echo "  Cloning khook..."
  mkdir -p "$REMOTE_DIR/lib"
  git clone "$KHOOK_URL" "\$KHOOK_DIR" 2>&1 | tail -3
else
  echo "  khook already present, pulling..."
  git -C "\$KHOOK_DIR" pull --ff-only 2>&1 | tail -2 || true
fi
echo "  khook: \$(git -C "\$KHOOK_DIR" log --oneline -1)"
ENDSSH
ok "khook"

# ---------------------------------------------------------------------------
# 5. Generate kmod C headers
# ---------------------------------------------------------------------------
step "Generating kmod C headers (tools/codegen)"
ssh "$REMOTE" "bash -s" <<ENDSSH
set -euo pipefail
source "\$HOME/.cargo/env" 2>/dev/null || true
cd "$REMOTE_DIR"
cargo run -p codegen --release -- \
  --tbl-dir files \
  --forwarded files/forwarded_syscalls \
  --out kmod 2>&1 | grep -v '^warning'
echo "  generated: kmod/handler_wrappers.h kmod/syscalls.c"
ENDSSH
ok "kmod headers"

# ---------------------------------------------------------------------------
# 6. Build kernel module
# ---------------------------------------------------------------------------
step "Building kernel module on $REMOTE"
ssh "$REMOTE" "bash -s" <<ENDSSH
set -euo pipefail
cd "$REMOTE_DIR/kmod"
make clean 2>/dev/null || true
make all 2>&1 | grep -E 'error:|LD \[M\]|Error [0-9]' | head -20
ls -lh rscaller.ko
ENDSSH
ok "kmod/rscaller.ko built"

# ---------------------------------------------------------------------------
# 7. Build Rust workspace
# ---------------------------------------------------------------------------
step "Building Rust workspace on $REMOTE"
ssh "$REMOTE" "bash -s" <<ENDSSH
set -euo pipefail
source "\$HOME/.cargo/env" 2>/dev/null || true
cd "$REMOTE_DIR"
cargo build --workspace --release 2>&1 | grep -E '^error|^warning\[|Compiling|Finished'
ls -lh target/release/rsclient target/release/rsbeacon
ENDSSH
ok "Rust binaries built"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "==> Bootstrap complete on $REMOTE"
echo ""
echo "    Load kmod:"
echo "      ssh $REMOTE 'cd $REMOTE_DIR/kmod && sudo insmod rscaller.ko'"
echo ""
echo "    Start beacon locally:"
echo "      ./target/release/rsbeacon --listen 0.0.0.0:9999"
echo ""
echo "    Start relay on victim:"
echo "      ssh $REMOTE 'sudo $REMOTE_DIR/target/release/rsclient --beacon <local-ip>:9999'"
echo ""
echo "    Run tests:"
echo "      make test-remote REMOTE=$REMOTE"
