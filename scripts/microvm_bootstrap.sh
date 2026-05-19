#!/usr/bin/env bash
# microvm_bootstrap.sh — idempotent setup for Firecracker microVM testing on the VM.
#
# Run this INSIDE the VM (dev-vm-rscaller) as root:
#   sudo bash scripts/microvm_bootstrap.sh
#
# What it does (all idempotent):
#   1. Install deps (firecracker, e2fsprogs, docker)
#   2. Extract vmlinux from host vmlinuz (skip if already done)
#   3. Build rootfs via docker + Alpine (skip if already done)
#      - Inject rsbeacon + rscaller.ko
#   4. Set up fc-tap0 (172.16.0.1/30) — teardown+recreate to be idempotent
#   5. Write Firecracker JSON config to /tmp/fc-config.json
#   6. Print launch command
#
# Outputs (on the VM):
#   /tmp/rscaller-vmlinux       — uncompressed ELF kernel
#   /tmp/rscaller-rootfs.img    — ext4 rootfs with rsbeacon + rscaller.ko
#   /tmp/fc-config.json         — Firecracker config
#
# Guest networking: 172.16.0.2/30, host tap: 172.16.0.1/30 (same /30 subnet)
# rsbeacon listens on guest :9999, reachable from host at 172.16.0.2:9999

set -euo pipefail

RSCALLER_DIR="${RSCALLER_DIR:-/home/ubuntu/rscaller}"
VMLINUX_OUT="/tmp/rscaller-vmlinux"
ROOTFS_OUT="/tmp/rscaller-rootfs.img"
FC_CONFIG="/tmp/fc-config.json"
GUEST_IP="172.16.0.2"
HOST_TAP_IP="172.16.0.1"
TAP_DEV="fc-tap0"
FC_MAC="06:00:AC:10:00:02"
BEACON_PORT=9999

log() { echo "==> $*"; }

# ── 1. Install deps ───────────────────────────────────────────────────────────
log "[1/5] Checking deps..."

if ! command -v firecracker &>/dev/null; then
    log "Installing Firecracker..."
    ARCH="x86_64"
    LATEST=$(basename "$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        https://github.com/firecracker-microvm/firecracker/releases/latest)")
    curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/${LATEST}/firecracker-${LATEST}-${ARCH}.tgz" \
        | tar -xz -C /tmp
    install -m755 "/tmp/release-${LATEST}-${ARCH}/firecracker-${LATEST}-${ARCH}" /usr/local/bin/firecracker
    log "Firecracker installed: $(firecracker --version 2>&1 | head -1)"
else
    log "Firecracker already installed: $(firecracker --version 2>&1 | head -1)"
fi

apt-get install -y -q e2fsprogs 2>&1 | grep -E "^(Inst|E:|Setting)" || true

# Ensure /dev/kvm accessible by current user
chmod 666 /dev/kvm 2>/dev/null || true

# ── 2. Extract vmlinux ────────────────────────────────────────────────────────
log "[2/5] Extracting vmlinux..."
KVER="$(uname -r)"
EXTRACT="$(find /usr/src -name extract-vmlinux 2>/dev/null | head -1)"

if [[ -f "$VMLINUX_OUT" ]]; then
    log "vmlinux already at $VMLINUX_OUT ($(du -h "$VMLINUX_OUT" | cut -f1)) — skipping"
else
    [[ -n "$EXTRACT" ]] || { echo "ERROR: extract-vmlinux not found"; exit 1; }
    bash "$EXTRACT" "/boot/vmlinuz-${KVER}" > "$VMLINUX_OUT"
    log "vmlinux extracted: $(du -h "$VMLINUX_OUT" | cut -f1)"
fi
file "$VMLINUX_OUT" | grep -q ELF || { echo "ERROR: $VMLINUX_OUT is not ELF"; exit 1; }

# ── 3. Build rootfs ───────────────────────────────────────────────────────────
log "[3/5] Building rootfs..."

RSBEACON="${RSCALLER_DIR}/target/release/rsbeacon"
KMOD="${RSCALLER_DIR}/kmod/rscaller.ko"

[[ -f "$RSBEACON" ]] || { echo "ERROR: rsbeacon not found at $RSBEACON — run deploy first"; exit 1; }
[[ -f "$KMOD" ]]     || { echo "ERROR: rscaller.ko not found at $KMOD — run make in kmod/ first"; exit 1; }

if [[ -f "$ROOTFS_OUT" ]]; then
    log "rootfs already at $ROOTFS_OUT ($(du -h "$ROOTFS_OUT" | cut -f1)) — skipping"
    log "  (delete $ROOTFS_OUT to force rebuild)"
else
    ROOTFS_DIR="$(mktemp -d /tmp/rscaller-rootfs-build-XXXXXX)"
    trap 'rm -rf "$ROOTFS_DIR"' EXIT

    log "  Exporting Ubuntu 22.04 via docker (glibc — matches rsbeacon binary)..."
    CID="$(docker run -d ubuntu:22.04 sh -c 'apt-get update -qq && apt-get install -y -qq iproute2 2>/dev/null; sleep 5')"
    sleep 15
    docker export "$CID" | tar -x -C "$ROOTFS_DIR" 2>/dev/null
    docker rm -f "$CID" >/dev/null

    log "  Injecting rsbeacon + rscaller.ko..."
    install -Dm755 "$RSBEACON" "$ROOTFS_DIR/usr/local/bin/rsbeacon"
    mkdir -p "$ROOTFS_DIR/lib/modules/rscaller"
    cp "$KMOD" "$ROOTFS_DIR/lib/modules/rscaller/rscaller.ko"

    # Device nodes
    for spec in "null c 1 3 666" "zero c 1 5 666" "random c 1 8 444" \
                "urandom c 1 9 444" "tty c 5 0 666" "console c 5 1 600"; do
        read -r name type major minor mode <<< "$spec"
        [[ -e "$ROOTFS_DIR/dev/$name" ]] || \
            mknod -m "$mode" "$ROOTFS_DIR/dev/$name" "$type" "$major" "$minor" 2>/dev/null || true
    done

    # /init
    cat > "$ROOTFS_DIR/init" << INITEOF
#!/bin/sh
mount -t proc    proc     /proc               2>/dev/null || true
mount -t sysfs   sysfs    /sys                2>/dev/null || true
mount -t devtmpfs devtmpfs /dev               2>/dev/null || true
mount -t tracefs tracefs  /sys/kernel/tracing 2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts  devpts   /dev/pts            2>/dev/null || true
ip link set lo up                             2>/dev/null || true
ip addr add ${GUEST_IP}/30 dev eth0           2>/dev/null || true
ip link set eth0 up                           2>/dev/null || true
ip route add default via ${HOST_TAP_IP}       2>/dev/null || true

if [ -f /lib/modules/rscaller/rscaller.ko ]; then
    echo "[init] loading rscaller kmod..."
    insmod /lib/modules/rscaller/rscaller.ko \
        && echo "[init] rscaller.ko loaded" \
        || echo "[init] WARNING: insmod failed"
else
    echo "[init] WARNING: rscaller.ko not found"
fi

echo "[init] rsbeacon starting on 0.0.0.0:${BEACON_PORT}"
exec /usr/local/bin/rsbeacon --listen 0.0.0.0:${BEACON_PORT}
INITEOF
    chmod +x "$ROOTFS_DIR/init"

    log "  Packing ext4 image (512M)..."
    mkfs.ext4 -d "$ROOTFS_DIR" -L rscaller-rootfs "$ROOTFS_OUT" 512M 2>&1 | grep -v "^$" | tail -3
    log "  rootfs: $(du -h "$ROOTFS_OUT" | cut -f1)"
fi

# ── 4. Set up tap device ──────────────────────────────────────────────────────
log "[4/5] Setting up tap device ${TAP_DEV}..."
ip link del "$TAP_DEV" 2>/dev/null || true
ip tuntap add dev "$TAP_DEV" mode tap
ip addr add "${HOST_TAP_IP}/30" dev "$TAP_DEV"
ip link set "$TAP_DEV" up
log "  tap: $(ip addr show "$TAP_DEV" | grep 'inet ')"

# ── 5. Write Firecracker config ───────────────────────────────────────────────
log "[5/5] Writing Firecracker config to $FC_CONFIG..."
cat > "$FC_CONFIG" << JSON
{
  "boot-source": {
    "kernel_image_path": "${VMLINUX_OUT}",
    "boot_args": "console=ttyS0 root=/dev/vda rw init=/init quiet panic=1 reboot=k"
  },
  "drives": [{
    "drive_id": "rootfs",
    "path_on_host": "${ROOTFS_OUT}",
    "is_root_device": true,
    "is_read_only": false
  }],
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 512
  },
  "network-interfaces": [{
    "iface_id": "net1",
    "guest_mac": "${FC_MAC}",
    "host_dev_name": "${TAP_DEV}"
  }]
}
JSON

echo ""
echo "============================================================"
echo " Bootstrap complete!"
echo " vmlinux: $VMLINUX_OUT"
echo " rootfs:  $ROOTFS_OUT"
echo " tap:     $TAP_DEV  host=$HOST_TAP_IP  guest=$GUEST_IP"
echo ""
echo " Launch Firecracker:"
echo "   firecracker --no-api --config-file $FC_CONFIG"
echo ""
echo " Once running, rsbeacon reachable at ${GUEST_IP}:${BEACON_PORT}"
echo "============================================================"
