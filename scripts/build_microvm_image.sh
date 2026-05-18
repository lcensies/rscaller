#!/usr/bin/env bash
# build_microvm_image.sh — build a guest rootfs image for rscaller microVM.
#
# Usage:
#   scripts/build_microvm_image.sh [--output rootfs.img] [--size 512M]
#
# What it does:
#   1. Fetches a minimal Alpine Linux rootfs (no Docker needed).
#   2. Injects the rsbeacon binary (built from this repo).
#   3. Writes a minimal /init that starts rsbeacon on port 9999.
#   4. Packs everything into an ext4 image.
#
# Requirements on the host:
#   curl, tar, mkfs.ext4 (e2fsprogs), sudo (for mknod/chown inside rootfs)
#
# The resulting image can be used as the rootfs for:
#   qemu-system-x86_64 -drive file=rootfs.img,format=raw,if=virtio \
#     -kernel <vmlinuz> -append "root=/dev/vda rw init=/init console=ttyS0"
#
# For a guest kernel, download a pre-built one:
#   https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTPUT_IMG="${OUTPUT_IMG:-$REPO_ROOT/microvm-rootfs.img}"
IMG_SIZE="${IMG_SIZE:-512M}"
ALPINE_VERSION="${ALPINE_VERSION:-3.19}"
ARCH="${ARCH:-x86_64}"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"

WORK_DIR="$(mktemp -d /tmp/rscaller-build-microvm-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

ROOTFS_DIR="$WORK_DIR/rootfs"
mkdir -p "$ROOTFS_DIR"

echo "==> Downloading Alpine Linux ${ALPINE_VERSION} minirootfs (${ARCH})…"
TARBALL_URL="${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ARCH}.tar.gz"
TARBALL="$WORK_DIR/alpine-minirootfs.tar.gz"
curl -fsSL -o "$TARBALL" "$TARBALL_URL"
echo "    Downloaded: $(du -h "$TARBALL" | cut -f1)"

echo "==> Extracting Alpine rootfs…"
tar -xzf "$TARBALL" -C "$ROOTFS_DIR"

echo "==> Injecting rsbeacon…"
RSBEACON="$REPO_ROOT/target/release/rsbeacon"
if [[ ! -f "$RSBEACON" ]]; then
    echo "    rsbeacon not found at $RSBEACON; building…"
    (cd "$REPO_ROOT" && cargo build -p rsbeacon --release)
fi
install -Dm755 "$RSBEACON" "$ROOTFS_DIR/usr/local/bin/rsbeacon"
echo "    rsbeacon: $(file "$ROOTFS_DIR/usr/local/bin/rsbeacon" | head -1)"

echo "==> Writing /init…"
cat > "$ROOTFS_DIR/init" << 'EOF'
#!/bin/sh
# rscaller microVM init — PID 1
mount -t proc  proc  /proc  2>/dev/null || true
mount -t sysfs sysfs /sys   2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true

# Configure loopback interface.
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true

echo "[microvm-init] starting rsbeacon on 0.0.0.0:9999"
exec /usr/local/bin/rsbeacon --listen 0.0.0.0:9999
EOF
chmod +x "$ROOTFS_DIR/init"

# Ensure essential device nodes exist (needed if devtmpfs mount fails).
echo "==> Creating essential device nodes…"
mkdir -p "$ROOTFS_DIR/dev"
[[ -c "$ROOTFS_DIR/dev/null"    ]] || mknod -m 666 "$ROOTFS_DIR/dev/null"    c 1 3  || true
[[ -c "$ROOTFS_DIR/dev/zero"    ]] || mknod -m 666 "$ROOTFS_DIR/dev/zero"    c 1 5  || true
[[ -c "$ROOTFS_DIR/dev/random"  ]] || mknod -m 444 "$ROOTFS_DIR/dev/random"  c 1 8  || true
[[ -c "$ROOTFS_DIR/dev/urandom" ]] || mknod -m 444 "$ROOTFS_DIR/dev/urandom" c 1 9  || true
[[ -c "$ROOTFS_DIR/dev/tty"     ]] || mknod -m 666 "$ROOTFS_DIR/dev/tty"     c 5 0  || true
[[ -c "$ROOTFS_DIR/dev/console" ]] || mknod -m 600 "$ROOTFS_DIR/dev/console" c 5 1  || true

echo "==> Packing ext4 image → $OUTPUT_IMG (${IMG_SIZE})…"
# mkfs.ext4 -d populates the image from the directory.
mkfs.ext4 -d "$ROOTFS_DIR" -L rootfs "$OUTPUT_IMG" "$IMG_SIZE"

echo ""
echo "==> Done!  Image: $OUTPUT_IMG ($(du -h "$OUTPUT_IMG" | cut -f1))"
echo ""
echo "To use with rscaller-run:"
echo "  export RSCALLER_KERNEL=/path/to/vmlinuz-guest"
echo "  rscaller-run --image ignored --microvm --microvm-kernel \$RSCALLER_KERNEL \\"
echo "               --microvm-mem 512 -- /bin/sh"
echo ""
echo "To get a guest kernel (Firecracker pre-built):"
echo "  curl -fsSL https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin \\"
echo "    -o /tmp/vmlinux-guest.bin"
