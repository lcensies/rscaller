#!/usr/bin/env bash
# build_microvm_image.sh — build a guest rootfs ext4 image for rscaller microVM.
#
# The image contains:
#   - Alpine Linux minirootfs base
#   - rscaller kmod (.ko) compiled for GUEST_KERNEL_VERSION
#   - rsbeacon binary (injected from host build)
#   - tracefs format files snapshotted from TRACEFS_HOST (or locally)
#   - syscall codegen run to produce kmod/syscalls.c for the target kernel
#   - Minimal /init: insmod rscaller.ko → start rsbeacon
#
# Usage:
#   bash scripts/build_microvm_image.sh [options]
#
# Options (env vars):
#   OUTPUT_IMG          path for output .img        [./microvm-rootfs.img]
#   IMG_SIZE            ext4 image size              [768M]
#   ALPINE_VERSION      Alpine base version          [3.19]
#   GUEST_KERNEL_VER    kernel version string        [auto-detect from TRACEFS_HOST]
#   TRACEFS_HOST        host to snapshot tracefs from; "localhost" = local [localhost]
#   BUILD_KMOD          1=build kmod, 0=skip         [1]
#   SKIP_CODEGEN        1=skip codegen               [0]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTPUT_IMG="${OUTPUT_IMG:-$REPO_ROOT/microvm-rootfs.img}"
IMG_SIZE="${IMG_SIZE:-768M}"
ALPINE_VERSION="${ALPINE_VERSION:-3.19}"
ARCH="${ARCH:-x86_64}"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
TRACEFS_HOST="${TRACEFS_HOST:-localhost}"
BUILD_KMOD="${BUILD_KMOD:-1}"
SKIP_CODEGEN="${SKIP_CODEGEN:-0}"

WORK_DIR="$(mktemp -d /tmp/rscaller-build-microvm-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

ROOTFS_DIR="$WORK_DIR/rootfs"
mkdir -p "$ROOTFS_DIR"

# ── helpers ───────────────────────────────────────────────────────────────────
is_local() { [[ "$TRACEFS_HOST" == "localhost" || "$TRACEFS_HOST" == "127.0.0.1" ]]; }

remote_cmd() {
    if is_local; then bash -c "$*"; else ssh "$TRACEFS_HOST" "$*"; fi
}
remote_cat() {
    if is_local; then cat "$1"; else ssh "$TRACEFS_HOST" "cat '$1'"; fi
}

# ── 1. Detect guest kernel version ───────────────────────────────────────────
if [[ -z "${GUEST_KERNEL_VER:-}" ]]; then
    echo "==> Detecting kernel version from $TRACEFS_HOST..."
    GUEST_KERNEL_VER="$(remote_cmd 'uname -r')"
    echo "    Detected: $GUEST_KERNEL_VER"
fi

# ── 2. Snapshot tracefs format files ─────────────────────────────────────────
echo "==> Snapshotting tracefs syscall format files from $TRACEFS_HOST..."
TRACEFS_DIR="$WORK_DIR/tracefs"
mkdir -p "$TRACEFS_DIR"

FORWARDED_FILE="$REPO_ROOT/files/forwarded_syscalls"
mapfile -t SYSCALLS < <(grep -v '^\s*#' "$FORWARDED_FILE" | grep -v '^\s*$')

for name in "${SYSCALLS[@]}"; do
    remote_path="/sys/kernel/tracing/events/syscalls/sys_enter_${name}/format"
    local_dir="$TRACEFS_DIR/sys_enter_${name}"
    mkdir -p "$local_dir"
    if remote_cat "$remote_path" > "$local_dir/format" 2>/dev/null && [[ -s "$local_dir/format" ]]; then
        echo "    [ok] $name"
    else
        echo "    [warn] $name: no tracefs format (hardcoded fallback)"
        rm -f "$local_dir/format"
        rmdir "$local_dir" 2>/dev/null || true
    fi
done

# ── 3. Run codegen ────────────────────────────────────────────────────────────
if [[ "$SKIP_CODEGEN" != "1" ]]; then
    echo "==> Running codegen for kernel $GUEST_KERNEL_VER..."
    (cd "$REPO_ROOT" && cargo run -p codegen --release -- \
        --tbl-dir files \
        --forwarded files/forwarded_syscalls \
        --tracefs-dir "$TRACEFS_DIR" \
        --out kmod)
    echo "    codegen complete — kmod/syscalls.c regenerated"
else
    echo "==> Skipping codegen (SKIP_CODEGEN=1)"
fi

# ── 4. Build rscaller kmod ───────────────────────────────────────────────────
KMOD_KO="$REPO_ROOT/kmod/rscaller.ko"

if [[ "$BUILD_KMOD" == "1" ]]; then
    echo "==> Building rscaller.ko for kernel $GUEST_KERNEL_VER..."
    if is_local; then
        echo "    Building kmod locally..."
        (cd "$REPO_ROOT/kmod" && make clean 2>/dev/null || true && make -j"$(nproc)")
    else
        echo "    Syncing source to $TRACEFS_HOST..."
        rsync -az --exclude target --exclude '.git' \
            "$REPO_ROOT/" "$TRACEFS_HOST:/tmp/rscaller-kmod-build/"
        echo "    Building on $TRACEFS_HOST..."
        ssh "$TRACEFS_HOST" 'set -e; cd /tmp/rscaller-kmod-build/kmod; make clean 2>/dev/null || true; make -j$(nproc)'
        echo "    Fetching rscaller.ko..."
        scp "$TRACEFS_HOST:/tmp/rscaller-kmod-build/kmod/rscaller.ko" "$KMOD_KO"
    fi
    echo "    kmod built: $(file "$KMOD_KO" | head -1)"
else
    echo "==> Skipping kmod build (BUILD_KMOD=0)"
    [[ -f "$KMOD_KO" ]] || echo "    WARNING: $KMOD_KO not found — image will lack the kernel module"
fi

# ── 5. Build rsbeacon ─────────────────────────────────────────────────────────
echo "==> Building rsbeacon (release)..."
RSBEACON="$REPO_ROOT/target/release/rsbeacon"
if [[ ! -f "$RSBEACON" ]]; then
    (cd "$REPO_ROOT" && cargo build -p rsbeacon --release)
fi
echo "    rsbeacon: $(du -h "$RSBEACON" | cut -f1)"

# ── 6. Fetch Alpine minirootfs ────────────────────────────────────────────────
echo "==> Downloading Alpine Linux ${ALPINE_VERSION} minirootfs (${ARCH})..."
TARBALL_URL="${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ARCH}.tar.gz"
TARBALL="$WORK_DIR/alpine-minirootfs.tar.gz"
curl -fsSL -o "$TARBALL" "$TARBALL_URL"
echo "    Downloaded: $(du -h "$TARBALL" | cut -f1)"
tar -xzf "$TARBALL" -C "$ROOTFS_DIR"

# ── 7. Inject binaries ────────────────────────────────────────────────────────
echo "==> Injecting binaries..."
install -Dm755 "$RSBEACON" "$ROOTFS_DIR/usr/local/bin/rsbeacon"
KMOD_GUEST_DIR="$ROOTFS_DIR/lib/modules/rscaller"
mkdir -p "$KMOD_GUEST_DIR"
if [[ -f "$KMOD_KO" ]]; then
    cp "$KMOD_KO" "$KMOD_GUEST_DIR/rscaller.ko"
    echo "    rscaller.ko injected"
else
    echo "    WARNING: rscaller.ko missing — skipped"
fi

# ── 8. Enable tracefs in guest ────────────────────────────────────────────────
mkdir -p "$ROOTFS_DIR/etc"
cat >> "$ROOTFS_DIR/etc/fstab" << 'EOF'
tracefs  /sys/kernel/tracing  tracefs  defaults  0  0
EOF

# ── 9. Write /init ────────────────────────────────────────────────────────────
echo "==> Writing /init..."
cat > "$ROOTFS_DIR/init" << 'INITEOF'
#!/bin/sh
# rscaller microVM init — PID 1
mount -t proc    proc    /proc              2>/dev/null || true
mount -t sysfs   sysfs   /sys               2>/dev/null || true
mount -t devtmpfs devtmpfs /dev             2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts             2>/dev/null || true
ip link set lo up                           2>/dev/null || true

if [ -f /lib/modules/rscaller/rscaller.ko ]; then
    echo "[init] loading rscaller kmod..."
    insmod /lib/modules/rscaller/rscaller.ko && \
        echo "[init] rscaller.ko loaded" || \
        echo "[init] WARNING: insmod failed"
else
    echo "[init] WARNING: rscaller.ko not found"
fi

echo "[init] starting rsbeacon on 0.0.0.0:9999"
exec /usr/local/bin/rsbeacon --listen 0.0.0.0:9999
INITEOF
chmod +x "$ROOTFS_DIR/init"

# ── 10. Essential device nodes ────────────────────────────────────────────────
mkdir -p "$ROOTFS_DIR/dev"
for spec in "null c 1 3 666" "zero c 1 5 666" "random c 1 8 444" \
            "urandom c 1 9 444" "tty c 5 0 666" "console c 5 1 600"; do
    read -r name type major minor mode <<< "$spec"
    [[ -e "$ROOTFS_DIR/dev/$name" ]] || \
        mknod -m "$mode" "$ROOTFS_DIR/dev/$name" "$type" "$major" "$minor" 2>/dev/null || true
done

# ── 11. Embed tracefs snapshot ────────────────────────────────────────────────
GUEST_TRACEFS_DIR="$ROOTFS_DIR/usr/share/rscaller/tracefs"
mkdir -p "$GUEST_TRACEFS_DIR"
[[ -d "$TRACEFS_DIR" ]] && cp -r "$TRACEFS_DIR"/. "$GUEST_TRACEFS_DIR/"
echo "    Embedded $(find "$GUEST_TRACEFS_DIR" -name format 2>/dev/null | wc -l) tracefs format files"

# ── 12. Pack ext4 image ───────────────────────────────────────────────────────
echo "==> Packing ext4 image -> $OUTPUT_IMG ($IMG_SIZE)..."
mkfs.ext4 -d "$ROOTFS_DIR" -L rscaller-rootfs "$OUTPUT_IMG" "$IMG_SIZE"

echo ""
echo "============================================================"
echo " microVM rootfs image built successfully"
echo "============================================================"
echo " Image:          $OUTPUT_IMG ($(du -h "$OUTPUT_IMG" | cut -f1))"
echo " Alpine:         $ALPINE_VERSION"
echo " Kernel target:  $GUEST_KERNEL_VER"
echo " kmod injected:  $([ -f "$KMOD_GUEST_DIR/rscaller.ko" ] && echo YES || echo NO)"
echo ""
echo " To test with QEMU:"
echo "   qemu-system-x86_64 -M microvm,x-option-roms=off,pit=off,pic=off,isa-serial=on,rtc=off \\"
echo "     -enable-kvm -cpu host -m 512M -smp 1 \\"
echo "     -kernel /tmp/vmlinux-guest.bin \\"
echo "     -append 'console=ttyS0 root=/dev/vda rw init=/init quiet' \\"
echo "     -drive id=rootfs,file=$OUTPUT_IMG,format=raw,if=virtio \\"
echo "     -netdev user,id=net0,hostfwd=tcp::9999-:9999 \\"
echo "     -device virtio-net-device,netdev=net0 \\"
echo "     -nographic -serial stdio"
echo "============================================================"
