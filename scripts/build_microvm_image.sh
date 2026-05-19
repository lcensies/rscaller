#!/usr/bin/env bash
# build_microvm_image.sh — build Firecracker rootfs + extract host vmlinux for rscaller.
#
# Strategy (simple, reliable):
#   - Extract uncompressed vmlinux from the host's /boot/vmlinuz (same kernel the VM runs)
#   - Build rscaller.ko against the host's kernel headers (already installed)
#   - Alpine minirootfs as guest userspace
#   - /init: insmod rscaller.ko -> exec rsbeacon
#
# Outputs:
#   $OUTPUT_IMG   — ext4 rootfs image  (default: ./microvm-rootfs.img)
#   $KERNEL_OUT   — vmlinux kernel     (default: ./microvm-vmlinux)
#
# Usage (must run as root or with sudo for mknod + mkfs.ext4 -d):
#   sudo bash scripts/build_microvm_image.sh
#
# Env overrides:
#   OUTPUT_IMG      [./microvm-rootfs.img]
#   KERNEL_OUT      [./microvm-vmlinux]
#   IMG_SIZE        [512M]
#   ALPINE_VERSION  [3.19]
#   SKIP_KMOD_BUILD 1 = skip kmod build  [0]
#   SKIP_CODEGEN    1 = skip codegen     [0]

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Cargo PATH
export PATH="${HOME}/.cargo/bin:/home/ubuntu/.cargo/bin:${PATH}"

KERNEL_VER="$(uname -r)"
VMLINUZ="/boot/vmlinuz-${KERNEL_VER}"
EXTRACT_VMLINUX="/usr/src/linux-headers-${KERNEL_VER}/scripts/extract-vmlinux"
OUTPUT_IMG="${OUTPUT_IMG:-${REPO_ROOT}/microvm-rootfs.img}"
KERNEL_OUT="${KERNEL_OUT:-${REPO_ROOT}/microvm-vmlinux}"
IMG_SIZE="${IMG_SIZE:-512M}"
ALPINE_VERSION="${ALPINE_VERSION:-3.19}"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"
ARCH="x86_64"
SKIP_KMOD_BUILD="${SKIP_KMOD_BUILD:-0}"
SKIP_CODEGEN="${SKIP_CODEGEN:-0}"

WORK_DIR="$(mktemp -d /tmp/rscaller-microvm-XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "============================================================"
echo " rscaller microVM image builder"
echo " Host kernel:  $KERNEL_VER"
echo " vmlinuz:      $VMLINUZ"
echo " Rootfs out:   $OUTPUT_IMG ($IMG_SIZE)"
echo " vmlinux out:  $KERNEL_OUT"
echo "============================================================"

# ── 1. Extract uncompressed vmlinux from vmlinuz ──────────────────────────────
echo "==> [1/7] Extracting vmlinux from $VMLINUZ..."
if [[ ! -f "$EXTRACT_VMLINUX" ]]; then
    echo "    extract-vmlinux not found at $EXTRACT_VMLINUX"
    echo "    Trying /usr/src/linux-headers-${KERNEL_VER%%-*}/scripts/extract-vmlinux..."
    EXTRACT_VMLINUX="$(find /usr/src -name extract-vmlinux 2>/dev/null | head -1)"
    [[ -f "$EXTRACT_VMLINUX" ]] || { echo "ERROR: extract-vmlinux not found"; exit 1; }
fi
bash "$EXTRACT_VMLINUX" "$VMLINUZ" > "$KERNEL_OUT"
echo "    vmlinux: $(du -h "$KERNEL_OUT" | cut -f1) — $(file "$KERNEL_OUT" | cut -d, -f1)"

# ── 2. Snapshot tracefs format files ─────────────────────────────────────────
echo "==> [2/7] Snapshotting tracefs format files..."
TRACEFS_DIR="$WORK_DIR/tracefs"
mkdir -p "$TRACEFS_DIR"
FORWARDED_FILE="$REPO_ROOT/files/forwarded_syscalls"
mapfile -t SYSCALLS < <(grep -v '^\s*#' "$FORWARDED_FILE" | grep -v '^\s*$')

for name in "${SYSCALLS[@]}"; do
    fmt="/sys/kernel/tracing/events/syscalls/sys_enter_${name}/format"
    dir="$TRACEFS_DIR/sys_enter_${name}"
    mkdir -p "$dir"
    if cat "$fmt" > "$dir/format" 2>/dev/null && [[ -s "$dir/format" ]]; then
        echo "    [ok] $name"
    else
        echo "    [warn] $name: not readable — hardcoded fallback"
        rm -f "$dir/format"; rmdir "$dir" 2>/dev/null || true
    fi
done

# ── 3. Run codegen ────────────────────────────────────────────────────────────
if [[ "$SKIP_CODEGEN" != "1" ]]; then
    echo "==> [3/7] Running codegen for kernel $KERNEL_VER..."
    (cd "$REPO_ROOT" && cargo run -p codegen --release -- \
        --tbl-dir files \
        --forwarded files/forwarded_syscalls \
        --tracefs-dir "$TRACEFS_DIR" \
        --out kmod)
    echo "    codegen done"
else
    echo "==> [3/7] Skipping codegen"
fi

# ── 4. Build kmod against host headers ───────────────────────────────────────
KMOD_KO="$REPO_ROOT/kmod/rscaller.ko"

if [[ "$SKIP_KMOD_BUILD" != "1" ]]; then
    echo "==> [4/7] Building rscaller.ko against kernel $KERNEL_VER headers..."
    KDIR="/lib/modules/${KERNEL_VER}/build"
    [[ -d "$KDIR" ]] || { echo "ERROR: kernel headers not found at $KDIR"; exit 1; }
    (cd "$REPO_ROOT/kmod" && make -B -j"$(nproc)" KDIR="$KDIR" 2>&1)
    [[ -f "$KMOD_KO" ]] || { echo "ERROR: rscaller.ko not produced"; exit 1; }
    echo "    kmod: $(file "$KMOD_KO" | cut -d, -f1-2)"
else
    echo "==> [4/7] Skipping kmod build"
    [[ -f "$KMOD_KO" ]] || { echo "ERROR: $KMOD_KO missing"; exit 1; }
fi

# ── 5. Build rsbeacon ─────────────────────────────────────────────────────────
echo "==> [5/7] Building rsbeacon..."
RSBEACON="$REPO_ROOT/target/release/rsbeacon"
[[ -f "$RSBEACON" ]] || (cd "$REPO_ROOT" && cargo build -p rsbeacon --release)
echo "    rsbeacon: $(du -h "$RSBEACON" | cut -f1)"

# ── 6. Assemble Alpine rootfs ─────────────────────────────────────────────────
echo "==> [6/7] Assembling Alpine rootfs..."
ROOTFS="$WORK_DIR/rootfs"
mkdir -p "$ROOTFS"

echo "    Downloading Alpine ${ALPINE_VERSION}..."
curl -fsSL -o "$WORK_DIR/alpine.tar.gz" \
    "${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/${ARCH}/alpine-minirootfs-${ALPINE_VERSION}.0-${ARCH}.tar.gz"
tar -xzf "$WORK_DIR/alpine.tar.gz" -C "$ROOTFS"

# Inject rsbeacon
install -Dm755 "$RSBEACON" "$ROOTFS/usr/local/bin/rsbeacon"

# Inject kmod
KMOD_GUEST_DIR="$ROOTFS/lib/modules/rscaller"
mkdir -p "$KMOD_GUEST_DIR"
cp "$KMOD_KO" "$KMOD_GUEST_DIR/rscaller.ko"
echo "    kmod injected: $(du -h "$KMOD_GUEST_DIR/rscaller.ko" | cut -f1)"

# Device nodes
mkdir -p "$ROOTFS/dev"
for spec in "null c 1 3 666" "zero c 1 5 666" "random c 1 8 444" \
            "urandom c 1 9 444" "tty c 5 0 666" "console c 5 1 600"; do
    read -r name type major minor mode <<< "$spec"
    [[ -e "$ROOTFS/dev/$name" ]] || mknod -m "$mode" "$ROOTFS/dev/$name" "$type" "$major" "$minor" 2>/dev/null || true
done

# /init
cat > "$ROOTFS/init" << 'INITEOF'
#!/bin/sh
mount -t proc    proc    /proc                2>/dev/null || true
mount -t sysfs   sysfs   /sys                 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev               2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing  2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts               2>/dev/null || true
ip link set lo up                             2>/dev/null || true
# Bring up eth0 with static IP (Firecracker tap networking)
ip addr add 172.16.0.2/30 dev eth0            2>/dev/null || true
ip link set eth0 up                           2>/dev/null || true
ip route add default via 172.16.0.1           2>/dev/null || true

if [ -f /lib/modules/rscaller/rscaller.ko ]; then
    echo "[init] loading rscaller kmod..."
    insmod /lib/modules/rscaller/rscaller.ko \
        && echo "[init] rscaller.ko loaded" \
        || echo "[init] WARNING: insmod failed"
else
    echo "[init] WARNING: rscaller.ko not found"
fi

echo "[init] starting rsbeacon on 0.0.0.0:9999"
exec /usr/local/bin/rsbeacon --listen 0.0.0.0:9999
INITEOF
chmod +x "$ROOTFS/init"

# ── 7. Pack ext4 image ────────────────────────────────────────────────────────
echo "==> [7/7] Packing ext4 image -> $OUTPUT_IMG ($IMG_SIZE)..."
rm -f "$OUTPUT_IMG"
mkfs.ext4 -d "$ROOTFS" -L rscaller-rootfs "$OUTPUT_IMG" "$IMG_SIZE"

echo ""
echo "============================================================"
echo " Build complete!"
echo " vmlinux:  $KERNEL_OUT  ($(du -h "$KERNEL_OUT" | cut -f1))"
echo " rootfs:   $OUTPUT_IMG  ($(du -h "$OUTPUT_IMG" | cut -f1))"
echo " kernel:   $KERNEL_VER"
echo "============================================================"
