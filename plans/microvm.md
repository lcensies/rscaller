# microVM support — status & fix plan

## Goal

`rscaller-run --microvm --microvm-kernel <vmlinux> <image>` launches an
ephemeral QEMU/Firecracker microVM, boots rsbeacon inside, proxies syscalls
through it, destroys VM on exit.

---

## What's merged (master)

| File | Description |
|------|-------------|
| `rscaller-run/src/microvm.rs` | QEMU launcher (533 lines). Injects rsbeacon into ext4 image, port-forwards beacon TCP port, polls until beacon is up. Firecracker backend stub (not implemented). |
| `rscaller-run/src/main.rs` | `--microvm`, `--microvm-backend`, `--microvm-kernel`, `--microvm-mem`, `--microvm-cpus` flags. |
| `scripts/build_microvm_image.sh` | Builds rootfs locally: extract vmlinux, snapshot tracefs, codegen, build kmod, download Alpine minirootfs, inject rsbeacon + kmod, pack ext4. |
| `scripts/microvm_bootstrap.sh` | Runs **on the VM** as root. Idempotent. Extracts vmlinux, builds Ubuntu 22.04 rootfs via docker export, sets up fc-tap0, writes `/tmp/fc-config.json`. |
| `scripts/fc_config.sh` | Emits Firecracker JSON config to stdout. |
| `scripts/test_microvm.sh` | tmux harness: deploy → build rootfs → launch QEMU → monitor beacon. |
| `kmod/Makefile` | Fixed: headers target uses `$(KDIR)` not `$(shell uname -r)`. |

---

## Current state (on dev-vm-rscaller)

| Artifact | Status |
|----------|--------|
| `/tmp/vmlinux` | ✅ 64M ELF extracted |
| `/tmp/rscaller-vmlinux` | ❌ missing (bootstrap writes here, but `/tmp/vmlinux` exists from earlier manual extraction) |
| `/tmp/rscaller-rootfs.img` | ⚠️ 512M — but **Alpine-based** (old run), rsbeacon is glibc binary → mismatch |
| `/tmp/fc-config.json` | ⚠️ references `/tmp/rscaller-vmlinux` (doesn't exist) |
| `fc-tap0` | ✅ up, host IP assigned |
| Firecracker | ✅ v1.15.1 at `/usr/local/bin/firecracker` |
| `/dev/kvm` | ✅ accessible |

---

## Known bugs

### 1. Rootfs: Alpine + glibc rsbeacon = kernel panic

rsbeacon is compiled against glibc (`/lib64/ld-linux-x86-64.so.2`).
Alpine uses musl. The binary will page-fault on first exec inside Alpine.

**Fix options** (in order of preference):
1. Add `gcompat` to Alpine rootfs — `apk add gcompat` in a chroot or via
   `docker run alpine:3.19 apk add --no-cache gcompat iproute2` then export.
   Lightweight, keeps Alpine's fast startup.
2. Switch to Ubuntu 22.04 rootfs — `microvm_bootstrap.sh` already has this
   path (docker export), just delete the existing Alpine rootfs to trigger rebuild.

### 2. fc-config.json: wrong kernel path

`microvm_bootstrap.sh` sets `VMLINUX_OUT=/tmp/rscaller-vmlinux` and skips
extraction if file exists — but `/tmp/vmlinux` exists (different path) so
bootstrap skips extraction AND writes config referencing `/tmp/rscaller-vmlinux`
which doesn't exist.

**Fix**: in bootstrap, also check if `/tmp/vmlinux` exists and symlink/copy it,
OR just delete the old file and let bootstrap re-extract to the right path.

**Immediate workaround** (on VM):
```bash
cp /tmp/vmlinux /tmp/rscaller-vmlinux
```

### 3. Networking: tap not bridged to docker0

Current setup: fc-tap0 has a standalone IP in one subnet, guest init sets
a different subnet — they can't communicate.

**Fix**: bridge fc-tap0 to docker0. Guest gets IP in docker0's subnet,
gateway = docker0 IP. docker0 provides NAT to the outside.

Script logic:
```bash
DOCKER0_IP=$(ip -4 addr show docker0 | grep -oP '(?<=inet )\d+\.\d+\.\d+\.\d+')
DOCKER0_PREFIX=$(ip -4 addr show docker0 | grep -oP '(?<=inet )[\d.]+/\d+' | cut -d/ -f2)
# Pick an IP in docker0's subnet for the guest (e.g. docker0_network + 200)
GUEST_IP=<docker0_network_base>.200
# tap: no IP needed, just bridge to docker0
ip link del fc-tap0 2>/dev/null || true
ip tuntap add dev fc-tap0 mode tap
ip link set fc-tap0 up
brctl addif docker0 fc-tap0
# Guest init: ip addr add $GUEST_IP/$PREFIX dev eth0; ip route add default via $DOCKER0_IP
```

Auto-detect host outbound interface:
```bash
HOST_IFACE=$(ip route show default | grep -oP 'dev \K\S+')
```

---

## Fix plan (ASAP — make it work)

**Step 1** (on VM, manual, 2 min):
```bash
# Fix kernel path
cp /tmp/vmlinux /tmp/rscaller-vmlinux

# Fix rootfs: delete Alpine image, rebuild with Ubuntu
rm /tmp/rscaller-rootfs.img
RSCALLER_DIR=/home/ubuntu/rscaller sudo bash /home/ubuntu/rscaller/scripts/microvm_bootstrap.sh
```

**Step 2** — fix `microvm_bootstrap.sh` persistently so it's idempotent and correct:
- Detect docker0 IP, compute guest IP in same subnet.
- Bridge tap to docker0 instead of standalone IP.
- Write guest IP + docker0 IP as gateway into `/init`.
- Check both `/tmp/vmlinux` and `/tmp/rscaller-vmlinux` when skipping extraction.

**Step 3** — launch FC and verify:
```bash
firecracker --no-api --config-file /tmp/fc-config.json
# In another pane:
nc -z $GUEST_IP 9999 && echo "beacon up"
```

**Step 4** — test rscaller-run --microvm end-to-end:
```bash
rscaller-run --microvm --microvm-kernel /tmp/rscaller-vmlinux \
  --microvm-rootfs /tmp/rscaller-rootfs.img run ls /
```

---

## Firecracker vs QEMU

`microvm.rs` implements QEMU with user-mode networking (hostfwd).
Firecracker requires tap + real networking but boots in ~125ms vs ~2s for QEMU.

For now: QEMU with `--netdev user,hostfwd=tcp::PORT-:9999` is simpler
(no tap/bridge needed for QEMU path). The `--microvm` flag in rscaller-run
uses QEMU by default.

**Recommendation**: fix the Firecracker script path for manual testing,
but keep rscaller-run using QEMU (user-mode net, no root required).
