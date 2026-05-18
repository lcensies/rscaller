#!/usr/bin/env bash
# rscaller-microvm-test.sh
# tmux harness: build microVM rootfs image on dev-vm-rscaller, then test it.

set -euo pipefail

REMOTE="dev-vm-rscaller"
BEACON_HOST="dev-vm-rscaller-clone"
REMOTE_DIR="/home/ubuntu/rscaller"
BEACON_PORT=9999
SESSION="rscaller"
WIN="microvm-test"
BECOME_PASS="${BECOME_PASS:-ubuntu}"
REPO_ROOT="/home/esc/repos/rscaller__worktrees/feature-microvm"
SENTINEL="/tmp/rscaller-microvm-build-done"

# Resolve beacon IP
BEACON_IP="$(ssh "$BEACON_HOST" 'hostname -I 2>/dev/null' | awk '{print $1}')"
echo "==> Beacon host: $BEACON_HOST ($BEACON_IP:$BEACON_PORT)"

# ── Pane 1 script ─────────────────────────────────────────────────────────────
python3 - "$REMOTE" "$REMOTE_DIR" "$BEACON_HOST" "$BEACON_IP" "$BEACON_PORT" "$BECOME_PASS" "$REPO_ROOT" "$SENTINEL" << 'PYEOF'
import sys, os
REMOTE, REMOTE_DIR, BEACON_HOST, BEACON_IP, BEACON_PORT, BECOME_PASS, REPO_ROOT, SENTINEL = sys.argv[1:]

script = f"""#!/usr/bin/env bash
set -euo pipefail
rm -f '{SENTINEL}'

echo "==> [1/6] Deploying rscaller to {REMOTE}..."
BECOME_PASS='{BECOME_PASS}' bash '{REPO_ROOT}/scripts/deploy.sh' '{REMOTE}' '{REMOTE_DIR}'

echo "==> [2/6] Downloading Firecracker guest kernel on {REMOTE}..."
ssh '{REMOTE}' 'VMKERNEL=/tmp/vmlinux-guest.bin; if [ ! -f "$VMKERNEL" ]; then curl -fsSL https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin -o "$VMKERNEL" && echo "Downloaded: $(du -h $VMKERNEL | cut -f1)"; else echo "Already present: $(du -h $VMKERNEL | cut -f1)"; fi'

echo "==> [3/6] Installing build deps on {REMOTE} (qemu, e2fsprogs)..."
ssh '{REMOTE}' 'sudo apt-get install -y -q qemu-system-x86 e2fsprogs 2>&1 | tail -3'

echo "==> [4/6] Building microVM rootfs image on {REMOTE}..."
ssh '{REMOTE}' 'cd {REMOTE_DIR} && TRACEFS_HOST=localhost BUILD_KMOD=1 SKIP_CODEGEN=0 OUTPUT_IMG=/tmp/rscaller-microvm-rootfs.img IMG_SIZE=768M bash scripts/build_microvm_image.sh'

echo "==> [5/6] Starting rsbeacon on {BEACON_HOST}..."
ssh -n '{BEACON_HOST}' 'pkill rsbeacon 2>/dev/null || true; sleep 0.3' || true
ssh -fn '{BEACON_HOST}' '{REMOTE_DIR}/target/release/rsbeacon --listen 0.0.0.0:{BEACON_PORT} > /tmp/rsbeacon.log 2>&1' || true

touch '{SENTINEL}'

echo "==> [6/6] Launching QEMU microVM on {REMOTE}..."
echo "    Kernel: /tmp/vmlinux-guest.bin"
echo "    Rootfs: /tmp/rscaller-microvm-rootfs.img"
echo "    Port 9999 → guest rsbeacon"
echo ""
ssh '{REMOTE}' 'sudo qemu-system-x86_64 -M microvm,x-option-roms=off,pit=off,pic=off,isa-serial=on,rtc=off -enable-kvm -cpu host -m 512M -smp 1 -kernel /tmp/vmlinux-guest.bin -append "console=ttyS0 root=/dev/vda rw init=/init quiet" -drive id=rootfs,file=/tmp/rscaller-microvm-rootfs.img,format=raw,if=virtio -netdev user,id=net0,hostfwd=tcp::9999-:9999 -device virtio-net-device,netdev=net0 -nographic -serial stdio'
"""
with open('/tmp/rscaller-microvm-pane1.sh', 'w') as f:
    f.write(script)
os.chmod('/tmp/rscaller-microvm-pane1.sh', 0o755)
print("pane1 written")
PYEOF

# ── Pane 2 script ─────────────────────────────────────────────────────────────
python3 - "$REMOTE" "$SENTINEL" << 'PYEOF'
import sys, os
REMOTE, SENTINEL = sys.argv[1:]
script = f"""#!/usr/bin/env bash
echo "Waiting for build to finish..."
until test -f '{SENTINEL}'; do sleep 1; done
echo "==> dmesg -w on {REMOTE} (rscaller + microVM messages)..."
ssh '{REMOTE}' 'sudo dmesg -w 2>/dev/null | grep --line-buffered -i -E "rscaller|microvm|init|rsbeacon|kmod"'
"""
with open('/tmp/rscaller-microvm-pane2.sh', 'w') as f:
    f.write(script)
os.chmod('/tmp/rscaller-microvm-pane2.sh', 0o755)
print("pane2 written")
PYEOF

# ── Pane 3 script ─────────────────────────────────────────────────────────────
python3 - "$BEACON_HOST" "$BEACON_IP" "$BEACON_PORT" "$REMOTE" "$SENTINEL" << 'PYEOF'
import sys, os
BEACON_HOST, BEACON_IP, BEACON_PORT, REMOTE, SENTINEL = sys.argv[1:]
script = f"""#!/usr/bin/env bash
echo "Waiting for build to finish..."
until test -f '{SENTINEL}'; do sleep 1; done
echo "==> Monitoring rsbeacon on {BEACON_HOST} ({BEACON_IP}:{BEACON_PORT})..."
echo ""
echo "Polling rsbeacon port..."
until ssh -n '{BEACON_HOST}' "bash -c '</dev/tcp/127.0.0.1/{BEACON_PORT}'" 2>/dev/null; do
    printf '.'; sleep 0.5
done
echo ""
echo "rsbeacon UP on {BEACON_HOST}!"
echo ""
echo "Testing {REMOTE} -> {BEACON_IP}:{BEACON_PORT}..."
ssh '{REMOTE}' "bash -c '</dev/tcp/{BEACON_IP}/{BEACON_PORT}' 2>/dev/null && echo 'REACHABLE from {REMOTE}' || echo 'NOT REACHABLE from {REMOTE}'"
echo ""
echo "==> Tailing rsbeacon log..."
ssh '{BEACON_HOST}' 'tail -f /tmp/rsbeacon.log 2>/dev/null || sleep infinity'
"""
with open('/tmp/rscaller-microvm-pane3.sh', 'w') as f:
    f.write(script)
os.chmod('/tmp/rscaller-microvm-pane3.sh', 0o755)
print("pane3 written")
PYEOF

# ── Create tmux window ────────────────────────────────────────────────────────
tmux kill-window -t "$SESSION:$WIN" 2>/dev/null || true
sleep 0.1

tmux new-window   -t "$SESSION:" -n "$WIN" -c "$REPO_ROOT" -d
tmux split-window -t "$SESSION:$WIN.1" -h -c "$REPO_ROOT"
tmux split-window -t "$SESSION:$WIN.2" -v -c "$REPO_ROOT"
tmux resize-pane  -t "$SESSION:$WIN.1" -x "55%"

tmux send-keys -t "$SESSION:$WIN.1" "bash /tmp/rscaller-microvm-pane1.sh 2>&1 | tee /tmp/rscaller-microvm-build.log" Enter
tmux send-keys -t "$SESSION:$WIN.2" "bash /tmp/rscaller-microvm-pane2.sh" Enter
tmux send-keys -t "$SESSION:$WIN.3" "bash /tmp/rscaller-microvm-pane3.sh" Enter

echo "==> Window '$WIN' ready"
tmux select-window -t "$SESSION:$WIN"
tmux select-pane   -t "$SESSION:$WIN.1"
