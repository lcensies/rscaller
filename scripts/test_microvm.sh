#!/usr/bin/env bash
# rscaller-microvm-test.sh
# tmux harness: build microVM rootfs image on dev-vm-rscaller, then test it.
#
# Layout (window: microvm-test):
#   pane 1 (left)  : build steps + QEMU microVM launch on dev-vm-rscaller
#   pane 2 (right-top) : dmesg -w on dev-vm-rscaller (kmod messages)
#   pane 3 (right-bot) : rsbeacon on dev-vm-rscaller-clone (the "remote" beacon)
#
# dev-vm-rscaller  = the kmod host + microVM host
# dev-vm-rscaller-clone = rsbeacon host (remote filesystem target)

set -euo pipefail

REMOTE="dev-vm-rscaller"
BEACON_HOST="dev-vm-rscaller-clone"
REMOTE_DIR="/home/ubuntu/rscaller"
BEACON_PORT=9999
SESSION="rscaller"
WIN="microvm-test"
BECOME_PASS="${BECOME_PASS:-ubuntu}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="/tmp/rscaller-microvm-build-done"

# ── Resolve IPs ──────────────────────────────────────────────────────────────
BEACON_IP="$(ssh "$BEACON_HOST" 'hostname -I 2>/dev/null' | awk '{print $1}')"
echo "==> Beacon host: $BEACON_HOST ($BEACON_IP:$BEACON_PORT)"

# ── Write per-pane scripts ───────────────────────────────────────────────────

# Pane 1: deploy + build microVM image + download kernel + launch QEMU
cat > /tmp/rscaller-microvm-pane1.sh << SCRIPT
#!/usr/bin/env bash
set -euo pipefail
rm -f '${SENTINEL}'

echo "==> [1/6] Deploying rscaller to $REMOTE…"
BECOME_PASS='${BECOME_PASS}' bash '${REPO_ROOT}/scripts/deploy.sh' '${REMOTE}' '${REMOTE_DIR}'

echo "==> [2/6] Downloading Firecracker guest kernel on $REMOTE…"
ssh '${REMOTE}' '
    KERNEL=/tmp/vmlinux-guest.bin
    if [ ! -f "$KERNEL" ]; then
        echo "Downloading vmlinux…"
        curl -fsSL https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin -o "$KERNEL"
        echo "Downloaded: $(du -h $KERNEL | cut -f1)"
    else
        echo "Kernel already present: $(du -h $KERNEL | cut -f1)"
    fi
'

echo "==> [3/6] Installing build deps on $REMOTE (qemu, e2fsprogs)…"
ssh '${REMOTE}' '
    sudo apt-get install -y -q qemu-system-x86 e2fsprogs 2>&1 | tail -3
'

echo "==> [4/6] Building microVM rootfs image on $REMOTE…"
ssh '${REMOTE}' "
    cd '${REMOTE_DIR}'
    TRACEFS_HOST=localhost BUILD_KMOD=1 SKIP_CODEGEN=0 \
    OUTPUT_IMG=/tmp/rscaller-microvm-rootfs.img \
    IMG_SIZE=768M \
    bash scripts/build_microvm_image.sh
"

echo "==> [5/6] Starting rsbeacon on $BEACON_HOST…"
ssh -n '${BEACON_HOST}' 'pkill rsbeacon 2>/dev/null || true; sleep 0.3' || true
ssh -f '${BEACON_HOST}' "'${REMOTE_DIR}/target/release/rsbeacon' --listen 0.0.0.0:'${BEACON_PORT}'" || true

touch '${SENTINEL}'

echo "==> [6/6] Launching QEMU microVM on $REMOTE…"
echo "    Kernel: /tmp/vmlinux-guest.bin"
echo "    Rootfs: /tmp/rscaller-microvm-rootfs.img"
echo "    Port-forward: localhost:9999 → guest:9999"
echo ""
ssh '${REMOTE}' "
    sudo qemu-system-x86_64 \
      -M microvm,x-option-roms=off,pit=off,pic=off,isa-serial=on,rtc=off \
      -enable-kvm -cpu host \
      -m 512M -smp 1 \
      -kernel /tmp/vmlinux-guest.bin \
      -append 'console=ttyS0 root=/dev/vda rw init=/init quiet' \
      -drive id=rootfs,file=/tmp/rscaller-microvm-rootfs.img,format=raw,if=virtio \
      -netdev user,id=net0,hostfwd=tcp::9999-:9999 \
      -device virtio-net-device,netdev=net0 \
      -nographic -serial stdio
"
SCRIPT

# Pane 2: dmesg on REMOTE (watch for kmod messages from inside microVM)
cat > /tmp/rscaller-microvm-pane2.sh << SCRIPT
#!/usr/bin/env bash
echo "Waiting for build…"
until test -f '${SENTINEL}'; do sleep 1; done
echo "==> dmesg -w on $REMOTE (watching for microVM + rscaller messages)…"
ssh '${REMOTE}' 'sudo dmesg -w 2>/dev/null | grep --line-buffered -i -E "rscaller|microvm|init|rsbeacon"'
SCRIPT

# Pane 3: verify rsbeacon on clone + watch its output
cat > /tmp/rscaller-microvm-pane3.sh << SCRIPT
#!/usr/bin/env bash
echo "Waiting for build…"
until test -f '${SENTINEL}'; do sleep 1; done
echo "==> Tailing rsbeacon on $BEACON_HOST ($BEACON_IP:$BEACON_PORT)…"
echo ""

# Poll until rsbeacon port is open (guest microVM connects to beacon from REMOTE)
echo "Waiting for rsbeacon port on $BEACON_HOST…"
until ssh -n '${BEACON_HOST}' "bash -c '</dev/tcp/127.0.0.1/${BEACON_PORT}'" 2>/dev/null; do
    sleep 0.5
done
echo "rsbeacon is up on $BEACON_HOST!"
echo ""

# Also test connectivity from REMOTE to BEACON_HOST
echo "Testing $REMOTE → $BEACON_IP:$BEACON_PORT…"
ssh '${REMOTE}' "bash -c '</dev/tcp/${BEACON_IP}/${BEACON_PORT}' 2>/dev/null && echo 'REACHABLE' || echo 'NOT REACHABLE'"

echo ""
echo "==> Watching rsbeacon log on $BEACON_HOST…"
ssh '${BEACON_HOST}' 'tail -f /tmp/rsbeacon.log 2>/dev/null || journalctl -f -u rsbeacon 2>/dev/null || sleep infinity'
SCRIPT

chmod +x /tmp/rscaller-microvm-pane{1,2,3}.sh

# ── Create tmux window ────────────────────────────────────────────────────────
tmux kill-window -t "$SESSION:$WIN" 2>/dev/null || true
sleep 0.1

tmux new-window  -t "$SESSION:" -n "$WIN" -c "$REPO_ROOT" -d
tmux split-window -t "$SESSION:$WIN.1" -h -c "$REPO_ROOT"
tmux split-window -t "$SESSION:$WIN.2" -v -c "$REPO_ROOT"
tmux resize-pane  -t "$SESSION:$WIN.1" -x "55%"

tmux send-keys -t "$SESSION:$WIN.1" "bash /tmp/rscaller-microvm-pane1.sh 2>&1 | tee /tmp/rscaller-microvm-build.log" Enter
tmux send-keys -t "$SESSION:$WIN.2" "bash /tmp/rscaller-microvm-pane2.sh" Enter
tmux send-keys -t "$SESSION:$WIN.3" "bash /tmp/rscaller-microvm-pane3.sh" Enter

echo "==> Window '$WIN' ready — switching focus"
tmux select-window -t "$SESSION:$WIN"
tmux select-pane   -t "$SESSION:$WIN.1"
