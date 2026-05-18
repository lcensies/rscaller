#!/usr/bin/env bash
# run-image.sh — tmux-pane harness for testing rscaller --image mode
#
# Usage: bash scripts/run-image.sh [SSH_HOST] [image] [cmd...]
# Example: bash scripts/run-image.sh dev-vm-rscaller alpine:latest /bin/sh
#
# Optional env vars:
#   BEACON_HOST  — SSH host where rsbeacon should run (default: local machine).
#                  When set, rsbeacon binary is rsynced there and started via SSH.
#                  The container's file I/O will go to BEACON_HOST's filesystem.
#   BEACON_IP    — Override the IP that rscaller-run uses to reach rsbeacon.
#                  Auto-detected from BEACON_HOST when not set.
#
# Layout (everything in tmux — no blocking subshells):
#   left pane  : deploy (rsync + remote build + insmod), then rsbeacon
#   right-top  : remote dmesg -w (starts after sentinel)
#   right-bot  : rscaller-run via ssh -t (starts after sentinel)
#
# NOTE: does NOT rmmod. Revert VM to clean snapshot before running.

set -euo pipefail
REMOTE="${1:-${REMOTE:-dev-vm-rscaller}}"
IMAGE="${2:-${IMAGE:-alpine:latest}}"
shift 2 2>/dev/null || true
CMD="${*:-/bin/sh}"
REMOTE_DIR="/home/ubuntu/rscaller"
BEACON_PORT="${BEACON_PORT:-9999}"
BECOME_PASS="${BECOME_PASS:-ubuntu}"
BEACON_HOST="${BEACON_HOST:-}"
SESSION="rscaller"
WIN="image-test"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="/tmp/rscaller-deploy-done"

# ── 1. Resolve beacon IP reachable from REMOTE ────────────────────────────
if [[ -n "$BEACON_HOST" ]]; then
    # rsbeacon will run on BEACON_HOST — get its IP as seen from REMOTE
    if [[ -z "${BEACON_IP:-}" ]]; then
        BEACON_IP="$(ssh "$BEACON_HOST" 'hostname -I' 2>/dev/null | awk '{print $1}')"
    fi
    echo "==> Beacon host: $BEACON_HOST ($BEACON_IP:$BEACON_PORT)"
else
    # rsbeacon runs locally — get local IP reachable from REMOTE
    if [[ -z "${BEACON_IP:-}" ]]; then
        BEACON_IP="$(ssh "$REMOTE" 'echo $SSH_CLIENT' 2>/dev/null | awk '{print $1}')"
        [[ -z "$BEACON_IP" ]] && BEACON_IP="$(hostname -I | awk '{print $1}')"
    fi
    echo "==> Beacon: local ($BEACON_IP:$BEACON_PORT)"
fi

# ── 2. Write per-pane launch scripts ───────────────────────────────────────

# Beacon start command: remote SSH or local exec
if [[ -n "$BEACON_HOST" ]]; then
    BEACON_START="rsync -az '${REPO_ROOT}/target/release/rsbeacon' '${BEACON_HOST}:/tmp/rsbeacon' && ssh -n '${BEACON_HOST}' 'pkill rsbeacon || true; sleep 0.5' && echo '=== rsbeacon on ${BEACON_HOST} ===' && exec ssh -o BatchMode=yes '${BEACON_HOST}' '/tmp/rsbeacon --listen 0.0.0.0:${BEACON_PORT}'"
else
    BEACON_START="pkill rsbeacon || true; echo '=== rsbeacon 0.0.0.0:${BEACON_PORT} ===' && exec '${REPO_ROOT}/target/release/rsbeacon' --listen 0.0.0.0:${BEACON_PORT}"
fi

cat > /tmp/rscaller-pane1.sh <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
rm -f '${SENTINEL}'
echo '==> Deploying...'
BECOME_PASS='${BECOME_PASS}' bash '${REPO_ROOT}/scripts/deploy.sh' '${REMOTE}' '${REMOTE_DIR}'
echo '==> Loading kmod...'
ssh '${REMOTE}' "sudo insmod ${REMOTE_DIR}/kmod/rscaller.ko && lsmod | grep rscaller && ls /proc/rscaller && echo kmod_ok"
echo '==> kmod ready'
touch '${SENTINEL}'
${BEACON_START}
SCRIPT

cat > /tmp/rscaller-pane2.sh <<SCRIPT
#!/usr/bin/env bash
echo 'Waiting for deploy...'
until test -f '${SENTINEL}'; do sleep 1; done
exec ssh '${REMOTE}' 'echo ${BECOME_PASS} | sudo -S dmesg -w 2>/dev/null | grep --line-buffered -i rscaller'
SCRIPT

cat > /tmp/rscaller-pane3.sh <<SCRIPT
#!/usr/bin/env bash
echo 'Waiting for deploy...'
until test -f '${SENTINEL}'; do sleep 1; done
echo 'Waiting for beacon ${BEACON_IP}:${BEACON_PORT}...'
until bash -c ">/dev/tcp/${BEACON_IP}/${BEACON_PORT}" 2>/dev/null; do sleep 0.5; done
echo 'Beacon ready.'
exec ssh -t '${REMOTE}' "sudo -E env PATH=\\\$PATH ${REMOTE_DIR}/target/release/rscaller-run --image ${IMAGE} --beacon ${BEACON_IP}:${BEACON_PORT} -- ${CMD}"
SCRIPT

chmod +x /tmp/rscaller-pane1.sh /tmp/rscaller-pane2.sh /tmp/rscaller-pane3.sh

# ── 3. Set up tmux window ──────────────────────────────────────────────────
tmux kill-window -t "$SESSION:$WIN" 2>/dev/null || true
sleep 0.1
tmux new-window -t "$SESSION:" -n "$WIN" -c "$REPO_ROOT" -d
tmux split-window -t "$SESSION:$WIN.1" -h -c "$REPO_ROOT"
tmux split-window -t "$SESSION:$WIN.2" -v -c "$REPO_ROOT"
tmux resize-pane  -t "$SESSION:$WIN.1" -x "40%"

tmux send-keys -t "$SESSION:$WIN.1" "bash /tmp/rscaller-pane1.sh" Enter
tmux send-keys -t "$SESSION:$WIN.2" "bash /tmp/rscaller-pane2.sh" Enter
tmux send-keys -t "$SESSION:$WIN.3" "bash /tmp/rscaller-pane3.sh" Enter

echo "==> Window '$WIN' set up — switching focus"
tmux select-window -t "$SESSION:$WIN"
tmux select-pane   -t "$SESSION:$WIN.3"
