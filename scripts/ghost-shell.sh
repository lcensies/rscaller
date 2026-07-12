#!/usr/bin/env bash
# ghost-shell.sh — interactive ghost-profile shell on dev-vm-1 → dev-vm-2
#
# 3-pane tmux layout (idempotent — kills and rebuilds if it exists):
#   Left:         dev-vm-1 — rsc shell --mount-profile ghost (attacker)
#   Top-right:    dev-vm-2 — tracee exec events (live tail)
#   Bottom-right: dev-vm-2 — beacon shell (rsbeacon + interactive)
#
# Ghost profile provides:
#   /proc        → merged: local PIDs as-is, beacon PIDs at offset +10,000,000
#   /mnt/target  → beacon's full rootfs (read/write)
#   kill/tgkill/tkill forwarded to beacon, EXCEPT local-cgroup processes
#
# Usage:
#   bash scripts/ghost-shell.sh            # (re)start: tear down + rebuild
#   bash scripts/ghost-shell.sh --teardown # kill session, stop rsbeacon+tracee
#
# Env overrides:
#   REMOTE=dev-vm-1   BEACON_VM=dev-vm-2
#   BEACON_PORT=9999  REMOTE_DIR=/home/ubuntu/rscaller
#   TRACEE=0          # set to skip tracee startup

set -euo pipefail

REMOTE="${REMOTE:-dev-vm-1}"
BEACON_VM="${BEACON_VM:-dev-vm-2}"
BEACON_PORT="${BEACON_PORT:-9999}"
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/rscaller}"
BEACON_BIN_REMOTE="${BEACON_BIN_REMOTE:-/home/ubuntu/rsbeacon}"
TRACEE="${TRACEE:-1}"
TRACEE_IMAGE="${TRACEE_IMAGE:-aquasec/tracee:latest}"
TRACEE_CONTAINER="tracee-ghost"
SESSION="rsc-ghost"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bold=$'\e[1m'; reset=$'\e[0m'
green=$'\e[32m'; cyan=$'\e[36m'

step() { echo ""; echo "${bold}${green}==> $*${reset}"; }
note() { echo "    ${cyan}$*${reset}"; }

# ── Cleanup helper ────────────────────────────────────────────────────────────
cleanup() {
    ssh "$BEACON_VM" "
      sudo docker rm -f $TRACEE_CONTAINER 2>/dev/null; true
      sudo pkill -f rsbeacon 2>/dev/null; true
    " 2>/dev/null || true
    ssh "$REMOTE" "
      sudo pkill -f 'rsc shell' 2>/dev/null; true
      sudo pkill -f 'rsc exec'  2>/dev/null; true
      sleep 0.5
      sudo umount -l /rsc/ghost      2>/dev/null; true
      sudo umount -l /rsc/ghosttest  2>/dev/null; true
      sudo umount -l /rsc/ghosttest2 2>/dev/null; true
    " 2>/dev/null || true
    tmux kill-session -t "$SESSION" 2>/dev/null || true
}

# ── Teardown ──────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--teardown" ]]; then
    step "Teardown"
    cleanup
    echo "Done."
    exit 0
fi

# ── Resolve beacon IP ─────────────────────────────────────────────────────────
BEACON_IP=$(bash "$(dirname "${BASH_SOURCE[0]}")/vm_ip.sh" "$BEACON_VM" 2>/dev/null \
            || ssh "$BEACON_VM" "hostname -I | awk '{print \$1}'")
note "Beacon ($BEACON_VM) IP: $BEACON_IP:$BEACON_PORT"

RSC_CMD="sudo $REMOTE_DIR/target/release/rsc shell \
  --beacon $BEACON_IP:$BEACON_PORT \
  --name ghost \
  --mount-profile ghost"

# ── Tear down any existing session so we always start clean ──────────────────
if tmux has-session -t "$SESSION" 2>/dev/null; then
    step "Existing session found — tearing down before rebuild"
    cleanup
fi

# ── Create 3-pane session ────────────────────────────────────────────────────
#   [LEFT          ] | [TOP-RIGHT   ]
#   [ghost shell   ] | [tracee tail ]
#                    | [beacon shell]
step "Creating tmux session '$SESSION'"
tmux new-session -d -s "$SESSION" -x "$(tput cols)" -y "$(tput lines)"

PANE_LEFT=$(tmux display-message -p -t "$SESSION" '#{pane_id}')
tmux split-window -h -t "$PANE_LEFT"
PANE_TRACEE=$(tmux display-message -p -t "$SESSION" '#{pane_id}')
tmux split-window -v -t "$PANE_TRACEE"
PANE_BEACON=$(tmux display-message -p -t "$SESSION" '#{pane_id}')

tmux select-pane -t "$PANE_LEFT"   -T "dev-vm-1 (attacker / ghost shell)"
tmux select-pane -t "$PANE_TRACEE" -T "dev-vm-2 (tracee exec events)"
tmux select-pane -t "$PANE_BEACON" -T "dev-vm-2 (beacon shell)"

# ── SSH into VMs ─────────────────────────────────────────────────────────────
# Left and bottom-right SSH to their respective VMs.
# Top-right runs tracee_watch.py locally (it handles SSH internally).
tmux send-keys -t "$PANE_LEFT"   "ssh $REMOTE"    Enter
tmux send-keys -t "$PANE_BEACON" "ssh $BEACON_VM" Enter
sleep 2

# ── Start rsbeacon on dev-vm-2 (beacon shell pane) ───────────────────────────
step "Starting rsbeacon on $BEACON_VM (port $BEACON_PORT)"
tmux send-keys -t "$PANE_BEACON" \
    "sudo $BEACON_BIN_REMOTE --listen 0.0.0.0:$BEACON_PORT" Enter
sleep 1

# ── Start tracee on dev-vm-2 (tracee pane) ───────────────────────────────────
if [[ "$TRACEE" == "1" ]]; then
    step "Starting tracee watcher (python3 tracee_watch.py)"
    note "Script starts container if needed, then streams parsed exec events"
    tmux send-keys -t "$PANE_TRACEE" \
        "python3 $SCRIPT_DIR/tracee_watch.py $BEACON_VM $TRACEE_CONTAINER $TRACEE_IMAGE" Enter
else
    tmux send-keys -t "$PANE_TRACEE" \
        "echo 'tracee disabled (TRACEE=0); run: python3 $SCRIPT_DIR/tracee_watch.py $BEACON_VM'" Enter
fi

# ── Open ghost shell on dev-vm-1 ─────────────────────────────────────────────
step "Opening ghost-profile shell on $REMOTE"
note "Beacon PID offset: +10,000,000 (beacon PID 42 → 10000042 inside shell)"
tmux send-keys -t "$PANE_LEFT" "$RSC_CMD" Enter

tmux select-pane -t "$PANE_LEFT"

cat <<GUIDE

${bold}${green}=== ghost-shell ready ===${reset}

  ${cyan}Left${reset}         dev-vm-1 — attacker / ghost shell
  ${cyan}Top-right${reset}    dev-vm-2 — tracee exec events (live)
  ${cyan}Bottom-right${reset} dev-vm-2 — beacon shell + rsbeacon

${bold}Ghost shell commands:${reset}

  ps aux | awk '\$2 > 10000000'              # beacon processes (virtual PIDs)
  cat /proc/version                          # beacon kernel version
  cat /mnt/target/etc/hostname               # beacon hostname

${bold}Kill demo (beacon runs as root):${reset}

  # bottom-right: spawn a target
  #   sleep 9999 &
  # ghost shell: find + kill it
  ps aux | awk '\$2 > 10000000 && /sleep/'   # find virtual PID
  kill -9 <virtual_pid>                      # forwarded to beacon
  # top-right: watch tracee — no exec appears (kill only, no exec)

${bold}Exec evasion demo:${reset}

  # ghost shell: run something on beacon via forwarded exec
  # top-right: tracee should NOT show it (or show rsclient, not the tool)

${bold}Re-run to reset:${reset}  bash scripts/ghost-shell.sh
${bold}Teardown:${reset}         bash scripts/ghost-shell.sh --teardown
${bold}Skip tracee:${reset}      TRACEE=0 bash scripts/ghost-shell.sh

GUIDE

# Attach only when running in a real terminal (not piped from make).
if [ -t 0 ]; then
    exec tmux attach-session -t "$SESSION"
fi
