#!/usr/bin/env bash
# demo.sh — rscaller PoC demo
#
# Sets up a 3-pane tmux session:
#   Pane 0 (left):        dev-vm-1 — rsc client (attacker side)
#   Pane 1 (right-top):   dev-vm-2 — rsbeacon target (ip absent)
#   Pane 2 (right-bottom): host    — orchestration/guide text
#
# Usage:
#   bash scripts/demo.sh            # set up session, print step guide, attach
#   bash scripts/demo.sh --auto     # send demo commands automatically
#   bash scripts/demo.sh --teardown # restore ip on dev-vm-2, kill session
#
# Env overrides (all optional):
#   REMOTE=dev-vm-1   BEACON_VM=dev-vm-2
#   BEACON_PORT=9999  REMOTE_DIR=/home/ubuntu/rscaller

set -euo pipefail

REMOTE="${REMOTE:-dev-vm-1}"
BEACON_VM="${BEACON_VM:-dev-vm-2}"
BEACON_PORT="${BEACON_PORT:-9999}"
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/rscaller}"
# rsbeacon on BEACON_VM may have been scp'd to this flat path by deploy-beacon
BEACON_BIN_REMOTE="${BEACON_BIN_REMOTE:-/home/ubuntu/rsbeacon}"
SESSION="rsc-demo"
MODE="${1:-}"

# ── Colours ──────────────────────────────────────────────────────────────────
bold=$'\e[1m'; reset=$'\e[0m'
green=$'\e[32m'; yellow=$'\e[33m'; cyan=$'\e[36m'; red=$'\e[31m'

step()  { echo ""; echo "${bold}${green}==> $*${reset}"; }
note()  { echo "    ${cyan}$*${reset}"; }
warn()  { echo "    ${yellow}⚠  $*${reset}"; }

# ── Teardown ─────────────────────────────────────────────────────────────────
if [[ "$MODE" == "--teardown" ]]; then
    step "Teardown"
    ssh "$BEACON_VM" "
      sudo pkill -f rsbeacon 2>/dev/null || true
      [ -f /usr/sbin/ip.demo-bak ] && sudo mv /usr/sbin/ip.demo-bak /usr/sbin/ip || true
    " 2>/dev/null || true
    ssh "$REMOTE" "
      sudo umount /rsc/default/dev /rsc/default/sys 2>/dev/null || true
      sudo umount /rsc/default 2>/dev/null || true
      sudo pkill -f 'rsc shell' 2>/dev/null || true
    " 2>/dev/null || true
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    echo "Done."
    exit 0
fi

# ── Resolve beacon IP ────────────────────────────────────────────────────────
BEACON_IP=$(bash "$(dirname "${BASH_SOURCE[0]}")/vm_ip.sh" "$BEACON_VM" 2>/dev/null \
            || ssh "$BEACON_VM" "hostname -I | awk '{print \$1}'")
note "Beacon ($BEACON_VM) IP: $BEACON_IP:$BEACON_PORT"

# ── Tmux session ─────────────────────────────────────────────────────────────
step "Setting up tmux session '$SESSION'"

if tmux has-session -t "$SESSION" 2>/dev/null; then
    warn "Session '$SESSION' already exists — attaching."
    exec tmux attach-session -t "$SESSION"
fi

tmux new-session -d -s "$SESSION" -x "$(tput cols)" -y "$(tput lines)"

# Capture the initial pane (dev-vm-1 / left).  Use %id references so
# base-index setting doesn't matter.
PANE_VM1=$(tmux display-message -p -t "$SESSION" '#{pane_id}')

# Split right half for dev-vm-2 (top-right).
tmux split-window -h -t "$PANE_VM1"
PANE_VM2=$(tmux display-message -p -t "$SESSION" '#{pane_id}')

# Split bottom-right for host status.
tmux split-window -v -t "$PANE_VM2"
PANE_HOST=$(tmux display-message -p -t "$SESSION" '#{pane_id}')

tmux select-pane -t "$PANE_VM1"  -T "dev-vm-1 (rsc client)"
tmux select-pane -t "$PANE_VM2"  -T "dev-vm-2 (beacon/target)"
tmux select-pane -t "$PANE_HOST" -T "host"

# SSH into VMs
tmux send-keys -t "$PANE_VM1"  "ssh $REMOTE"     Enter
tmux send-keys -t "$PANE_VM2"  "ssh $BEACON_VM"  Enter
sleep 2

# ── Auto mode ────────────────────────────────────────────────────────────────
if [[ "$MODE" == "--auto" ]]; then
    step "Running demo automatically"

    vm1()  { tmux send-keys -t "$PANE_VM1"  "$*" Enter; }
    vm2()  { tmux send-keys -t "$PANE_VM2"  "$*" Enter; }
    host() { tmux send-keys -t "$PANE_HOST" "$*" Enter; }
    pause(){ sleep "${1:-2}"; }

    # ── 1. Remove ip from dev-vm-2 ──────────────────────────────────────────
    host "echo '${bold}[STEP 1] Hiding ip addr on $BEACON_VM${reset}'"
    vm2  "sudo mv /usr/sbin/ip /usr/sbin/ip.demo-bak"
    pause 1
    vm2  "echo '--- ip addr on dev-vm-2 ---'; ip addr 2>&1 || true"
    pause 2

    # ── 2. Start rsbeacon on dev-vm-2 ───────────────────────────────────────
    host "echo '${bold}[STEP 2] Starting rsbeacon on $BEACON_VM${reset}'"
    vm2  "echo '--- starting rsbeacon ---'"
    vm2  "sudo $BEACON_BIN_REMOTE --listen 0.0.0.0:$BEACON_PORT"
    pause 3

    # ── 3. rsc shell on dev-vm-1 ─────────────────────────────────────────────
    host "echo '${bold}[STEP 3] rsc shell on $REMOTE → mounts dev-vm-2 fs at /rsc/default/${reset}'"
    vm1  "echo '--- opening rsc shell (mounts dev-vm-2 filesystem via FUSE) ---'"
    vm1  "sudo $REMOTE_DIR/target/release/rsc shell --beacon $BEACON_IP:$BEACON_PORT --name default"
    pause 5

    # ── 4. Confirm FUSE mount and that ip is absent there ───────────────────
    host "echo '${bold}[STEP 4] /rsc/default/ is dev-vm-2 via FUSE${reset}'"
    vm1  "echo '--- /rsc/default/ is dev-vm-2 filesystem ---'; ls /rsc/default/"
    pause 2
    vm1  "echo '--- ip absent on dev-vm-2 ---'; ls /rsc/default/usr/sbin/ip 2>&1 || true"
    pause 2
    vm1  "echo '--- dev-vm-2 hostname via FUSE ---'; cat /rsc/default/etc/hostname"
    pause 2

    # ── 5. Read dev-vm-2 network info from FUSE /proc ───────────────────────
    host "echo '${bold}[STEP 5] Reading dev-vm-2 network info via FUSE /proc${reset}'"
    vm1  "echo '--- dev-vm-2 interfaces (/proc/net/dev via FUSE) ---'"
    vm1  "cat /rsc/default/proc/net/dev"
    pause 2
    vm1  "echo '--- dev-vm-2 IP addresses (/proc/net/fib_trie via FUSE) ---'"
    vm1  "awk '/32 host/{print f}{f=\$2}' /rsc/default/proc/net/fib_trie | sort -u"
    pause 3

    # ── 6. chroot into dev-vm-2 filesystem ──────────────────────────────────
    host "echo '${bold}[STEP 6] chroot into dev-vm-2 filesystem — ip absent, but /proc reads through FUSE${reset}'"
    vm1  "echo '--- chrooting into dev-vm-2 filesystem ---'"
    # Bind /dev so bash can open a tty inside the chroot
    vm1  "sudo mount --bind /dev /rsc/default/dev 2>/dev/null || true"
    vm1  "sudo chroot /rsc/default/ bash -c \""
    vm1  "  echo '=== inside dev-vm-2 chroot ===';"
    vm1  "  echo '--- hostname ---'; hostname;"
    vm1  "  echo '--- ip addr → absent ---'; ip addr 2>&1 || true;"
    vm1  "  echo '--- interfaces via /proc/net/dev ---'; cat /proc/net/dev;"
    vm1  "  echo '--- IP addresses via /proc/net/fib_trie ---';"
    vm1  "  awk '/32 host/{print f}{f=\\\$2}' /proc/net/fib_trie | sort -u"
    vm1  "\""
    pause 5

    host "echo '${bold}${green}Demo complete!${reset}'"
    host "echo 'dev-vm-1 read dev-vm-2 network info even though ip addr was absent on dev-vm-2'"

else
    # ── Interactive guide ─────────────────────────────────────────────────────
    cat <<GUIDE

${bold}${green}=== rscaller PoC Demo Guide ===${reset}

Pane layout:
  ${cyan}Left${reset}          → dev-vm-1 (${REMOTE})  — rsc client
  ${cyan}Right-top${reset}     → dev-vm-2 (${BEACON_VM}) — target (beacon)
  ${cyan}Right-bottom${reset}  → host

${bold}BEACON = ${BEACON_IP}:${BEACON_PORT}     REMOTE_DIR = ${REMOTE_DIR}${reset}

────────────────────────────────────────────────────────────────────────
${bold}STEP 1${reset}  [dev-vm-2]  Make ip addr absent on the target
────────────────────────────────────────────────────────────────────────
  sudo mv /usr/sbin/ip /usr/sbin/ip.demo-bak
  ip addr                       # → bash: ip: command not found

${bold}STEP 2${reset}  [dev-vm-2]  Start rsbeacon
────────────────────────────────────────────────────────────────────────
  sudo ${BEACON_BIN_REMOTE} --listen 0.0.0.0:${BEACON_PORT}

${bold}STEP 3${reset}  [dev-vm-1]  Open rsc shell — mounts dev-vm-2 fs at /rsc/default/
────────────────────────────────────────────────────────────────────────
  sudo ${REMOTE_DIR}/target/release/rsc shell \\
       --beacon ${BEACON_IP}:${BEACON_PORT} --name default

${bold}STEP 4${reset}  [dev-vm-1, inside rsc shell]  Confirm FUSE mount + ip absent
────────────────────────────────────────────────────────────────────────
  ls /rsc/default/                        # dev-vm-2's root filesystem
  ls /rsc/default/usr/sbin/ip             # absent!
  cat /rsc/default/etc/hostname           # → dev-vm-2

${bold}STEP 5${reset}  [dev-vm-1, inside rsc shell]  Read dev-vm-2 network via FUSE /proc
────────────────────────────────────────────────────────────────────────
  # Interfaces (equivalent to "ip link")
  cat /rsc/default/proc/net/dev

  # IP addresses (equivalent to "ip addr") — reads dev-vm-2's fib_trie via FUSE
  awk '/32 host/{print f}{f=\$2}' /rsc/default/proc/net/fib_trie | sort -u

${bold}STEP 6${reset}  [dev-vm-1, inside rsc shell]  chroot into dev-vm-2 filesystem
────────────────────────────────────────────────────────────────────────
  # Bind /dev so bash works inside chroot
  sudo mount --bind /dev /rsc/default/dev

  # Enter dev-vm-2's filesystem; /proc inside = /rsc/default/proc → FUSE → dev-vm-2
  sudo chroot /rsc/default/ bash -c "
    echo '=== inside dev-vm-2 chroot ==='; hostname
    echo '--- ip addr → absent ---'; ip addr 2>&1 || true
    echo '--- interfaces via /proc/net/dev ---'; cat /proc/net/dev
    echo '--- IPs via /proc/net/fib_trie ---'
    awk '/32 host/{print f}{f=\\\$2}' /proc/net/fib_trie | sort -u
  "

${bold}TEARDOWN${reset}
────────────────────────────────────────────────────────────────────────
  bash scripts/demo.sh --teardown

${bold}TIP:${reset} run with --auto to execute all steps automatically:
  bash scripts/demo.sh --auto
GUIDE

    exec tmux attach-session -t "$SESSION"
fi

exec tmux attach-session -t "$SESSION"
