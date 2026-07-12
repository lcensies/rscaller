#!/usr/bin/env bash
# poc.sh — manual PoC CLI for rscaller mount namespace overlay profiles.
#
# Starts rsbeacon (and optionally tracee) on BEACON_VM, then runs a single
# command via `rsc exec` with the chosen mount profile on REMOTE.  Prints
# tracee events after the command exits so you can verify execution locality.
#
# Usage:
#   bash scripts/poc.sh [OPTIONS]
#
# Options:
#   --profile  <name>   Mount profile: none|recon|relay|shadow|ghost  (default: recon)
#   --cmd      <cmd>    Command to run inside rsc exec                  (default: see profile)
#   --no-tracee         Skip tracee monitoring (faster startup)
#   --beacon   <host>   Beacon VM SSH alias                             (default: dev-vm-2)
#   --client   <host>   Client VM SSH alias                             (default: dev-vm-1)
#   --port     <port>   rsbeacon port                                   (default: 9999)
#   --dir      <path>   Remote rscaller dir                             (default: /home/ubuntu/rscaller)
#   -h, --help
#
# Profiles:
#   none   — no overlay, no forwarding; ip addr shows CLIENT addresses
#   recon  — /proc + /sys overlaid; grep /proc/net/fib_trie shows beacon IP
#   relay  — network syscalls forwarded through beacon; no filesystem overlay
#   shadow — full identity overlay (/proc + /sys + /etc) + network forwarding
#   ghost  — shadow + writable /mnt/target + process signal forwarding
#
# Examples:
#   bash scripts/poc.sh --profile recon
#   bash scripts/poc.sh --profile shadow --cmd hostname
#   bash scripts/poc.sh --profile none --no-tracee --cmd "ip -4 addr"
#   bash scripts/poc.sh --profile recon --cmd "grep . /sys/class/net/enp1s0/address"

set -euo pipefail

BEACON_VM="${BEACON_VM:-dev-vm-2}"
REMOTE="${REMOTE:-dev-vm-1}"
BEACON_PORT="${BEACON_PORT:-9999}"
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/rscaller}"
BEACON_BIN="${BEACON_BIN:-/home/ubuntu/rsbeacon}"
TRACEE_BIN="${TRACEE_BIN:-/tmp/tracee}"
MOUNT_BASE="/tmp/rsc-profiles"

PROFILE="recon"
CMD=""
NO_TRACEE=0

bold=$'\e[1m'; dim=$'\e[2m'; green=$'\e[32m'; yellow=$'\e[33m'; red=$'\e[31m'; reset=$'\e[0m'

usage() {
    sed -n '/^# Usage:/,/^[^#]/{ /^#/{ s/^# \?//; p } }' "$0"
    exit 0
}

die() { echo "${red}error:${reset} $*" >&2; exit 1; }
say() { echo "${bold}==>${reset} $*"; }
info() { echo "    $*"; }

# ── Arg parse ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)  PROFILE="$2";    shift 2 ;;
        --cmd)      CMD="$2";        shift 2 ;;
        --no-tracee) NO_TRACEE=1;   shift   ;;
        --beacon)   BEACON_VM="$2"; shift 2 ;;
        --client)   REMOTE="$2";    shift 2 ;;
        --port)     BEACON_PORT="$2"; shift 2 ;;
        --dir)      REMOTE_DIR="$2"; shift 2 ;;
        -h|--help)  usage ;;
        *) die "Unknown option: $1" ;;
    esac
done

# Default command per profile
if [[ -z "$CMD" ]]; then
    case "$PROFILE" in
        none)
            CMD="ip -4 addr"
            ;;
        recon)
            BEACON_IP=$(ssh "$BEACON_VM" "hostname -I | awk '{print \$1}'" 2>/dev/null || echo "")
            CMD="grep ${BEACON_IP:-192.168.122.180} /proc/net/fib_trie"
            ;;
        relay)
            CMD="curl -s ifconfig.me"
            ;;
        shadow|ghost)
            CMD="hostname"
            ;;
        *)
            CMD="hostname"
            ;;
    esac
fi

RSC="$REMOTE_DIR/target/release/rsc"
RSCLIENT="$REMOTE_DIR/target/release/rsclient"
NAME="prof-$PROFILE"
MOUNT_POINT="$MOUNT_BASE/$NAME"

# ── Validate profile ─────────────────────────────────────────────────────────
case "$PROFILE" in
    none|recon|relay|shadow|ghost) ;;
    *) die "Unknown profile '$PROFILE'. Valid: none recon relay shadow ghost" ;;
esac

# ── Print plan ───────────────────────────────────────────────────────────────
echo ""
echo "${bold}rscaller PoC — mount namespace overlay${reset}"
echo "  client:  ${green}${REMOTE}${reset}"
echo "  beacon:  ${green}${BEACON_VM}:${BEACON_PORT}${reset}"
echo "  profile: ${yellow}${PROFILE}${reset}"
echo "  command: ${dim}${CMD}${reset}"
echo "  tracee:  $([ "$NO_TRACEE" -eq 1 ] && echo "disabled" || echo "enabled")"
echo ""

# ── Step 1: Start rsbeacon ───────────────────────────────────────────────────
say "Starting rsbeacon on $BEACON_VM"
ssh "$BEACON_VM" "sudo pkill rsbeacon 2>/dev/null || true; sleep 0.3; \
    nohup sudo $BEACON_BIN --listen 0.0.0.0:$BEACON_PORT >/tmp/rsbeacon-poc.log 2>&1 &"
sleep 1
if ! ssh "$BEACON_VM" "ss -tlnp | grep -q ':$BEACON_PORT'" 2>/dev/null; then
    echo "${red}rsbeacon failed to start. Log:${reset}"
    ssh "$BEACON_VM" "cat /tmp/rsbeacon-poc.log" 2>/dev/null || true
    die "rsbeacon not listening on :$BEACON_PORT"
fi
info "rsbeacon listening on :$BEACON_PORT"

# ── Step 2: Start tracee (optional) ─────────────────────────────────────────
TRACEE_PID=""
if [[ "$NO_TRACEE" -eq 0 ]]; then
    say "Starting tracee on $BEACON_VM (settle 3s)"
    TRACEE_LOG="/tmp/tracee-poc-$$.log"
    # Download tracee if missing
    ssh "$BEACON_VM" "
        if [ ! -x '$TRACEE_BIN' ]; then
            echo 'Downloading tracee...'
            curl -fsSL https://github.com/aquasecurity/tracee/releases/latest/download/tracee-amd64 \
                -o '$TRACEE_BIN' && chmod +x '$TRACEE_BIN'
        fi
    " 2>/dev/null
    ssh "$BEACON_VM" \
        "nohup sudo $TRACEE_BIN --output format:json \
            --events execve,execveat \
            >$TRACEE_LOG 2>/dev/null &
         echo \$!" > /tmp/poc-tracee-pid-$$ 2>/dev/null || true
    TRACEE_PID=$(cat /tmp/poc-tracee-pid-$$ 2>/dev/null || echo "")
    rm -f /tmp/poc-tracee-pid-$$
    sleep 3
    info "tracee running (pid ${TRACEE_PID:-unknown}) → $TRACEE_LOG"
fi

# ── Step 3: Clean up stale mounts ───────────────────────────────────────────
BEACON_IP_SSH=$(ssh "$BEACON_VM" "hostname -I | awk '{print \$1}'" 2>/dev/null)

say "Cleaning stale mounts on $REMOTE"
ssh "$REMOTE" "mkdir -p '$MOUNT_BASE'; \
    sudo pkill -9 -f '$NAME' 2>/dev/null || true; sleep 0.4; \
    grep -qF '$MOUNT_POINT' /proc/mounts && sudo umount -l '$MOUNT_POINT' 2>/dev/null || true; \
    sudo rm -rf '$MOUNT_POINT' 2>/dev/null || true"

# ── Step 4: Run command via rsc exec ────────────────────────────────────────
say "Running: sudo rsc exec --mount-profile $PROFILE -- $CMD"
echo ""
echo "─── stdout ──────────────────────────────────────────────────────────────"
set +e
ssh "$REMOTE" \
    "sudo $RSC exec \
        --beacon '${BEACON_IP_SSH}:${BEACON_PORT}' \
        --rsclient '$RSCLIENT' \
        --mount-base '$MOUNT_BASE' \
        --name '$NAME' \
        --mount-profile '$PROFILE' \
        -- $CMD"
EXIT_CODE=$?
set -e
echo "─────────────────────────────────────────────────────────────────────────"
echo ""
info "exit code: $EXIT_CODE"

# ── Step 5: Cleanup rscfuse ─────────────────────────────────────────────────
ssh "$REMOTE" \
    "sudo pkill -9 -f '$NAME' 2>/dev/null || true; sleep 0.4; \
     grep -qF '$MOUNT_POINT' /proc/mounts && sudo umount -l '$MOUNT_POINT' 2>/dev/null || true; \
     sudo rm -rf '$MOUNT_POINT' 2>/dev/null || true" 2>/dev/null

# ── Step 6: Print tracee events ─────────────────────────────────────────────
if [[ "$NO_TRACEE" -eq 0 ]]; then
    say "Tracee events from $BEACON_VM (execve/execveat)"
    echo ""
    EVENTS=$(ssh "$BEACON_VM" "cat $TRACEE_LOG 2>/dev/null" | \
        python3 -c "
import sys, json
motd = {'50-landscape-sy','50-motd-news','85-fwupd','90-updates-avai',
        'update-motd-fsc','update-motd-upd','landscape-sysinfo'}
found = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except Exception:
        continue
    if e.get('processName','') in motd:
        continue
    cmd = e.get('processName','?')
    pid = e.get('processId','?')
    ts  = e.get('timestamp','')
    print(f'  [{ts}] execve pid={pid} cmd={cmd}')
    found += 1
if found == 0:
    print('  (none — all execution was local)')
" 2>/dev/null || echo "  (tracee log unavailable)")
    echo "$EVENTS"
    echo ""

    # Stop tracee
    if [[ -n "$TRACEE_PID" ]]; then
        ssh "$BEACON_VM" "sudo kill $TRACEE_PID 2>/dev/null || true" 2>/dev/null
    fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
say "Done (exit=$EXIT_CODE)"
if [[ "$EXIT_CODE" -eq 0 ]]; then
    echo "${green}PASS${reset}"
else
    echo "${red}FAIL${reset}"
    exit 1
fi
