#!/usr/bin/env bash
# test_evasion_no_rscaller.sh — baseline: lse runs directly on victim.
#
# Tracee on CLONE (victim) MUST see execve events — proves the detector is active.
# PASS if at least one exec event is captured.
#
# Usage:
#   bash observability/test_evasion_no_rscaller.sh [clone]
#   EXEC_TIMEOUT=60 bash observability/test_evasion_no_rscaller.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/test_lib_rscaller.sh"

CLONE="${1:-${CLONE:-dev-vm-rscaller-clone}}"
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/rscaller}"
EXEC_TIMEOUT="${EXEC_TIMEOUT:-60}"
TOOL_URL="https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh"
export TRACEE_EVENTS="${TRACEE_EVENTS:-execve,execveat}"

CLONE_IP="$(ssh "$CLONE" 'hostname -I 2>/dev/null' | awk '{print $1}')"
export LOKI_URL="http://${CLONE_IP}:3100"

echo "=============================================="
echo " Observability test: no-rscaller baseline"
echo "=============================================="
echo
log_info "Victim (CLONE)  : $CLONE ($CLONE_IP)"
log_info "Tracee events   : $TRACEE_EVENTS"
log_info "Loki URL        : $LOKI_URL"
echo

# ── Start observability stack on victim ───────────────────────────────────────
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
COMPOSE_DIR="$SCRIPT_DIR"

log_info "Ensuring observability stack on $CLONE..."
ssh "$CLONE" "
  mkdir -p /tmp/rscaller-obs/config/loki /tmp/rscaller-obs/config/promtail
"
scp -q "$COMPOSE_FILE" "$CLONE:/tmp/rscaller-obs/docker-compose.yml"
scp -q "$SCRIPT_DIR/config/loki/loki.yml"         "$CLONE:/tmp/rscaller-obs/config/loki/loki.yml"
scp -q "$SCRIPT_DIR/config/promtail/promtail.yml"  "$CLONE:/tmp/rscaller-obs/config/promtail/promtail.yml"

ssh "$CLONE" "
  cd /tmp/rscaller-obs
  TRACEE_EVENTS='${TRACEE_EVENTS}' docker compose up -d 2>&1 | tail -5
"

# Wait for stack on CLONE
log_info "Waiting for Loki on $CLONE_IP:3100..."
for i in $(seq 1 60); do
  curl -sf "${LOKI_URL}/ready" >/dev/null 2>&1 && break || true
  sleep 1
done
curl -sf "${LOKI_URL}/ready" >/dev/null 2>&1 || { log_error "Loki not ready"; exit 1; }
log_info "Stack OK"

# ── Fetch and run lse.sh directly on victim ───────────────────────────────────
log_info "Fetching and running lse.sh directly on $CLONE (no rscaller)..."
ssh "$CLONE" "
  curl -fsSL '${TOOL_URL}' -o /tmp/lse.sh 2>/dev/null
  chmod +x /tmp/lse.sh
"
T_START=$(now_ns)
log_info "Running lse.sh (timeout ${EXEC_TIMEOUT}s)..."
ssh "$CLONE" "timeout ${EXEC_TIMEOUT} bash /tmp/lse.sh -l 1 -i 2>&1" \
  | tail -5 || true

# ── Wait for Tracee to capture exec events ────────────────────────────────────
log_info "Waiting up to ${LOKI_QUERY_TIMEOUT}s for execve events from lse.sh..."
if wait_for_event "$LOKI_QUERY_TIMEOUT" "$T_START" "execve" "lse"; then
  log_pass "Tracee captured exec events for lse.sh — detector is active."
  exit 0
else
  log_error "Tracee did NOT detect exec events within ${LOKI_QUERY_TIMEOUT}s."
  exit 1
fi
