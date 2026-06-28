#!/usr/bin/env bash
# test_evasion_obs.sh — tmux harness for evasion observability test
#
# Delegates to test_evasion_baseline.sh (pane 2); pane 1 tails the tracee
# exec-event log live; pane 3 monitors the rsbeacon on the clone VM.
#
# Layout (tmux):
#   Pane 1 (left)      — live tracee exec-event log tail from REMOTE
#   Pane 2 (top-right) — test_evasion_baseline.sh (tracee + tool + pass/fail)
#   Pane 3 (bot-right) — rsbeacon log on CLONE
#
# Usage:
#   bash scripts/test_evasion_obs.sh [remote] [clone]
#   TOOL=linpeas EXEC_TIMEOUT=120 bash scripts/test_evasion_obs.sh

set -euo pipefail

REMOTE="${1:-${REMOTE:-dev-vm-rscaller}}"
CLONE="${2:-${CLONE:-dev-vm-rscaller-clone}}"
BECOME_PASS="${BECOME_PASS:-ubuntu}"
TOOL="${TOOL:-lse}"
EXEC_TIMEOUT="${EXEC_TIMEOUT:-90}"
BEACON_PORT="${BEACON_PORT:-9999}"
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/rscaller}"
TRACEE_LOG="${TRACEE_LOG:-/tmp/rscaller-tracee-baseline.log}"

SESSION="${TMUX_SESSION:-$(tmux display-message -p '#S' 2>/dev/null || echo '')}"
WIN="evasion-obs"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="$REPO_ROOT/scripts"

if [[ -f "$REPO_ROOT/.env" ]]; then
  set -o allexport; source "$REPO_ROOT/.env"; set +o allexport
fi

echo "==> Evasion observability test"
echo "    Remote  : $REMOTE"
echo "    Clone   : $CLONE"
echo "    Tool    : $TOOL (timeout ${EXEC_TIMEOUT}s)"
echo "    Baseline: scripts/test_evasion_baseline.sh"
echo ""

REMOTE_IP="$(ssh "$REMOTE" 'hostname -I 2>/dev/null' | awk '{print $1}')"
CLONE_IP="$(ssh "$CLONE"  'hostname -I 2>/dev/null' | awk '{print $1}')"
echo "    Remote IP: $REMOTE_IP"
echo "    Clone  IP: $CLONE_IP"

# ── Pane 1: tail tracee log live from remote ──────────────────────────────────
cat > /tmp/rscaller-evasion-pane1.sh << PANE1
#!/usr/bin/env bash
REMOTE="${REMOTE}"
TRACEE_LOG="${TRACEE_LOG}"

echo "==> [pane1] Waiting for tracee log to appear on \$REMOTE..."
until ssh "\$REMOTE" "test -s '\$TRACEE_LOG'" 2>/dev/null; do
  printf '.'; sleep 0.5
done
echo ""
echo "==> [pane1] Tailing tracee exec events from \$REMOTE:\$TRACEE_LOG"
echo "    (execve / execveat only)"
echo "------------------------------------------------------------"
ssh "\$REMOTE" "tail -f '\$TRACEE_LOG'" | grep --line-buffered -i execve
PANE1
chmod +x /tmp/rscaller-evasion-pane1.sh

# ── Pane 2: run baseline test ─────────────────────────────────────────────────
cat > /tmp/rscaller-evasion-pane2.sh << PANE2
#!/usr/bin/env bash
echo "==> [pane2] Running test_evasion_baseline.sh..."
echo ""
REMOTE="${REMOTE}" \
BECOME_PASS="${BECOME_PASS}" \
TOOL="${TOOL}" \
EXEC_TIMEOUT="${EXEC_TIMEOUT}" \
TRACEE_LOG="${TRACEE_LOG}" \
  bash "${SCRIPTS_DIR}/test_evasion_baseline.sh"
PANE2
chmod +x /tmp/rscaller-evasion-pane2.sh

# ── Pane 3: beacon monitor on clone ──────────────────────────────────────────
cat > /tmp/rscaller-evasion-pane3.sh << PANE3
#!/usr/bin/env bash
CLONE="${CLONE}"
BEACON_PORT="${BEACON_PORT}"
REMOTE_DIR="${REMOTE_DIR}"

echo "==> [pane3] Clone: \$CLONE — beacon monitor"
echo ""
ssh "\$CLONE" "
  if test -f '${REMOTE_DIR}/target/release/rsbeacon'; then
    pkill rsbeacon 2>/dev/null || true
    sleep 0.3
    nohup '${REMOTE_DIR}/target/release/rsbeacon' --listen '0.0.0.0:${BEACON_PORT}' \
      > /tmp/rsbeacon-evasion.log 2>&1 &
    echo 'rsbeacon started on clone'
  else
    echo 'rsbeacon binary not found on clone — skipping'
  fi
" 2>/dev/null || echo "(clone beacon setup skipped)"

echo ""
echo "==> [pane3] Tailing rsbeacon log on \$CLONE..."
ssh "\$CLONE" 'tail -f /tmp/rsbeacon-evasion.log 2>/dev/null || sleep infinity'
PANE3
chmod +x /tmp/rscaller-evasion-pane3.sh

# ── Create tmux window ────────────────────────────────────────────────────────
tmux kill-window -t "$SESSION:$WIN" 2>/dev/null || true
sleep 0.1

tmux new-window   -t "$SESSION:" -n "$WIN" -c "$REPO_ROOT" -d
tmux split-window -t "$SESSION:$WIN.1" -h -c "$REPO_ROOT"
tmux split-window -t "$SESSION:$WIN.2" -v -c "$REPO_ROOT"
tmux resize-pane  -t "$SESSION:$WIN.1" -x "55%"

tmux send-keys -t "$SESSION:$WIN.1" "bash /tmp/rscaller-evasion-pane1.sh" Enter
tmux send-keys -t "$SESSION:$WIN.2" \
  "bash /tmp/rscaller-evasion-pane2.sh 2>&1 | tee /tmp/rscaller-evasion-baseline.log" Enter
tmux send-keys -t "$SESSION:$WIN.3" "bash /tmp/rscaller-evasion-pane3.sh" Enter

echo ""
echo "==> Window '$WIN' ready in session '$SESSION'"
echo "    baseline log : /tmp/rscaller-evasion-baseline.log"
echo ""

tmux select-window -t "$SESSION:$WIN"
tmux select-pane   -t "$SESSION:$WIN.1"
