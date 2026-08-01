#!/usr/bin/env bash
# poc_tmux.sh — 2-pane tmux visualization wrapper around poc.sh, for
# screenshotting an evasion run.
#
# Layout (tmux window, split left/right):
#   Pane 1 (left)  "rsclient"  — runs poc.sh in the foreground (the attacker
#                                side: rsc exec, tracee counts, verdict).
#   Pane 2 (right) "rsbeacon"  — tails rsbeacon's log on the beacon VM, so
#                                forwarded syscalls are visible live
#                                (RUST_LOG=rsbeacon=debug by default in poc.sh).
#
# All arguments are forwarded verbatim to poc.sh — see `bash scripts/poc.sh --help`.
#
# Usage:
#   bash scripts/poc_tmux.sh --scenario exec
#   bash scripts/poc_tmux.sh --scenario network
#   bash scripts/poc_tmux.sh --profile ghost --compare --cmd "..." --baseline-cmd "..."
#
# Env overrides:
#   BEACON_VM (default dev-vm-2) — only used to pick which host's rsbeacon
#                                  log to tail; pass --beacon to poc.sh too
#                                  if you want it to actually use that host.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BEACON_VM="${BEACON_VM:-dev-vm-2}"
# Pick up an explicit --beacon <host> from the forwarded args, if given.
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
	if [[ "${args[$i]}" == "--beacon" && -n "${args[$((i + 1))]:-}" ]]; then
		BEACON_VM="${args[$((i + 1))]}"
	fi
done

SESSION="${TMUX_SESSION:-$(tmux display-message -p '#S' 2>/dev/null || echo '')}"
WIN="${WINDOW:-poc-evasion}"

# ── Pane 1: run poc.sh with all forwarded args ──────────────────────────────
PANE1_SCRIPT="/tmp/rscaller-poc-pane1.sh"
{
	echo "#!/usr/bin/env bash"
	echo "cd '$REPO_ROOT'"
	printf 'bash scripts/poc.sh'
	for a in "$@"; do printf ' %q' "$a"; done
	printf '\n'
} >"$PANE1_SCRIPT"
chmod +x "$PANE1_SCRIPT"

# ── Pane 2: tail rsbeacon log on the beacon VM ──────────────────────────────
PANE2_SCRIPT="/tmp/rscaller-poc-pane2.sh"
cat >"$PANE2_SCRIPT" <<PANE2
#!/usr/bin/env bash
BEACON_VM="${BEACON_VM}"
echo "==> [rsbeacon] waiting for rsbeacon log on \$BEACON_VM..."
until ssh "\$BEACON_VM" "test -s /tmp/rsbeacon-poc.log" 2>/dev/null; do
  printf '.'; sleep 0.5
done
echo ""
echo "==> [rsbeacon] tailing /tmp/rsbeacon-poc.log on \$BEACON_VM"
echo "------------------------------------------------------------"
ssh "\$BEACON_VM" "tail -n +1 -f /tmp/rsbeacon-poc.log"
PANE2
chmod +x "$PANE2_SCRIPT"

# ── Create tmux window (in current session if inside tmux, else a new one) ─
if [[ -z "$SESSION" ]]; then
	SESSION="rscaller-poc"
	tmux kill-session -t "$SESSION" 2>/dev/null || true
	tmux new-session -d -s "$SESSION" -x "$(tput cols 2>/dev/null || echo 200)" -y "$(tput lines 2>/dev/null || echo 50)"
	tmux rename-window -t "$SESSION:" "$WIN"
else
	tmux kill-window -t "$SESSION:$WIN" 2>/dev/null || true
	sleep 0.1
	tmux new-window -t "$SESSION:" -n "$WIN" -c "$REPO_ROOT" -d
fi

tmux split-window -t "$SESSION:$WIN.1" -h -c "$REPO_ROOT"

tmux select-pane -t "$SESSION:$WIN.1" -T "rsclient"
tmux select-pane -t "$SESSION:$WIN.2" -T "rsbeacon"

tmux send-keys -t "$SESSION:$WIN.1" "bash '$PANE1_SCRIPT'" Enter
tmux send-keys -t "$SESSION:$WIN.2" "bash '$PANE2_SCRIPT'" Enter

echo "==> Window '$WIN' ready in session '$SESSION' (panes: rsclient | rsbeacon)"
tmux select-window -t "$SESSION:$WIN"
tmux select-pane -t "$SESSION:$WIN.1"
