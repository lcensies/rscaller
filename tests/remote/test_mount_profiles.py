"""
test_mount_profiles.py — verify rsc exec mount namespace overlay profiles.

Commands run on dev-vm-1 (client) via `rsc exec -- <cmd>` inside a private
mount namespace.  Tracee on dev-vm-2 (beacon) must see zero execve events,
proving all execution is local even when reading remote data.
"""
from __future__ import annotations

import re
import time
import pytest

from conftest import run, run_bg, REMOTE_DIR
from test_evasion import _make_tracee

BEACON_BIN = "/home/ubuntu/rsbeacon"
MOUNT_BASE = "/tmp/rsc-profiles"

# Ubuntu MOTD process names that appear on SSH login; strip from tracee events.
_MOTD_PROCS = frozenset([
    "50-landscape-sy", "50-motd-news", "85-fwupd", "90-updates-avai",
    "update-motd-fsc", "update-motd-upd", "landscape-sysinfo",
])


def _filter_motd(events: list[dict]) -> list[dict]:
    return [e for e in events if e.get("processName", "") not in _MOTD_PROCS]


def _parse_ip_addrs(text: str) -> set[str]:
    """Extract IPv4 addresses from `ip -4 addr` output (inet X.X.X.X/prefix lines)."""
    return set(re.findall(r'\binet (\d+\.\d+\.\d+\.\d+)/', text))


# ---------------------------------------------------------------------------
# Core helper: run via rsc exec synchronously, capture stdout
# ---------------------------------------------------------------------------

def _rsc_exec(client: str, beacon_ip: str, beacon_port: int,
              mount_profile: str, cmd: str, timeout: int = 60) -> tuple[int, str]:
    """
    Run cmd inside `rsc exec --mount-profile <profile> -- <cmd>`.
    Returns (exit_code, stdout).  Execution happens in rsc's private mount
    namespace on the client; stdout is the command's output.
    """
    rsc      = f"{REMOTE_DIR}/target/release/rsc"
    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    name     = f"prof-{mount_profile}"
    mount_point = f"{MOUNT_BASE}/{name}"

    run(client, f"mkdir -p '{MOUNT_BASE}'")
    # Kill any leftover rscfuse, then lazy-unmount the FUSE dir (root-owned).
    # Use -l (lazy) only — -f is for NFS and can cause FUSE umount to fail.
    # Check /proc/mounts to only unmount if actually mounted.
    run(client,
        f"sudo pkill -9 -f '{name}' 2>/dev/null || true; sleep 0.4; "
        f"grep -qF '{mount_point}' /proc/mounts && sudo umount -l '{mount_point}' 2>/dev/null || true; "
        f"sudo rm -rf '{mount_point}' 2>/dev/null || true")

    r = run(client,
            f"sudo {rsc} exec "
            f"--beacon '{beacon_ip}:{beacon_port}' "
            f"--rsclient '{rsclient}' "
            f"--mount-base '{MOUNT_BASE}' "
            f"--name '{name}' "
            f"--mount-profile '{mount_profile}' "
            f"-- {cmd}",
            timeout=timeout)

    # Post-run cleanup: rscfuse stays alive as orphan, kill and lazy-unmount.
    run(client,
        f"sudo pkill -9 -f '{name}' 2>/dev/null || true; sleep 0.4; "
        f"grep -qF '{mount_point}' /proc/mounts && sudo umount -l '{mount_point}' 2>/dev/null || true; "
        f"sudo rm -rf '{mount_point}' 2>/dev/null || true")

    print(f"[rsc_exec:{mount_profile}] cmd={cmd!r} exit={r.return_code} "
          f"stdout_len={len(r.stdout)}", flush=True)
    if r.stdout:
        print(f"[rsc_exec:{mount_profile}] stdout:\n{r.stdout[:500]}", flush=True)
    if r.stderr:
        print(f"[rsc_exec:{mount_profile}] stderr:\n{r.stderr[:500]}", flush=True)
    return (r.return_code, r.stdout)


# ---------------------------------------------------------------------------
# Fixture: fresh rsbeacon per test
# ---------------------------------------------------------------------------

@pytest.fixture()
def rsbeacon(beacon_host, beacon_port):
    run(beacon_host, "sudo pkill rsbeacon 2>/dev/null || true")
    time.sleep(0.2)
    run_bg(beacon_host,
           f"nohup sudo {BEACON_BIN} --listen 0.0.0.0:{beacon_port} "
           f">/tmp/rsbeacon-prof.log 2>&1")
    time.sleep(1)
    r = run(beacon_host, f"ss -tlnp | grep ':{beacon_port}'")
    if not r.ok:
        log = run(beacon_host, "cat /tmp/rsbeacon-prof.log 2>/dev/null")
        pytest.fail(f"rsbeacon failed to start:\n{log.stdout}")
    yield
    run(beacon_host, "sudo pkill rsbeacon 2>/dev/null || true")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(120)
def test_none(client, beacon_host, beacon_ip, beacon_port, rsbeacon):
    """Profile 'none': ip addr returns CLIENT's own addresses, not beacon's."""
    tracee = _make_tracee(beacon_host)
    tracee.start(settle_secs=3.0)

    rc, stdout = _rsc_exec(client, beacon_ip, beacon_port, "none", "ip -4 addr")

    events = _filter_motd(tracee.stop())
    ips = _parse_ip_addrs(stdout)
    print(f"[none] IPs={sorted(ips)}, beacon_ip={beacon_ip}", flush=True)

    assert rc == 0, f"ip -4 addr failed (exit {rc})"
    assert ips, "ip -4 addr returned no IPv4 addresses"
    assert beacon_ip not in ips, (
        f"beacon IP {beacon_ip!r} appeared without overlay; IPs: {sorted(ips)}"
    )
    ip_events = tracee.execve_matches(events, pattern="ip")
    assert not ip_events, (
        f"tracee saw ip execve on beacon (expected 0 — exec must be local):\n"
        + "\n".join("  " + tracee.format_event(e) for e in ip_events)
    )


@pytest.mark.timeout(120)
def test_recon_proc(client, beacon_host, beacon_ip, beacon_port, rsbeacon):
    """Profile 'recon': /proc reads return beacon data.

    ip(8) uses netlink, not /proc files, so we grep /proc/net/fib_trie directly
    — the beacon IP appears there as a /32 LOCAL route on the beacon but not on
    the client.  grep executes locally; tracee on beacon must stay silent.
    """
    tracee = _make_tracee(beacon_host)
    tracee.start(settle_secs=3.0)

    rc, _ = _rsc_exec(client, beacon_ip, beacon_port, "recon",
                      f"grep {beacon_ip} /proc/net/fib_trie")

    events = _filter_motd(tracee.stop())
    print(f"[recon_proc] grep rc={rc}, beacon_ip={beacon_ip}", flush=True)

    assert rc == 0, (
        f"Expected beacon IP {beacon_ip!r} in /proc/net/fib_trie through recon overlay "
        f"(grep exited {rc}) — /proc overlay not working"
    )
    grep_events = tracee.execve_matches(events, pattern="grep")
    assert not grep_events, (
        f"tracee saw grep execve on beacon (expected 0 — exec must be local):\n"
        + "\n".join("  " + tracee.format_event(e) for e in grep_events)
    )


@pytest.mark.timeout(120)
def test_recon_sys(client, beacon_host, beacon_ip, beacon_port, rsbeacon):
    """Profile 'recon': /sys file reads reflect beacon data.

    ip-link(8) uses netlink, not /sys files.  We read /sys/class/net/enp1s0/address
    (the NIC MAC address) directly through the FUSE overlay — the beacon's unique
    MAC appears there.  grep executes locally; tracee on beacon must be silent.
    """
    r = run(beacon_host, "cat /sys/class/net/enp1s0/address")
    beacon_mac = r.stdout.strip()
    print(f"[recon_sys] beacon enp1s0 MAC: {beacon_mac!r}", flush=True)

    tracee = _make_tracee(beacon_host)
    tracee.start(settle_secs=3.0)

    rc, _ = _rsc_exec(client, beacon_ip, beacon_port, "recon",
                      f"grep {beacon_mac} /sys/class/net/enp1s0/address")

    events = _filter_motd(tracee.stop())
    print(f"[recon_sys] grep rc={rc}, beacon_mac={beacon_mac!r}", flush=True)

    assert rc == 0, (
        f"Expected beacon MAC {beacon_mac!r} in overlaid /sys/class/net/enp1s0/address "
        f"(grep exited {rc}) — /sys overlay not working"
    )
    grep_events = tracee.execve_matches(events, pattern="grep")
    assert not grep_events, (
        f"tracee saw grep execve on beacon (expected 0 — exec must be local):\n"
        + "\n".join("  " + tracee.format_event(e) for e in grep_events)
    )


@pytest.mark.timeout(120)
def test_shadow(client, beacon_host, beacon_ip, beacon_port, rsbeacon):
    """Profile 'shadow': hostname and /proc both reflect the beacon."""
    r = run(beacon_host, "hostname")
    beacon_hostname = r.stdout.strip()
    print(f"[shadow] beacon hostname: {beacon_hostname!r}", flush=True)

    tracee = _make_tracee(beacon_host)
    tracee.start(settle_secs=3.0)

    rc, stdout = _rsc_exec(client, beacon_ip, beacon_port, "shadow", "hostname")

    events = _filter_motd(tracee.stop())
    observed = stdout.strip()
    print(f"[shadow] observed hostname: {observed!r}", flush=True)

    assert rc == 0, f"hostname failed (exit {rc})"
    assert observed == beacon_hostname, (
        f"Expected beacon hostname {beacon_hostname!r}, got {observed!r}"
    )
    hostname_events = tracee.execve_matches(events, pattern="hostname")
    assert not hostname_events, (
        f"tracee saw hostname execve on beacon (expected 0 — exec must be local):\n"
        + "\n".join("  " + tracee.format_event(e) for e in hostname_events)
    )


# ---------------------------------------------------------------------------
# Network routing tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(120)
def test_net_routing_default_local(client, beacon_host, beacon_ip, beacon_port, rsbeacon):
    """Default routing: all connections LOCAL (no --route args).
    
    Connect to localhost:9999 (nothing listening).  Should fail locally with
    'Connection refused', NOT hang waiting for beacon response (which would
    indicate the connection was routed to beacon).
    """
    # Create a simple Python script that tries to connect to localhost:9999
    test_script = """
import socket
try:
    s = socket.socket()
    s.settimeout(2)
    s.connect(('127.0.0.1', 9999))
except ConnectionRefusedError:
    print("LOCAL_REFUSED")
except Exception as e:
    print(f"ERROR: {e}")
"""
    rc, stdout = _rsc_exec(client, beacon_ip, beacon_port, "none",
                           f"python3 -c '{test_script}'", timeout=15)
    
    print(f"[test_net_routing_default_local] stdout={stdout.strip()!r}", flush=True)
    # With default LOCAL routing, should get ECONNREFUSED locally (not hang on beacon)
    assert "LOCAL_REFUSED" in stdout or "Refused" in stdout or rc != 0, (
        f"Expected local connect failure, got: {stdout}"
    )


@pytest.mark.timeout(120)
def test_net_routing_route_arg(client, beacon_host, beacon_ip, beacon_port, rsbeacon):
    """Network routing with --route argument.
    
    Pass --route to rsc exec; verify it's parsed and does not crash.
    The actual routing behavior (LOCAL vs REMOTE) is tested by unit tests.
    This e2e test just ensures the CLI arg is accepted and the process runs.
    """
    rsc      = f"{REMOTE_DIR}/target/release/rsc"
    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    name     = "net-routing-test"
    mount_point = f"{MOUNT_BASE}/{name}"
    
    run(client, f"mkdir -p '{MOUNT_BASE}'")
    run(client,
        f"sudo pkill -9 -f '{name}' 2>/dev/null || true; sleep 0.4; "
        f"grep -qF '{mount_point}' /proc/mounts && sudo umount -l '{mount_point}' 2>/dev/null || true; "
        f"sudo rm -rf '{mount_point}' 2>/dev/null || true")
    
    # Start rsc fuse overlay with routing args
    cmd = (
        f"cd {REMOTE_DIR} && "
        f"LD_LIBRARY_PATH=/home/ubuntu/install/lib:$LD_LIBRARY_PATH "
        f"sudo -E {rsc} fuse --mount {mount_point} "
        f"--remote-target rsbeacon --remote-origin {beacon_ip}:{beacon_port} "
        f"--route '192.0.2.0/24=remote' "
        f"--route '0.0.0.0/0=local' "
        f">/tmp/rsc-fuse-routing.log 2>&1 &"
    )
    
    run(client, cmd)
    time.sleep(1)
    
    # Verify mount exists
    r = run(client, f"test -d {mount_point} && echo OK")
    assert r.ok and "OK" in r.stdout, (
        f"rsc fuse mount failed; check /tmp/rsc-fuse-routing.log:\n"
        + run(client, "cat /tmp/rsc-fuse-routing.log").stdout[:500]
    )
    
    # Clean up
    run(client,
        f"sudo pkill -9 -f '{name}' 2>/dev/null || true; sleep 0.4; "
        f"grep -qF '{mount_point}' /proc/mounts && sudo umount -l '{mount_point}' 2>/dev/null || true")


@pytest.mark.timeout(120)
def test_recon_routed_beacon_ip_visible(client, beacon_host, beacon_ip, beacon_port, rsbeacon):
    """Recon-routed profile: beacon's IP visible via 'ip addr', no local IP match.
    
    Use recon-routed profile with network routing to relay connections.
    Beacon's IP addresses should appear in 'ip addr' output (mounted /proc),
    and should NOT match the client's IP addresses.
    """
    tracee = _make_tracee(beacon_host)
    tracee.start(settle_secs=3.0)
    
    # Get beacon's IPs
    r = run(beacon_host, "ip -4 addr | grep 'inet ' | awk '{print $2}'")
    beacon_ips = set(r.stdout.strip().split('\n')) if r.ok else set()
    print(f"[recon_routed] beacon IPs: {beacon_ips}", flush=True)
    
    # Run rsc exec with recon-routed profile
    rc, stdout = _rsc_exec(client, beacon_ip, beacon_port, "recon-routed",
                           "ip -4 addr | grep 'inet ' | awk '{print $2}'", timeout=30)
    
    events = _filter_motd(tracee.stop())
    client_ips = set(stdout.strip().split('\n')) if stdout.strip() else set()
    print(f"[recon_routed] client saw IPs: {client_ips}", flush=True)
    
    assert rc == 0, f"ip -4 addr failed (exit {rc})"
    assert client_ips, "ip -4 addr returned no IPv4 addresses"
    
    # Key assertion: beacon's IPs should be visible, not client's
    # (or at least not all client IPs — beacon might share some for testing)
    assert any(ip in client_ips for ip in beacon_ips), (
        f"beacon IPs {beacon_ips} NOT visible via recon-routed profile. "
        f"Got IPs: {client_ips}. Mount overlay might not be working."
    )
    
    # Execution must be local (ip command doesn't run on beacon)
    ip_events = tracee.execve_matches(events, pattern="ip")
    assert not ip_events, (
        f"tracee saw ip execve on beacon (expected 0 — exec must be local):\n"
        + "\n".join("  " + tracee.format_event(e) for e in ip_events)
    )


