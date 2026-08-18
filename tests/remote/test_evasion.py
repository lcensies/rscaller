"""
test_evasion.py — verify rscaller FS evasion: ip addr must NOT execute on dev-vm-2.

Scenario
--------
- `ip` is temporarily removed from dev-vm-2 (the beacon/target).
- dev-vm-1 (the rsc client) opens a rscfuse FUSE mount of dev-vm-2's filesystem,
  then reads /proc/net/fib_trie through that mount to get dev-vm-2's IP addresses.
- Tracee (eBPF, via Docker) watches for execve/execveat events on dev-vm-2.

Pass conditions
---------------
1. dev-vm-1 successfully retrieves dev-vm-2's IP addresses (FUSE read works).
2. Tracee on dev-vm-2 sees zero execve events matching "ip" (binary ran on dev-vm-1,
   not on dev-vm-2 — the whole point of rscfuse evasion).

test_negative_control verifies tracee IS active by running ip addr directly
on dev-vm-2 and asserting the execve appears.
"""
from __future__ import annotations

import time
import pytest

from conftest import run, run_bg, REMOTE_DIR, vm_sync_clock
from obs import Tracee

BEACON_BIN = "/home/ubuntu/rsbeacon"
MOUNT_BASE = "/tmp/rsc-evasion"
MOUNT_NAME = "evasion"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tracee(host: str) -> Tracee:
    return Tracee(
        run_fn=lambda cmd: run(host, cmd),
        events=["execve", "execveat"],
        name="tracee-evasion",
    )


def _parse_fib_trie(text: str) -> set[str]:
    """Extract /32 LOCAL host IPs from /proc/net/fib_trie output.

    The kernel emits lines like:
       |-- 192.168.122.180
          /32 host LOCAL
    We track the last IP seen on a '|-- <ip>' line and add it when the
    next line contains '/32 ... host ... LOCAL'.
    """
    ips: set[str] = set()
    last_ip = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("|-- "):
            last_ip = s[4:]
        elif "/32" in s and "host" in s and "LOCAL" in s and last_ip:
            ips.add(last_ip)
            last_ip = ""
    return ips


RSC_MOUNT_TIMEOUT = 20   # seconds to wait for FUSE mount to appear
RSC_EXEC_TIMEOUT  = 30   # seconds for the long-lived rsc exec process (sleep)


def _rsc_read_fib_trie(client: str, beacon_ip: str, beacon_port: int) -> set[str]:
    """
    On client (dev-vm-1): rsc exec → FUSE mount of beacon → cat fib_trie.
    Returns the set of IP addresses found in beacon's /proc/net/fib_trie.

    No cleanup: caller is expected to hold a client_snapshotted fixture so the
    VM is reverted to clean state after the test regardless of outcome.
    """
    rsc      = f"{REMOTE_DIR}/target/release/rsc"
    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    mount_point = f"{MOUNT_BASE}/{MOUNT_NAME}"

    run(client, f"mkdir -p '{MOUNT_BASE}'")

    print(f"[rsc_read] launching rsc exec on {client} → beacon {beacon_ip}:{beacon_port}", flush=True)
    # rsc fuse is a subcommand of rsc itself — no separate rscfuse binary needed.
    run_bg(client,
           f"nohup {rsc} exec "
           f"--beacon '{beacon_ip}:{beacon_port}' "
           f"--rsclient '{rsclient}' "
           f"--mount-base '{MOUNT_BASE}' "
           f"--name '{MOUNT_NAME}' "
           f"-- sleep {RSC_EXEC_TIMEOUT} "
           f">/tmp/rsc-evasion.log 2>&1")

    # Poll until rscfuse mounts the beacon's /proc tree.
    # mountpoint(1) reads the kernel mount table — never triggers FUSE.
    fib_trie_path = f"{mount_point}/proc/net/fib_trie"
    deadline = time.time() + RSC_MOUNT_TIMEOUT
    while time.time() < deadline:
        r = run(client, f"mountpoint -q '{mount_point}' 2>/dev/null && echo ok || echo wait")
        status = r.stdout.strip()
        print(f"[rsc_read] mount poll: {status}", flush=True)
        if status == "ok":
            break
        time.sleep(1)
    else:
        log = run(client, "cat /tmp/rsc-evasion.log 2>/dev/null")
        print(f"[rsc_read] mount never appeared; rsc exec log:\n{log.stdout}", flush=True)
        return set()

    print(f"[rsc_read] FUSE mount ready; reading {fib_trie_path}", flush=True)
    r = run(client, f"cat '{fib_trie_path}'")
    print(f"[rsc_read] cat exit={r.return_code} stdout_len={len(r.stdout)} stderr={r.stderr.strip()[:200]}", flush=True)
    if r.stdout:
        print(f"[rsc_read] first 300 chars of fib_trie:\n{r.stdout[:300]}", flush=True)
    return _parse_fib_trie(r.stdout) if r.ok else set()


# ---------------------------------------------------------------------------
# Module-level fixture: pull tracee image once
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def ensure_tracee_image(beacon_host):
    # Sync the VM clock first: on a freshly reverted baseline the clock is
    # weeks behind and docker.io's TLS cert is "not yet valid", so the pull
    # fails spuriously (seen in practice).
    vm_sync_clock(beacon_host)
    _make_tracee(beacon_host).ensure_image()


@pytest.fixture(scope="module", autouse=True)
def cleanup_rsc_leftovers(client):
    """Module teardown: kill the rsc exec / rscfuse this file leaves running.

    _rsc_read_fib_trie starts `rsc exec -- sleep N` via run_bg and never
    reaps it (per-test revert only happens BEFORE a test). When this file is
    followed by another suite (make test-vm), the stale FUSE mount + dead
    beacon connection breaks the next file's rsc exec. Clean up after
    ourselves."""
    yield
    run(client, "pkill -9 -f 'rsc exec' 2>/dev/null; pkill -9 rsclient 2>/dev/null; "
                "pkill -9 -f 'rsc fuse' 2>/dev/null; pkill -9 sleep 2>/dev/null || true")
    run(client,
        f"fusermount -u {MOUNT_BASE}/{MOUNT_NAME} 2>/dev/null || "
        f"umount -l {MOUNT_BASE}/{MOUNT_NAME} 2>/dev/null || true; "
        f"rm -rf {MOUNT_BASE}")


# ---------------------------------------------------------------------------
# Function-scoped fixtures for the evasion test
# ---------------------------------------------------------------------------

@pytest.fixture()
def rsbeacon(beacon_host, beacon_port):
    """Start rsbeacon on beacon_host for a single test."""
    run(beacon_host, "sudo pkill rsbeacon 2>/dev/null || true")
    time.sleep(0.2)
    run_bg(beacon_host,
           f"nohup sudo {BEACON_BIN} --listen 0.0.0.0:{beacon_port} "
           f">/tmp/rsbeacon-evasion.log 2>&1")
    time.sleep(1)
    r = run(beacon_host, f"ss -tlnp | grep ':{beacon_port}'")
    if not r.ok:
        log = run(beacon_host, "cat /tmp/rsbeacon-evasion.log 2>/dev/null")
        pytest.fail(f"rsbeacon failed to start:\n{log.stdout}")
    yield
    run(beacon_host, "sudo pkill rsbeacon 2>/dev/null || true")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.timeout(300)
def test_negative_control(beacon_host):
    """
    Negative control: ip addr run directly on dev-vm-2 must appear in tracee.
    If this fails, eBPF hooks are broken and the evasion test result is meaningless.
    """
    tracee = _make_tracee(beacon_host)
    tracee.start(settle_secs=3.0)

    # Use the real binary path (not the symlink) so the execve is unambiguous.
    r = run(beacon_host, "readlink -f $(which ip 2>/dev/null) 2>/dev/null || echo /usr/sbin/ip")
    ip_bin = r.stdout.strip() or "/usr/sbin/ip"
    run(beacon_host, f"{ip_bin} addr >/dev/null 2>&1 || true")

    # Tracee flushes events with a lag — poll until the execve appears
    # (fixed 1s sleep raced the flush and lost the event in practice).
    deadline = time.time() + 15
    while time.time() < deadline:
        if tracee.execve_matches(tracee.peek(), pattern="ip"):
            break
        time.sleep(1)

    events = tracee.stop()

    print(f"\n[negative-control] tracee captured {len(events)} event(s) on {beacon_host}:")
    for e in events:
        print("  " + tracee.format_event(e))

    ip_events = tracee.execve_matches(events, pattern="ip")
    assert ip_events, (
        f"tracee saw 0 execve events for 'ip' even though ip addr ran directly "
        f"on {beacon_host} — eBPF probes may not be loading correctly."
    )


@pytest.mark.timeout(300)
def test_evasion(client, beacon_host, beacon_ip, beacon_port,
                 client_snapshotted, beacon_snapshotted, rsbeacon):
    """
    Core evasion test.

    Fixture setup order: client_snapshotted → beacon_snapshotted → rsbeacon
    Fixture teardown order (LIFO): rsbeacon → beacon_snapshotted → client_snapshotted

    beacon_snapshotted snapshots dev-vm-2 BEFORE ip removal and BEFORE rsbeacon
    starts, so revert restores the ip binary and leaves dev-vm-2 fully clean.
    client_snapshotted reverts dev-vm-1 after, removing any FUSE mounts / procs.

    dev-vm-1 reads dev-vm-2's /proc/net/fib_trie via rscfuse FUSE mount.
    dev-vm-2's tracee must capture zero execve events matching 'ip' —
    proving the binary never ran on dev-vm-2.
    """
    # 1. Remove ip from dev-vm-2 to simulate absent tool.
    r = run(beacon_host, "readlink -f $(which ip 2>/dev/null) 2>/dev/null || true")
    real_ip = r.stdout.strip()
    if not real_ip:
        # Maybe a leftover from a previous dirty run — check for backup
        r2 = run(beacon_host, "find /usr/bin /usr/sbin /sbin /bin -name 'ip.evasion-bak' 2>/dev/null | head -1")
        real_ip = r2.stdout.strip().removesuffix(".evasion-bak")
    if real_ip:
        run(beacon_host, f"sudo mv '{real_ip}' '{real_ip}.evasion-bak'")

    # 2. Confirm ip is actually absent on dev-vm-2.
    r = run(beacon_host, "command -v ip 2>/dev/null || true")
    assert not r.stdout.strip(), \
        f"Expected 'ip' to be absent on {beacon_host} but found: {r.stdout.strip()!r}"

    # 3. Start tracee, run FUSE read, stop tracee.
    tracee = _make_tracee(beacon_host)
    tracee.start(settle_secs=3.0)

    ips = _rsc_read_fib_trie(client, beacon_ip, beacon_port)

    events = tracee.stop()

    # Restore ip binary regardless of test outcome.
    if real_ip:
        run(beacon_host, f"sudo mv '{real_ip}.evasion-bak' '{real_ip}' 2>/dev/null || true")

    # 4. Print events for debug visibility regardless of outcome.
    print(f"\n[evasion] tracee captured {len(events)} event(s) on {beacon_host}:")
    for e in events:
        print("  " + tracee.format_event(e))

    # 5. Assert: FUSE read actually returned dev-vm-2's network info.
    rsc_log = run(client, "cat /tmp/rsc-evasion.log 2>/dev/null")
    print(f"\n[evasion] rsc exec log:\n{rsc_log.stdout}", flush=True)
    mount_status = run(client, f"mount | grep '{MOUNT_NAME}' || echo '(no mount found)'")
    print(f"[evasion] mount status: {mount_status.stdout.strip()}", flush=True)
    print(f"[evasion] IPs found: {sorted(ips)}", flush=True)
    assert ips, (
        "rsc exec returned no IP addresses — FUSE mount or cat command failed. "
        "Check that rsbeacon is running on dev-vm-2 and rscfuse is built."
    )
    assert beacon_ip in ips, (
        f"Expected beacon IP {beacon_ip!r} in FUSE /proc/net/fib_trie; "
        f"got IPs: {sorted(ips)}"
    )

    # 6. Assert: no execve for 'ip' on dev-vm-2.
    ip_events = tracee.execve_matches(events, pattern="ip")
    assert not ip_events, (
        f"tracee captured {len(ip_events)} 'ip'-related execve event(s) on {beacon_host} "
        f"(expected 0 — rscfuse should be transparent):\n"
        + "\n".join("  " + tracee.format_event(e) for e in ip_events)
    )
