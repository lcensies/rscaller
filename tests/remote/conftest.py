"""
Remote integration test harness.

All SSH is handled via Fabric/paramiko.  Only truly local operations
(virsh, deploy.sh) use subprocess.

Beacon topology
---------------
rsbeacon always runs on `beacon_host` (default: dev-vm-2).
`rsc` on `client` (default: dev-vm-1) connects directly to beacon_host's IP —
no localhost tunnel needed.  `beacon_ip` resolves the address as seen from client.

The local rsbeacon + paramiko tunnel fixtures are kept only for the legacy
kmod `rsclient` path.
"""
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest
from fabric import Connection

REPO_ROOT = Path(__file__).parent.parent.parent
REMOTE_DIR = "/home/ubuntu/rscaller"


# ---------------------------------------------------------------------------
# Fabric helpers
# ---------------------------------------------------------------------------

def _conn(host: str) -> Connection:
    return Connection(host, connect_timeout=10,
                      connect_kwargs={"allow_agent": True, "look_for_keys": True})


def run(host: str, cmd: str, warn: bool = True, hide: bool = True):
    """Run cmd on host; returns a fabric Result. Never raises on non-zero exit."""
    with _conn(host) as c:
        return c.run(cmd, warn=warn, hide=hide, in_stream=False)


def run_bg(host: str, cmd: str):
    """Fire-and-forget: run cmd on host via disown, return immediately."""
    with _conn(host) as c:
        c.run(cmd, disown=True, in_stream=False)


# ---------------------------------------------------------------------------
# VM lifecycle
# ---------------------------------------------------------------------------

def wait_for_ssh(host: str, retries: int = 30, interval: int = 3):
    for _ in range(retries):
        try:
            if run(host, "echo ok").ok:
                return
        except Exception:
            pass
        time.sleep(interval)
    pytest.fail(f"Host {host!r} unreachable after {retries * interval}s")


def vm_restart(vm_name: str):
    """Hard-reset a libvirt VM — no controlling TTY needed."""
    subprocess.run(["virsh", "destroy", vm_name], capture_output=True)
    time.sleep(1)
    subprocess.run(["virsh", "start", vm_name], check=True, capture_output=True)


# ---------------------------------------------------------------------------
# pytest options
# ---------------------------------------------------------------------------

def pytest_addoption(parser):
    parser.addoption("--remote",       default="dev-vm-1",
                     help="SSH host for the interceptor VM")
    parser.addoption("--client",       default=None,
                     help="SSH host that runs rsc/rsclient (default: --remote)")
    parser.addoption("--beacon-host",  default="dev-vm-2",
                     help="SSH host where rsbeacon runs")
    parser.addoption("--beacon-port",  type=int, default=9999)
    parser.addoption("--no-deploy",    action="store_true",
                     help="Skip rsync+build deploy step")
    parser.addoption("--kmod",         action="store_true",
                     help="Enable kmod load/unload tests (opt-in)")
    parser.addoption("--no-seccomp",   action="store_true",
                     help="Disable seccomp-unotify tests (on by default)")
    parser.addoption("--no-e2e",       action="store_true",
                     help="Disable E2E tests that require beacon-host (on by default)")
    parser.addoption("--vm-name",      default=None,
                     help="libvirt domain for auto-restart (default: --remote)")


# ---------------------------------------------------------------------------
# Session fixtures — topology
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def remote(pytestconfig):
    return pytestconfig.getoption("--remote")


@pytest.fixture(scope="session")
def client(pytestconfig, remote):
    return pytestconfig.getoption("--client") or remote


@pytest.fixture(scope="session")
def beacon_host(pytestconfig):
    return pytestconfig.getoption("--beacon-host")


@pytest.fixture(scope="session")
def beacon_port(pytestconfig):
    return pytestconfig.getoption("--beacon-port")


@pytest.fixture(scope="session")
def vm_name(pytestconfig, remote):
    return pytestconfig.getoption("--vm-name") or remote


@pytest.fixture(scope="session")
def beacon_ip(client, beacon_host):
    """IP of beacon_host as reachable from client (resolved via SSH on client)."""
    r = run(beacon_host, "hostname -I | awk '{print $1}'")
    ip = r.stdout.strip()
    assert ip, f"could not resolve IP of {beacon_host}"
    return ip


# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

def _deploy_to(host: str, vm_name: str):
    try:
        run(host, "echo ok")
    except Exception:
        vm_restart(vm_name)
        wait_for_ssh(host)

    try:
        subprocess.run(
            ["bash", str(REPO_ROOT / "scripts/deploy.sh"), host],
            check=True,
        )
    except subprocess.CalledProcessError:
        vm_restart(vm_name)
        wait_for_ssh(host)
        subprocess.run(
            ["bash", str(REPO_ROOT / "scripts/deploy.sh"), host],
            check=True,
        )


@pytest.fixture(scope="session", autouse=True)
def deploy(pytestconfig, remote, vm_name):
    if pytestconfig.getoption("--no-deploy"):
        return
    _deploy_to(remote, vm_name)


BEACON_BIN = "/home/ubuntu/rsbeacon"

@pytest.fixture(scope="session")
def deploy_beacon(pytestconfig, remote, beacon_host):
    """Copy the rsbeacon binary from remote (dev-vm-1) to beacon_host (dev-vm-2)."""
    if pytestconfig.getoption("--no-deploy") or pytestconfig.getoption("--no-e2e"):
        return
    # scp from remote where it was built — no build on beacon_host needed.
    subprocess.run(
        ["scp", f"{remote}:{REMOTE_DIR}/target/release/rsbeacon",
         f"{beacon_host}:{BEACON_BIN}"],
        check=True,
    )
    run(beacon_host, f"chmod +x {BEACON_BIN}")


# ---------------------------------------------------------------------------
# kmod (legacy, opt-in)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def kmod(pytestconfig, remote, deploy):
    if not pytestconfig.getoption("--kmod"):
        pytest.skip("kmod disabled — pass --kmod to enable")
    run(remote,
        "pkill -9 rsclient 2>/dev/null || true; sleep 0.3; "
        "lsmod | grep -q '^rscaller' && sudo rmmod rscaller 2>/dev/null || true")
    r = run(remote, f"cd {REMOTE_DIR}/kmod && sudo insmod rscaller.ko")
    assert r.ok, f"insmod failed:\n{r.stderr}"
    yield
    run(remote,
        "pkill -9 rsclient 2>/dev/null || true; sleep 0.3; "
        "sudo rmmod rscaller 2>/dev/null || sudo rmmod -f rscaller 2>/dev/null || true")


# ---------------------------------------------------------------------------
# Beacon — rsbeacon on beacon_host (dev-vm-2)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def rsbeacon_on_beacon(pytestconfig, beacon_host, beacon_port, deploy_beacon):
    """Start rsbeacon on beacon_host, listening on all interfaces."""
    if pytestconfig.getoption("--no-e2e"):
        pytest.skip("E2E disabled via --no-e2e")
    run(beacon_host, "pkill -9 rsbeacon 2>/dev/null || true")
    run_bg(beacon_host,
           f"nohup sudo {BEACON_BIN} "
           f"--listen 0.0.0.0:{beacon_port} "
           f">/tmp/rsbeacon.log 2>&1")
    time.sleep(1)
    r = run(beacon_host, f"ss -tlnp | grep ':{beacon_port}'")
    if not r.ok:
        log = run(beacon_host, "cat /tmp/rsbeacon.log 2>/dev/null")
        pytest.fail(f"rsbeacon failed to start on {beacon_host}:\n{log.stdout}")
    yield
    run(beacon_host, "sudo pkill -9 rsbeacon 2>/dev/null || true")


# ---------------------------------------------------------------------------
# Legacy: local rsbeacon + paramiko reverse tunnel (kmod rsclient path only)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def rsbeacon_local(beacon_port):
    """Start rsbeacon on localhost — used only by the kmod rsclient fixture."""
    bin_path = REPO_ROOT / "target/release/rsbeacon"
    assert bin_path.exists(), "rsbeacon not built locally — run: cargo build -p rsbeacon --release"
    subprocess.run(["pkill", "rsbeacon"], capture_output=True)
    proc = subprocess.Popen(
        [str(bin_path), "--listen", f"127.0.0.1:{beacon_port}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(0.5)
    yield proc
    proc.terminate()
    proc.wait()


def _forward_channel(chan, local_port: int):
    try:
        sock = socket.create_connection(("127.0.0.1", local_port))
    except OSError:
        chan.close()
        return

    def pump(src, dst):
        try:
            while chunk := src.recv(4096):
                dst.sendall(chunk)
        except Exception:
            pass
        finally:
            try: src.close()
            except Exception: pass
            try: dst.close()
            except Exception: pass

    threading.Thread(target=pump, args=(chan, sock), daemon=True).start()
    threading.Thread(target=pump, args=(sock, chan), daemon=True).start()


@pytest.fixture(scope="session")
def beacon_tunnel(client, beacon_port, rsbeacon_local):
    """Reverse paramiko tunnel: client:beacon_port → localhost:beacon_port (kmod only)."""
    conn = _conn(client)
    conn.open()
    transport = conn.client.get_transport()
    transport.request_port_forward("127.0.0.1", beacon_port)
    stop = threading.Event()

    def _accept_loop():
        while not stop.is_set():
            chan = transport.accept(timeout=1)
            if chan is not None:
                threading.Thread(
                    target=_forward_channel, args=(chan, beacon_port), daemon=True
                ).start()

    threading.Thread(target=_accept_loop, daemon=True).start()
    time.sleep(0.5)
    yield
    stop.set()
    transport.cancel_port_forward("127.0.0.1", beacon_port)
    conn.close()


# ---------------------------------------------------------------------------
# rsclient (kmod backend)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def rsclient(client, beacon_port, beacon_tunnel, kmod):
    run(client, "pkill -9 rsclient 2>/dev/null || true")
    run_bg(client,
           f"nohup {REMOTE_DIR}/target/release/rsclient "
           f"--beacon '127.0.0.1:{beacon_port}' "
           f"--proc-path /proc/rscaller "
           f">/tmp/rsclient.log 2>&1")
    time.sleep(1)
    r = run(client, "pgrep -fa rsclient | grep -v grep")
    if not r.ok:
        log = run(client, "cat /tmp/rsclient.log 2>/dev/null")
        pytest.fail(f"rsclient failed to start:\n{log.stdout}")
    yield
    run(client, "pkill -9 rsclient 2>/dev/null || true")


# ---------------------------------------------------------------------------
# rsc seccomp (default, on by default)
# beacon always on beacon_host — direct TCP, no tunnel
# ---------------------------------------------------------------------------

def _seccomp_cleanup(client, mount_dir: str):
    run(client, "pkill -9 rsclient 2>/dev/null; pkill -9 sleep 2>/dev/null || true")
    run(client,
        f"fusermount -u {mount_dir}/default 2>/dev/null || "
        f"umount -l {mount_dir}/default 2>/dev/null || true; "
        f"rm -rf {mount_dir}")


@pytest.fixture(scope="session")
def rsc_seccomp(pytestconfig, client, beacon_ip, beacon_port,
                rsbeacon_on_beacon, deploy):
    """rsc exec on client, rsbeacon on beacon_host — direct TCP, no tunnel.

    Requires --no-seccomp to disable.  Skipped automatically when --no-e2e
    is set (since rsbeacon_on_beacon will skip first).
    """
    if pytestconfig.getoption("--no-seccomp"):
        pytest.skip("seccomp disabled via --no-seccomp")

    mount_dir = "/tmp/rsc-mount"
    _seccomp_cleanup(client, mount_dir)
    run(client, f"mkdir -p {mount_dir}")

    rsc      = f"{REMOTE_DIR}/target/release/rsc"
    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    rscfuse  = f"{REMOTE_DIR}/target/release/rscfuse"

    run_bg(client,
           f"nohup {rsc} exec "
           f"--beacon '{beacon_ip}:{beacon_port}' "
           f"--encryption none "
           f"--rsclient {rsclient} "
           f"--rscfuse {rscfuse} "
           f"--mount-base {mount_dir} "
           f"--name default "
           f"-- sh -c 'kill -0 1; exec sleep 60' "
           f">/tmp/rsc-seccomp.log 2>&1")
    time.sleep(3)

    r = run(client, "pgrep -fa rsclient | grep -v grep")
    if not r.ok:
        log = run(client, "cat /tmp/rsc-seccomp.log 2>/dev/null")
        pytest.fail(f"rsc seccomp failed to start rsclient:\n{log.stdout}")
    yield
    _seccomp_cleanup(client, mount_dir)
