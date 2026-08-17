"""TLS encryption E2E: rsbeacon --encryption tls on beacon_host, rsc exec
--encryption tls on client, FUSE read/write verified through the encrypted
channel.

Self-contained: uses its own beacon port (9998) and mount dir so it can run
in the same session as the plain-TCP fixtures without disturbing them.
"""
import time
import uuid

import pytest

from conftest import run, run_bg, REMOTE_DIR, BEACON_BIN

TLS_PORT = 9998
MOUNT_DIR = "/tmp/rsc-mount-tls"
CA_PATH = "/tmp/rsc-tls-ca.pem"


def _tls_cleanup(client, beacon_host):
    run(client, "pkill -9 rsclient 2>/dev/null; pkill -9 sleep 2>/dev/null || true")
    run(client,
        f"fusermount -u {MOUNT_DIR}/default 2>/dev/null || "
        f"umount -l {MOUNT_DIR}/default 2>/dev/null || true; "
        f"rm -rf {MOUNT_DIR} {CA_PATH}")
    run(beacon_host, f"sudo pkill -9 -f 'rsbeacon.*:{TLS_PORT}' 2>/dev/null || true")


@pytest.fixture(scope="session")
def rsc_tls(pytestconfig, client, beacon_host, beacon_ip, deploy, deploy_beacon):
    if pytestconfig.getoption("--no-e2e"):
        pytest.skip("E2E disabled via --no-e2e")

    _tls_cleanup(client, beacon_host)
    run(client, f"mkdir -p {MOUNT_DIR}")

    # Beacon with TLS (embedded self-signed identity).
    run_bg(beacon_host,
           f"nohup sudo {BEACON_BIN} "
           f"--listen 0.0.0.0:{TLS_PORT} "
           f"--encryption tls "
           f">/tmp/rsbeacon-tls.log 2>&1")
    time.sleep(1)
    r = run(beacon_host, f"ss -tlnp | grep ':{TLS_PORT}'")
    if not r.ok:
        log = run(beacon_host, "cat /tmp/rsbeacon-tls.log 2>/dev/null")
        pytest.fail(f"TLS rsbeacon failed to start on {beacon_host}:\n{log.stdout}")

    # Provision the embedded CA to the client (--print-ca is the zero-config path).
    ca = run(beacon_host, f"{BEACON_BIN} --print-ca")
    assert ca.ok and "BEGIN CERTIFICATE" in ca.stdout, \
        f"--print-ca did not return a PEM:\n{ca.stdout}\n{ca.stderr}"
    import base64
    b64 = base64.b64encode(ca.stdout.encode()).decode()
    r = run(client, f"echo '{b64}' | base64 -d > {CA_PATH}")
    assert r.ok, f"failed to write CA to client:\n{r.stderr}"

    rsc      = f"{REMOTE_DIR}/target/release/rsc"
    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    run_bg(client,
           f"nohup {rsc} exec "
           f"--beacon '{beacon_ip}:{TLS_PORT}' "
           f"--encryption tls "
           f"--ca-cert {CA_PATH} "
           f"--rsclient {rsclient} "
           f"--mount-base {MOUNT_DIR} "
           f"--name default "
           f"-- sh -c 'kill -0 1; exec sleep 60' "
           f">/tmp/rsc-tls.log 2>&1")
    time.sleep(3)

    r = run(client, "pgrep -fa rsclient | grep -v grep")
    if not r.ok:
        log = run(client, "cat /tmp/rsc-tls.log 2>/dev/null")
        pytest.fail(f"rsc TLS failed to start rsclient:\n{log.stdout}")
    yield
    _tls_cleanup(client, beacon_host)


def test_tls_beacon_listening(rsc_tls, beacon_host):
    r = run(beacon_host, f"ss -tlnp | grep ':{TLS_PORT}'")
    assert r.ok, "TLS beacon not listening"

def test_tls_rsclient_running(rsc_tls, client):
    assert run(client, "pgrep -fa rsclient | grep -v grep").ok

def test_tls_fuse_mounted(rsc_tls, client):
    r = run(client, f"grep '{MOUNT_DIR}/default' /proc/mounts")
    assert r.ok, f"rscfuse (TLS) not mounted:\n{run(client, 'cat /proc/mounts').stdout}"
    assert "fuse" in r.stdout.lower()

def test_tls_file_read_via_fuse(rsc_tls, client, beacon_host):
    sentinel = "rscaller-tls-read-sentinel"
    run(beacon_host, f"echo '{sentinel}' > /tmp/rsc-e2e-tls-read.txt")
    r = run(client, f"cat {MOUNT_DIR}/default/tmp/rsc-e2e-tls-read.txt")
    assert r.ok, f"read via TLS rscfuse failed:\n{r.stderr}"
    assert sentinel in r.stdout, f"content mismatch: got {r.stdout!r}"

def test_tls_file_write_via_fuse(rsc_tls, client, beacon_host):
    sentinel = f"rscaller-tls-write-{uuid.uuid4().hex[:8]}"
    w = run(client, f"echo '{sentinel}' > {MOUNT_DIR}/default/tmp/rsc-e2e-tls-write.txt")
    assert w.ok, f"write through TLS rscfuse failed:\n{w.stderr}"
    r = run(beacon_host, "cat /tmp/rsc-e2e-tls-write.txt")
    assert r.ok and sentinel in r.stdout, \
        f"file missing/mismatched on beacon_host: {r.stdout!r} {r.stderr!r}"


# ---------------------------------------------------------------------------
# Custom identity via rsc certs-gen (no shell scripts involved)
# ---------------------------------------------------------------------------

CUSTOM_PORT = 9996
CUSTOM_DIR = "/tmp/rsc-certs"
CUSTOM_MOUNT = "/tmp/rsc-mount-tlsc"


def test_tls_custom_identity(rsc_tls, client, beacon_host, beacon_ip):
    """rsc certs-gen output works as a custom beacon identity:
    beacon --cert/--key + client --ca-cert from the same generated bundle."""
    rsc = f"{REMOTE_DIR}/target/release/rsc"

    run(client, f"rm -rf {CUSTOM_DIR} {CUSTOM_MOUNT} && mkdir -p {CUSTOM_MOUNT}")
    run(beacon_host, f"sudo pkill -9 -f 'rsbeacon.*:{CUSTOM_PORT}' 2>/dev/null || true")

    # Generate on client, ship cert+key to the beacon.
    r = run(client, f"{rsc} certs-gen --out {CUSTOM_DIR}")
    assert r.ok, f"certs-gen failed:\n{r.stdout}\n{r.stderr}"
    assert run(client, f"ls {CUSTOM_DIR}/ca.pem {CUSTOM_DIR}/cert.pem {CUSTOM_DIR}/key.pem").ok
    import subprocess
    subprocess.run(
        ["scp", f"{client}:{CUSTOM_DIR}/cert.pem", f"{client}:{CUSTOM_DIR}/key.pem",
         f"{beacon_host}:/tmp/"], check=True)

    run_bg(beacon_host,
           f"nohup sudo {BEACON_BIN} "
           f"--listen 0.0.0.0:{CUSTOM_PORT} "
           f"--encryption tls --cert /tmp/cert.pem --key /tmp/key.pem "
           f">/tmp/rsbeacon-tlsc.log 2>&1")
    time.sleep(1)
    r = run(beacon_host, f"ss -tlnp | grep ':{CUSTOM_PORT}'")
    assert r.ok, f"custom-identity beacon failed:\n{run(beacon_host, 'cat /tmp/rsbeacon-tlsc.log').stdout}"

    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    run_bg(client,
           f"nohup {rsc} exec "
           f"--beacon '{beacon_ip}:{CUSTOM_PORT}' "
           f"--encryption tls "
           f"--ca-cert {CUSTOM_DIR}/ca.pem "
           f"--rsclient {rsclient} "
           f"--mount-base {CUSTOM_MOUNT} "
           f"--name default "
           f"-- sh -c 'kill -0 1; exec sleep 60' "
           f">/tmp/rsc-tlsc.log 2>&1")
    time.sleep(3)

    sentinel = "rscaller-tlsc-sentinel"
    run(beacon_host, f"echo '{sentinel}' > /tmp/rsc-e2e-tlsc.txt")
    r = run(client, f"cat {CUSTOM_MOUNT}/default/tmp/rsc-e2e-tlsc.txt")
    assert r.ok and sentinel in r.stdout, \
        f"read via custom-identity TLS failed: {r.stdout!r} {r.stderr!r}"

    run(client, "pkill -9 rsclient 2>/dev/null; pkill -9 sleep 2>/dev/null || true")
    run(client,
        f"fusermount -u {CUSTOM_MOUNT}/default 2>/dev/null || "
        f"umount -l {CUSTOM_MOUNT}/default 2>/dev/null || true; "
        f"rm -rf {CUSTOM_MOUNT} {CUSTOM_DIR}")
    run(beacon_host, f"sudo pkill -9 -f 'rsbeacon.*:{CUSTOM_PORT}' 2>/dev/null; "
                     f"rm -f /tmp/cert.pem /tmp/key.pem || true")
