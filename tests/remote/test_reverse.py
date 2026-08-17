"""Reverse (rendezvous) mode E2E: rsserver on client host, rsbeacon DIALS OUT
from beacon_host, rsc exec reaches it through the server over TLS.

Topology under test (the whole point of reverse mode): the client never
connects to the beacon — both sides meet at rsserver.

Also covers: bad-token rejection and token-in-URL parsing.
"""
import time
import uuid

import pytest

from conftest import run, run_bg, REMOTE_DIR, BEACON_BIN

SERVER_PORT = 4444
MOUNT_DIR = "/tmp/rsc-mount-rev"
CA_PATH = "/tmp/rsc-rev-ca.pem"
TOKEN = "s3cret-rev"
RSSERVER_BIN = f"{REMOTE_DIR}/target/release/rsserver"


def _rev_cleanup(client, beacon_host):
    run(client, "pkill -9 rsclient 2>/dev/null; pkill -9 rsserver 2>/dev/null; "
                "pkill -9 sleep 2>/dev/null || true")
    run(client,
        f"fusermount -u {MOUNT_DIR}/default 2>/dev/null || "
        f"umount -l {MOUNT_DIR}/default 2>/dev/null || true; "
        f"rm -rf {MOUNT_DIR} {CA_PATH}")
    run(beacon_host, "sudo pkill -9 rsbeacon 2>/dev/null || true")


@pytest.fixture(scope="session")
def rsc_reverse(pytestconfig, client, beacon_host, deploy, deploy_beacon):
    if pytestconfig.getoption("--no-e2e"):
        pytest.skip("E2E disabled via --no-e2e")

    _rev_cleanup(client, beacon_host)
    run(client, f"mkdir -p {MOUNT_DIR}")

    # 1. rsserver on the client VM (any reachable host would do).
    run_bg(client,
           f"nohup {RSSERVER_BIN} --listen 0.0.0.0:{SERVER_PORT} "
           f"--auth-token {TOKEN} >/tmp/rsserver.log 2>&1")
    time.sleep(1)
    r = run(client, f"ss -tlnp | grep ':{SERVER_PORT}'")
    if not r.ok:
        log = run(client, "cat /tmp/rsserver.log 2>/dev/null")
        pytest.fail(f"rsserver failed to start:\n{log.stdout}")

    # Server address as seen from the beacon (dev-vm-1's libvirt IP).
    server_ip = run(client, "hostname -I").stdout.split()[0]

    # 2. Beacon DIALS OUT to the server (TLS identity = embedded).
    run_bg(beacon_host,
           f"nohup sudo {BEACON_BIN} "
           f"--connect {server_ip}:{SERVER_PORT} "
           f"--auth {TOKEN} "
           f"--encryption tls "
           f">/tmp/rsbeacon-rev.log 2>&1")
    time.sleep(2)
    log = run(client, "cat /tmp/rsserver.log").stdout
    if "registered" not in log:
        blog = run(beacon_host, "cat /tmp/rsbeacon-rev.log 2>/dev/null")
        pytest.fail(f"beacon did not register:\nserver:\n{log}\nbeacon:\n{blog.stdout}")

    # 3. CA to client (zero-config path) and rsc exec through the server,
    #    token passed in the URL form.
    ca = run(beacon_host, f"{BEACON_BIN} --print-ca")
    assert ca.ok and "BEGIN CERTIFICATE" in ca.stdout
    import base64
    b64 = base64.b64encode(ca.stdout.encode()).decode()
    assert run(client, f"echo '{b64}' | base64 -d > {CA_PATH}").ok

    rsc      = f"{REMOTE_DIR}/target/release/rsc"
    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    run_bg(client,
           f"nohup {rsc} exec "
           f"--server '{TOKEN}@127.0.0.1:{SERVER_PORT}' "
           f"--encryption tls "
           f"--ca-cert {CA_PATH} "
           f"--rsclient {rsclient} "
           f"--mount-base {MOUNT_DIR} "
           f"--name default "
           f"-- sh -c 'kill -0 1; exec sleep 60' "
           f">/tmp/rsc-rev.log 2>&1")
    time.sleep(3)
    r = run(client, "pgrep -fa rsclient | grep -v grep")
    if not r.ok:
        log = run(client, "cat /tmp/rsc-rev.log 2>/dev/null")
        pytest.fail(f"rsc reverse exec failed:\n{log.stdout}")
    yield
    _rev_cleanup(client, beacon_host)


def test_rev_beacon_registered(rsc_reverse, client):
    log = run(client, "cat /tmp/rsserver.log").stdout
    assert "registered" in log, f"no beacon registration:\n{log}"

def test_rev_client_paired(rsc_reverse, client):
    time.sleep(1)
    log = run(client, "cat /tmp/rsserver.log").stdout
    assert "paired" in log, f"no pairing:\n{log}"

def test_rev_fuse_mounted(rsc_reverse, client):
    r = run(client, f"grep '{MOUNT_DIR}/default' /proc/mounts")
    assert r.ok and "fuse" in r.stdout.lower(), \
        f"FUSE not mounted:\n{run(client, 'cat /proc/mounts').stdout}"

def test_rev_file_read_via_fuse(rsc_reverse, client, beacon_host):
    sentinel = "rscaller-rev-read-sentinel"
    run(beacon_host, f"echo '{sentinel}' > /tmp/rsc-e2e-rev-read.txt")
    r = run(client, f"cat {MOUNT_DIR}/default/tmp/rsc-e2e-rev-read.txt")
    assert r.ok and sentinel in r.stdout, \
        f"read via reverse beacon failed: {r.stdout!r} {r.stderr!r}"

def test_rev_file_write_via_fuse(rsc_reverse, client, beacon_host):
    sentinel = f"rscaller-rev-write-{uuid.uuid4().hex[:8]}"
    w = run(client, f"echo '{sentinel}' > {MOUNT_DIR}/default/tmp/rsc-e2e-rev-write.txt")
    assert w.ok, f"write failed:\n{w.stderr}"
    r = run(beacon_host, "cat /tmp/rsc-e2e-rev-write.txt")
    assert r.ok and sentinel in r.stdout, \
        f"mismatch on beacon_host: {r.stdout!r} {r.stderr!r}"

def test_rev_bad_token_rejected(rsc_reverse, client, beacon_host):
    # Wrong-token beacon must be rejected and exit (code 2), server logs it.
    run(beacon_host, "sudo pkill -9 -f 'rsbeacon.*bad-token' 2>/dev/null || true")
    server_ip = run(client, "hostname -I").stdout.split()[0]
    run(beacon_host,
        f"sudo timeout 5 {BEACON_BIN} --connect {server_ip}:{SERVER_PORT} "
        f"--auth bad-token --name badtoken 2>/dev/null; echo EXIT=$?")
    time.sleep(1)
    log = run(client, "cat /tmp/rsserver.log").stdout
    assert "rejected" in log, f"bad token not rejected:\n{log}"


# ---------------------------------------------------------------------------
# beacon-gen × reverse: zero-arg dial-out beacon
# ---------------------------------------------------------------------------

GENREV_DIR = "/tmp/beacon-gen-rev"
GENREV_BIN = "/home/ubuntu/rsbeacon-genrev"
GENREV_MOUNT = "/tmp/rsc-mount-genrev"
GENREV_NAME = "genrev"


def test_rev_gen_beacon_zero_args(rsc_reverse, client, beacon_host):
    """rsc beacon-gen --connect bakes server+token+name: the beacon runs with
    literally no arguments and still lands on the right rsserver session."""
    server_ip = run(client, "hostname -I").stdout.split()[0]
    rsc = f"{REMOTE_DIR}/target/release/rsc"

    run(client, f"rm -rf {GENREV_DIR} {GENREV_MOUNT} && mkdir -p {GENREV_MOUNT}")
    run(beacon_host, f"sudo pkill -9 -f rsbeacon-genrev 2>/dev/null || true")

    r = run(client,
            f"{rsc} beacon-gen "
            f"--connect '{TOKEN}@{server_ip}:{SERVER_PORT}' "
            f"--name {GENREV_NAME} "
            f"--out {GENREV_DIR}",
            timeout=300)
    assert r.ok, f"beacon-gen --connect failed:\n{r.stdout}\n{r.stderr}"

    import subprocess
    run(beacon_host, f"rm -f {GENREV_BIN}")
    subprocess.run(["scp", f"{client}:{GENREV_DIR}/rsbeacon",
                    f"{beacon_host}:{GENREV_BIN}"], check=True)
    run(beacon_host, f"chmod +x {GENREV_BIN}")

    # NO arguments — everything baked.
    run_bg(beacon_host, f"nohup sudo {GENREV_BIN} >/tmp/rsbeacon-genrev.log 2>&1")
    time.sleep(2)
    log = run(client, "cat /tmp/rsserver.log").stdout
    assert f"session '{GENREV_NAME}'" in log and "registered" in log, \
        f"generated reverse beacon did not register:\n{log}"

    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    run_bg(client,
           f"nohup {rsc} exec "
           f"--server '{TOKEN}@127.0.0.1:{SERVER_PORT}' "
           f"--encryption tls "
           f"--ca-cert {GENREV_DIR}/ca.pem "
           f"--rsclient {rsclient} "
           f"--mount-base {GENREV_MOUNT} "
           f"--name {GENREV_NAME} "
           f"-- sh -c 'kill -0 1; exec sleep 60' "
           f">/tmp/rsc-genrev.log 2>&1")
    time.sleep(3)

    sentinel = "rscaller-genrev-sentinel"
    run(beacon_host, f"echo '{sentinel}' > /tmp/rsc-e2e-genrev.txt")
    r = run(client, f"cat {GENREV_MOUNT}/{GENREV_NAME}/tmp/rsc-e2e-genrev.txt")
    assert r.ok and sentinel in r.stdout, \
        f"read via zero-arg reverse beacon failed: {r.stdout!r} {r.stderr!r}"

    # Teardown (this test runs after the shared-fixture ones).
    run(client, "pkill -9 rsclient 2>/dev/null; pkill -9 sleep 2>/dev/null || true")
    run(client,
        f"fusermount -u {GENREV_MOUNT}/{GENREV_NAME} 2>/dev/null || "
        f"umount -l {GENREV_MOUNT}/{GENREV_NAME} 2>/dev/null || true; "
        f"rm -rf {GENREV_MOUNT} {GENREV_DIR}")
    run(beacon_host, f"sudo pkill -9 -f rsbeacon-genrev 2>/dev/null || true")
