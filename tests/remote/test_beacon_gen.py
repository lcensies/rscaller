"""beacon-gen E2E: `rsc beacon-gen` compiles a zero-config rsbeacon on the
client; the generated binary is copied to beacon_host and started with NO
arguments; rsc connects over baked-in TLS using the generated ca.pem.
"""
import time
import uuid

import pytest

from conftest import run, run_bg, REMOTE_DIR

GEN_PORT = 9997
GEN_DIR = "/tmp/beacon-gen"
GEN_BIN = "/home/ubuntu/rsbeacon-gen"
MOUNT_DIR = "/tmp/rsc-mount-gen"
NAME = "default"


def _gen_cleanup(client, beacon_host):
    run(client, "pkill -9 rsclient 2>/dev/null; pkill -9 sleep 2>/dev/null || true")
    run(client,
        f"fusermount -u {MOUNT_DIR}/{NAME} 2>/dev/null || "
        f"umount -l {MOUNT_DIR}/{NAME} 2>/dev/null || true; "
        f"rm -rf {MOUNT_DIR}")
    run(beacon_host, f"sudo pkill -9 -f rsbeacon-gen 2>/dev/null || true")


@pytest.fixture(scope="session")
def rsc_beacon_gen(pytestconfig, client, beacon_host, beacon_ip, deploy):
    if pytestconfig.getoption("--no-e2e"):
        pytest.skip("E2E disabled via --no-e2e")

    _gen_cleanup(client, beacon_host)
    run(client, f"rm -rf {GEN_DIR} && mkdir -p {MOUNT_DIR}")

    # 1. Generate a zero-config beacon on the client (baked listen + TLS).
    rsc = f"{REMOTE_DIR}/target/release/rsc"
    r = run(client,
            f"{rsc} beacon-gen --listen 0.0.0.0:{GEN_PORT} --out {GEN_DIR}",
            timeout=300)
    assert r.ok, f"beacon-gen failed:\n{r.stdout}\n{r.stderr}"
    assert run(client, f"ls {GEN_DIR}/rsbeacon {GEN_DIR}/ca.pem").ok, \
        "beacon-gen did not emit rsbeacon + ca.pem"

    # 2. Push to beacon_host; start with NO arguments — config is baked in.
    import subprocess
    run(beacon_host, f"rm -f {GEN_BIN}")
    subprocess.run(
        ["scp", f"{client}:{GEN_DIR}/rsbeacon", f"{beacon_host}:{GEN_BIN}"],
        check=True,
    )
    run(beacon_host, f"chmod +x {GEN_BIN}")
    run_bg(beacon_host,
           f"nohup sudo {GEN_BIN} >/tmp/rsbeacon-gen.log 2>&1")
    time.sleep(1)
    r = run(beacon_host, f"ss -tlnp | grep ':{GEN_PORT}'")
    if not r.ok:
        log = run(beacon_host, "cat /tmp/rsbeacon-gen.log 2>/dev/null")
        pytest.fail(f"generated beacon failed to start:\n{log.stdout}")

    # 3. Connect with TLS using the generated CA.
    rsclient = f"{REMOTE_DIR}/target/release/rsclient"
    run_bg(client,
           f"nohup {rsc} exec "
           f"--beacon '{beacon_ip}:{GEN_PORT}' "
           f"--encryption tls "
           f"--ca-cert {GEN_DIR}/ca.pem "
           f"--rsclient {rsclient} "
           f"--mount-base {MOUNT_DIR} "
           f"--name {NAME} "
           f"-- sh -c 'kill -0 1; exec sleep 60' "
           f">/tmp/rsc-gen.log 2>&1")
    time.sleep(3)
    r = run(client, "pgrep -fa rsclient | grep -v grep")
    if not r.ok:
        log = run(client, "cat /tmp/rsc-gen.log 2>/dev/null")
        pytest.fail(f"rsc exec to generated beacon failed:\n{log.stdout}")
    yield
    _gen_cleanup(client, beacon_host)


def test_gen_beacon_listening(rsc_beacon_gen, beacon_host):
    assert run(beacon_host, f"ss -tlnp | grep ':{GEN_PORT}'").ok

def test_gen_fuse_mounted(rsc_beacon_gen, client):
    r = run(client, f"grep '{MOUNT_DIR}/{NAME}' /proc/mounts")
    assert r.ok and "fuse" in r.stdout.lower(), \
        f"FUSE not mounted:\n{run(client, 'cat /proc/mounts').stdout}"

def test_gen_file_read_via_fuse(rsc_beacon_gen, client, beacon_host):
    sentinel = "rscaller-gen-read-sentinel"
    run(beacon_host, f"echo '{sentinel}' > /tmp/rsc-e2e-gen-read.txt")
    r = run(client, f"cat {MOUNT_DIR}/{NAME}/tmp/rsc-e2e-gen-read.txt")
    assert r.ok and sentinel in r.stdout, \
        f"read via generated beacon failed: {r.stdout!r} {r.stderr!r}"

def test_gen_file_write_via_fuse(rsc_beacon_gen, client, beacon_host):
    sentinel = f"rscaller-gen-write-{uuid.uuid4().hex[:8]}"
    w = run(client, f"echo '{sentinel}' > {MOUNT_DIR}/{NAME}/tmp/rsc-e2e-gen-write.txt")
    assert w.ok, f"write failed:\n{w.stderr}"
    r = run(beacon_host, "cat /tmp/rsc-e2e-gen-write.txt")
    assert r.ok and sentinel in r.stdout, \
        f"mismatch on beacon_host: {r.stdout!r} {r.stderr!r}"
