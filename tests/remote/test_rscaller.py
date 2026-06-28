import subprocess
import time
import uuid

from conftest import run, REMOTE_DIR

MOUNT_DIR = "/tmp/rsc-mount"


# ---------------------------------------------------------------------------
# Basic connectivity
# ---------------------------------------------------------------------------

def test_remote_reachable(remote):
    assert run(remote, "echo ok").stdout.strip() == "ok"

def test_binaries_deployed(remote):
    assert run(remote,
               f"ls {REMOTE_DIR}/target/release/rsclient "
               f"{REMOTE_DIR}/target/release/rsbeacon "
               f"{REMOTE_DIR}/target/release/rsc").ok

def test_beacon_reachable(beacon_host):
    assert run(beacon_host, "echo ok").ok


# ---------------------------------------------------------------------------
# kmod tests (opt-in via --kmod)
# ---------------------------------------------------------------------------

def test_kmod_ko_exists(remote):
    assert run(remote, f"ls {REMOTE_DIR}/kmod/rscaller.ko").ok

def test_kmod_loaded(kmod, remote):
    assert run(remote, "lsmod | grep '^rscaller'").ok

def test_proc_entry(kmod, remote):
    assert run(remote, "ls /proc/rscaller").ok

def test_dmesg_init(kmod, remote):
    assert run(remote, "sudo dmesg | grep -i rscaller").ok

def test_rsclient_running(rsclient, client):
    assert run(client, "pgrep -fa rsclient | grep -v grep").ok

def test_rsclient_log_no_error(rsclient, client):
    log = run(client, "cat /tmp/rsclient.log 2>/dev/null").stdout
    assert "error" not in log.lower() or "connected" in log.lower(), \
        f"rsclient log:\n{log}"

def test_syscall_intercept(rsclient, remote):
    run(remote, "kill -0 $$ || true")
    time.sleep(0.5)
    assert run(remote,
               "sudo dmesg | tail -80 | "
               "grep -iE '(rscaller|handle_syscall|intercept|forwarded)'").ok


# ---------------------------------------------------------------------------
# Seccomp-unotify + rscfuse E2E tests
# (on by default; skip with --no-seccomp or --no-e2e)
#
# rsc runs on client (dev-vm-1), rsbeacon on beacon_host (dev-vm-2).
# Direct TCP — no tunnel.
# ---------------------------------------------------------------------------

def test_rsc_binary_deployed(remote):
    assert run(remote, f"ls {REMOTE_DIR}/target/release/rsc").ok

def test_seccomp_rsclient_running(rsc_seccomp, client):
    assert run(client, "pgrep -fa rsclient | grep -v grep").ok

def test_seccomp_rsclient_log_connected(rsc_seccomp, client):
    log = run(client, "cat /tmp/rsc-seccomp.log 2>/dev/null").stdout
    assert "error" not in log.lower() or "connected" in log.lower(), \
        f"rsc-seccomp log:\n{log}"

def test_seccomp_syscall_forwarded(rsc_seccomp, client):
    # sh called kill(1, 0) at startup — rsclient log must show a notification.
    log = run(client, "cat /tmp/rsc-seccomp.log 2>/dev/null").stdout
    assert any(kw in log.lower() for kw in ("notif", "syscall", "forward", "relay")), \
        f"no forwarding evidence in rsc log:\n{log}"

def test_rscfuse_mounted(rsc_seccomp, client):
    r = run(client, f"grep '{MOUNT_DIR}/default' /proc/mounts")
    assert r.ok, f"rscfuse not mounted:\n{run(client, 'cat /proc/mounts').stdout}"
    assert "fuse" in r.stdout.lower(), f"not a FUSE mount:\n{r.stdout}"

def test_file_read_via_fuse(rsc_seccomp, client, beacon_host):
    # Write on beacon_host (dev-vm-2); read back through rscfuse on client.
    sentinel = "rscaller-read-sentinel"
    run(beacon_host, f"echo '{sentinel}' > /tmp/rsc-e2e-read.txt")
    r = run(client, f"cat {MOUNT_DIR}/default/tmp/rsc-e2e-read.txt")
    assert r.ok, f"read via rscfuse failed:\n{r.stderr}"
    assert sentinel in r.stdout, f"content mismatch: got {r.stdout!r}"

def test_file_write_via_fuse(rsc_seccomp, client, beacon_host):
    # Write THROUGH rscfuse on client; verify file appears on beacon_host.
    sentinel = f"rscaller-write-{uuid.uuid4().hex[:8]}"
    fuse_path   = f"{MOUNT_DIR}/default/tmp/rsc-e2e-write.txt"
    remote_path = "/tmp/rsc-e2e-write.txt"
    w = run(client, f"echo '{sentinel}' > {fuse_path}")
    assert w.ok, f"write through rscfuse failed:\n{w.stderr}"
    r = run(beacon_host, f"cat {remote_path}")
    assert r.ok, f"file not found on beacon_host after fuse write:\n{r.stderr}"
    assert sentinel in r.stdout, f"content mismatch on beacon_host: got {r.stdout!r}"

def test_fuse_write_persists(rsc_seccomp, client, beacon_host):
    # Re-read the file written in test_file_write_via_fuse after sync.
    run(beacon_host, "sync")
    r = run(beacon_host, "stat /tmp/rsc-e2e-write.txt && cat /tmp/rsc-e2e-write.txt")
    assert r.ok, f"file missing on beacon_host after sync:\n{r.stderr}"
    assert "rscaller-write-" in r.stdout, f"unexpected content: {r.stdout!r}"
