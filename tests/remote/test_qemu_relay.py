"""
QEMU relay view E2E tests.

These tests exercise `rsc exec --profile qemu-relay`, which provisions a
local QEMU/KVM VM on the client (dev-vm-1), attaches a remote block device
from the beacon through rscfuse, mounts it inside the VM, and runs the
target command via the QEMU Guest Agent.

They are skipped unless:
  - libvirtd is running and KVM is available on the client, and
  - the relay boot artifacts (vmlinuz, initrd.img, rootfs.img) exist.

The beacon-side test device (/dev/vdb) is a scratch virtio disk attached to
the beacon VM at the hypervisor level — no in-guest setup runs on the
beacon (no losetup, no mounts), which mirrors the real use case where the
attacker cannot run setup commands on the victim.
"""
import uuid

import pytest
from conftest import run, REMOTE_DIR


RELAY_ARTIFACTS = "/var/lib/libvirt/images/rscaller-relay"
# Scratch disk attached to the beacon VM via `virsh attach-disk` (see module
# docstring); formatted ext4 host-side. Never mounted on the beacon.
RELAY_DEVICE = "/dev/vdb"


def _relay_artifacts_present(client):
    for name in ("vmlinuz", "initrd.img", "rootfs.img"):
        if not run(client, f"ls {RELAY_ARTIFACTS}/{name}").ok:
            return False
    return True


def _libvirtd_ready(client):
    r = run(client, "virsh list --all >/dev/null 2>&1")
    return r.ok


def _relay_cmd(beacon_ip, beacon_port, shell):
    return (
        f"sudo {REMOTE_DIR}/target/release/rsc exec "
        f"--beacon '{beacon_ip}:{beacon_port}' "
        f"--encryption none "
        f"--mount-profile qemu-relay "
        f"--relay-artifacts {RELAY_ARTIFACTS} "
        f"--relay-device {RELAY_DEVICE} "
        f"-- {shell}"
    )


@pytest.fixture(scope="module")
def relay_ready(client):
    if not _libvirtd_ready(client):
        pytest.skip("libvirtd not reachable on client — KVM relay tests disabled")
    if not _relay_artifacts_present(client):
        pytest.skip(f"relay artifacts missing at {RELAY_ARTIFACTS}")


def test_qemu_relay_writes_through_vm(client, beacon_ip, beacon_port, rsbeacon_on_beacon, relay_ready):
    """
    Write a sentinel file through the relay VM and read it back through a
    second relay invocation — verification never touches the beacon's shell.
    """
    sentinel = f"relay-sentinel-{uuid.uuid4().hex[:8]}"

    write = run(client, _relay_cmd(
        beacon_ip, beacon_port,
        f"sh -c 'echo {sentinel} > /mnt/relay/sentinel.txt && sync'",
    ), timeout=300)
    assert write.ok, f"relay write failed:\n{write.stderr}\n{write.stdout}"

    read = run(client, _relay_cmd(
        beacon_ip, beacon_port,
        "cat /mnt/relay/sentinel.txt",
    ), timeout=300)
    assert read.ok, f"relay read failed:\n{read.stderr}\n{read.stdout}"
    assert sentinel in read.stdout, f"sentinel mismatch: {read.stdout!r}"
