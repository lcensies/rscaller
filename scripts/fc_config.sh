#!/usr/bin/env bash
# fc_config.sh — emit a Firecracker JSON config to stdout.
# Usage: bash fc_config.sh <vmlinux> <rootfs.img> [host_port]
# The host_port is forwarded via a tap device; default 9999.
#
# This script is meant to be used with:
#   firecracker --no-api --config-file <(bash scripts/fc_config.sh vmlinux rootfs.img)

VMLINUX="${1:?Usage: $0 <vmlinux> <rootfs.img> [host_port]}"
ROOTFS="${2:?}"
# Firecracker uses tap networking — no user-mode port forward like QEMU.
# The guest gets IP 172.16.0.2/30, host tap gets 172.16.0.1/30.
GUEST_IP="172.16.0.2"
GUEST_GW="172.16.0.1"
TAP_DEV="${TAP_DEV:-fc-tap0}"
FC_MAC="06:00:AC:10:00:02"

cat << JSON
{
  "boot-source": {
    "kernel_image_path": "${VMLINUX}",
    "boot_args": "console=ttyS0 root=/dev/vda rw init=/init quiet panic=1 reboot=k"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "${ROOTFS}",
      "is_root_device": true,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 512
  },
  "network-interfaces": [
    {
      "iface_id": "net1",
      "guest_mac": "${FC_MAC}",
      "host_dev_name": "${TAP_DEV}"
    }
  ]
}
JSON
