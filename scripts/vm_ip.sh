#!/usr/bin/env bash
# vm_ip.sh — resolve a libvirt VM's primary IP address.
# Tries virsh domifaddr first; falls back to the name itself (SSH alias / /etc/hosts).
#
# Usage: bash scripts/vm_ip.sh <vm-name-or-domain>
set -euo pipefail

VM="${1:?Usage: vm_ip.sh <vm-name>}"

IP=$(virsh domifaddr "$VM" 2>/dev/null \
     | awk '/ipv4/{split($4,a,"/"); print a[1]}' \
     | head -1)

if [ -n "$IP" ]; then
    echo "$IP"
else
    # Fall back to the name (works if it resolves via SSH config or /etc/hosts)
    echo "$VM"
fi
