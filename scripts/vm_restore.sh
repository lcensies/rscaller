#!/usr/bin/env bash
# Revert a libvirt VM to a snapshot and wait for SSH to come up.
# Usage: vm_restore.sh <domain> <snapshot> [ssh_host] [timeout_sec]
set -euo pipefail

DOMAIN="${1:?Usage: vm_restore.sh <domain> <snapshot> [ssh_host] [timeout_sec]}"
SNAPSHOT="${2:-clean-base}"
SSH_HOST="${3:-$DOMAIN}"
TIMEOUT="${4:-60}"

echo "==> Reverting $DOMAIN to snapshot '$SNAPSHOT' ..."
virsh snapshot-revert "$DOMAIN" "$SNAPSHOT" --running
echo "    [ok] snapshot reverted, waiting for SSH on $SSH_HOST (up to ${TIMEOUT}s) ..."

deadline=$(( $(date +%s) + TIMEOUT ))
while true; do
    if ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no -o BatchMode=yes \
           "$SSH_HOST" "exit 0" 2>/dev/null; then
        echo "    [ok] $SSH_HOST is up"
        break
    fi
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "ERROR: $SSH_HOST did not come up within ${TIMEOUT}s after snapshot revert" >&2
        exit 1
    fi
    sleep 2
done
