#!/usr/bin/env bash
# provision-beacon.sh — install runtime dependencies on the beacon VM (dev-vm-2).
#
# The beacon host runs rsbeacon, tracee (docker) and — for the same-host relay
# PoC (poc.sh --scenario network-local) — the rsc/rsclient binaries. rsc links
# libvirt (qemu-vdw-core), so the runtime libs must exist on the beacon too.
# apt-get install is naturally idempotent; safe to re-run.
#
# Never hand-install packages on dev VMs — extend PKGS here instead, so a
# baseline-reverted VM is reproducible with one command.

set -euo pipefail

BEACON_VM="${BEACON_VM:-dev-vm-2}"
BECOME_PASS="${BECOME_PASS:-ubuntu}"

PKGS=(
	libvirt0 # rsc dynamic link (libvirt-qemu.so.0) for network-local PoC
)

echo ">> provisioning beacon $BEACON_VM: ${PKGS[*]}"
ssh "$BEACON_VM" "echo '$BECOME_PASS' | sudo -S apt-get install -y ${PKGS[*]} 2>&1 | tail -2"
echo ">> beacon provisioned"
