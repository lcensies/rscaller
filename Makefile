PWD := $(shell pwd)

# Detect NixOS and wrap cargo in nix-shell when needed
IS_NIXOS := $(shell test -f /etc/NIXOS && echo 1 || echo 0)
ifeq ($(IS_NIXOS),1)
CARGO = nix-shell $(PWD)/shell.nix --run "cargo $1"
else
CARGO = cargo $1
endif
KMOD_DIR := kmod
KMOD_ABS_DIR := ${PWD}/kmod
SCRIPTS_DIR := scripts
BINDGEN_DIR := rsclient/src/bindings/src

KERNEL_VOLUMES := -v /lib/modules:/lib/modules -v /usr/src/kernels:/usr/src/kernels 
APP_VOLUME := -v ${PWD}:/app
COMMON_VOLUMES := ${KERNEL_VOLUMES} ${APP_VOLUME}
# MAKE_IMAGE := gcc:15.1.0
# TODO: build properly
MAKE_IMAGE := archlinux:base-devel-20250720.0.386825

MAKE_CMD := docker run --rm -it ${COMMON_VOLUMES} -w /app ${MAKE_IMAGE} make

BUFFER_HEADER_PATH := ${KMOD_ABS_DIR}/buffer_header_only.h

.PHONY: all kmod kmod_native kmod_docker kmod_reload configure

all: build

configure: btf bindings handlers
# 	sudo dnf install kernel-devel-$(uname -r)
	bash $(SCRIPTS_DIR)/setup_host.sh
	git submodule update --init --remote
	cargo install --git https://github.com/lcensies/libloading-bindgen --bin cargo-libloading-bindgen
	cargo install single-header

.PHONY: bindings
bindings:
# 	cd ${BINDGEN_DIR} && cargo run ${PWD}/kmod/rscaller.h
# TODO: move buffer to lib folder
	single-header ${KMOD_ABS_DIR}/buffer.c -- -D__GENERATING_BINDINGS__ -D__USERSPACE__ > ${BUFFER_HEADER_PATH}
	cargo-libloading-bindgen ${BUFFER_HEADER_PATH} | rustfmt > ${BINDGEN_DIR}/bindings.rs


kmod-handlers:
	cd ${SCRIPTS_DIR} && poetry install && \
		ls && poetry run python3 generate_handler_wrappres.py

btf:
	# https://github.com/TuxInvader/focal-mainline-builder
	# Ensure that we have accerss to docker socket
	docker ps > /dev/null 2>/dev/null
	docker run --privileged calico/bpftool /bpftool btf dump file /sys/kernel/btf/vmlinux format c > kmod/vmlinux.h

kmod:
	$(MAKE) -C $(KMOD_DIR)

kmod_native:
	$(MAKE) -C $(KMOD_DIR)

kmod_docker:
	${MAKE_CMD} -C ${KMOD_DIR}

kmod_reload: 
	cd ${KMOD_DIR} && sudo make reload

kmod_unload: 
	cd ${KMOD_DIR} && sudo make unload

dev-env:
	docker build -t rscaller-devcont -f docker/devcontainer.Dockerfile .
	docker volume create rscaller_cache 2>/dev/null || :
	docker run -it \
		-v ${PWD}:/app \
		-v rscaller_cache:/root/.cache \
		-v /var/lib/docker:/var/lib/docker \
		-v /var/run/docker.sock:/var/run/docker.sock \
		${KERNEL_VOLUMES}
		rscaller-devcont
# dev-vm-1: build host / rsc client  (rsync + cargo build happens here)
# dev-vm-2: beacon host              (rsbeacon binary only, no full build)
REMOTE      ?= dev-vm-1
BEACON_VM   ?= dev-vm-2
BEACON_PORT ?= 9999
# Libvirt domain names (match SSH aliases above by default)
VM_DOMAIN        ?= $(REMOTE)
VM_DOMAIN_BEACON ?= $(BEACON_VM)
VM_SNAPSHOT      ?= baseline
BEACON_SNAPSHOT  ?= baseline
# Path where rsbeacon lives on BEACON_VM
BEACON_BIN_REMOTE ?= /home/ubuntu/rsbeacon
# rsbeacon --netstack backend (direct|smoltcp-xdp) and its --xdp-* flags,
# threaded through to `make poc`/`make test-evasion` etc. — see
# `net_backend/smoltcp_xdp/init.rs` for what each flag does. XDP_IFACE has
# no sane default (must match the beacon VM's real NIC), so it's left
# empty unless the caller passes it.
NETSTACK   ?= direct
XDP_IFACE  ?=
XDP_QUEUE  ?= 0

.PHONY: build test integration-tests setup-remote provision \
        deploy deploy-beacon deploy-all \
        snapshot-create snapshot-restore snapshot-beacon \
        vm-clean vm-reset \
        test-vm test-evasion test-evasion-clean \
        test-mount-profiles test-mount-profiles-clean \
        handlers demo demo-auto demo-teardown \
        poc poc-notracee poc-scenario poc-scenario-tmux poc-compare

build:
	$(call CARGO,build --workspace)

handlers:
	$(call CARGO,run -p codegen -- --tbl-dir files --forwarded files/forwarded_syscalls --out kmod)

test:
	$(call CARGO,test --workspace)

integration-tests:
	@echo "=== Local integration tests ==="
	bash tests/integration/test_codegen.sh
	bash tests/integration/test_beacon_local.sh
	bash tests/integration/test_proto_codec.sh
	@echo "=== All passed ==="

setup-remote:
	bash scripts/setup_remote.sh $(REMOTE)

provision:
	ansible-playbook -i $(REMOTE), -u ubuntu scripts/provision.yml

# Rsync repo source to REMOTE and build the full workspace there.
deploy:
	bash scripts/deploy.sh $(REMOTE)

# Copy the rsbeacon binary built on REMOTE to BEACON_VM.
# Runs scp from this host so VM-to-VM hostname resolution is not required.
# BEACON_VM is resolved to an IP via virsh (falls back to the name itself).
deploy-beacon: deploy
	@bash scripts/provision-beacon.sh
	@BEACON_IP=$$(bash scripts/vm_ip.sh $(VM_DOMAIN_BEACON)); \
	 echo "==> Stopping rsbeacon on $$BEACON_IP (unlock binary for overwrite)"; \
	 ssh ubuntu@$$BEACON_IP "sudo pkill -f rsbeacon 2>/dev/null; sleep 0.3; true" 2>/dev/null || true; \
	 echo "==> Copying rsbeacon from $(REMOTE) to ubuntu@$$BEACON_IP:$(BEACON_BIN_REMOTE)"; \
	 scp $(REMOTE):/home/ubuntu/rscaller/target/release/rsbeacon \
	     ubuntu@$$BEACON_IP:$(BEACON_BIN_REMOTE); \
	 echo "==> Copying rsc/rsclient to ubuntu@$$BEACON_IP (same-host relay PoC)"; \
	 ssh ubuntu@$$BEACON_IP "mkdir -p /home/ubuntu/rscaller/target/release"; \
	 scp $(REMOTE):/home/ubuntu/rscaller/target/release/rsc \
	     $(REMOTE):/home/ubuntu/rscaller/target/release/rsclient \
	     ubuntu@$$BEACON_IP:/home/ubuntu/rscaller/target/release/

# Full two-VM deploy: build on REMOTE, push rsbeacon to BEACON_VM, open ghost shell.
deploy-all: deploy-beacon
	@bash scripts/ghost-shell.sh

# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

# Snapshot REMOTE (dev-vm-1) — call after a clean deploy.
snapshot-create:
	virsh snapshot-create-as $(VM_DOMAIN) $(VM_SNAPSHOT) \
	  --description "clean boot, no kmod loaded" --atomic

# Refresh the client baseline snapshot to include the currently deployed binaries.
# Run after 'make deploy' when new binaries change the client's expected state.
snapshot-update-client:
	virsh snapshot-delete $(VM_DOMAIN) $(VM_SNAPSHOT) 2>/dev/null || true
	virsh snapshot-create-as $(VM_DOMAIN) $(VM_SNAPSHOT) \
	  --description "post-deploy baseline with rsc binaries" --atomic
	@echo "Baseline snapshot updated for $(VM_DOMAIN)."

# Revert REMOTE to its clean snapshot.
snapshot-restore:
	bash scripts/vm_restore.sh $(VM_DOMAIN) $(VM_SNAPSHOT)

# Snapshot BEACON_VM (dev-vm-2) — call after deploy-beacon while rsbeacon is in place.
snapshot-beacon:
	virsh snapshot-create-as $(VM_DOMAIN_BEACON) $(BEACON_SNAPSHOT) \
	  --description "ssh key + rsbeacon binary deployed" --atomic

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

# Open a 3-pane tmux session + print interactive step guide.
demo:
	bash scripts/demo.sh

# Run the demo automatically (sends commands to each pane with pauses).
demo-auto:
	bash scripts/demo.sh --auto

# Restore ip on dev-vm-2, unmount rscfuse, kill tmux session.
demo-teardown:
	bash scripts/demo.sh --teardown

# ---------------------------------------------------------------------------
# PoC manual testing
# ---------------------------------------------------------------------------

# Run PoC with all defaults: profile=proc, tracee on beacon.
# Usage:
#   make poc                                       # proc profile, default cmd
#   make poc PROFILE=shadow CMD=hostname           # shadow profile
#   make poc PROFILE=none CMD="ip -4 addr"
#   make poc NETSTACK=smoltcp-xdp XDP_IFACE=enp1s0 # exercise the smoltcp-xdp backend
#     (NETSTACK/XDP_IFACE/XDP_QUEUE reach poc.sh as env vars — see that
#     script's own `--netstack`/`--xdp-iface`/`--xdp-queue` flags)
poc:
	bash scripts/poc.sh --profile $(or $(PROFILE),proc) $(if $(CMD),--cmd "$(CMD)",)

# Same as poc but skip tracee (faster startup, ~3s less wait).
poc-notracee:
	bash scripts/poc.sh --no-tracee --profile $(or $(PROFILE),proc) $(if $(CMD),--cmd "$(CMD)",)

# Run one of the built-in evasion scenarios (exec|file|network) as a
# baseline-vs-evasion comparison; prints matching-event counts + verdict.
# Usage:
#   make poc-scenario SCENARIO=exec
#   make poc-scenario SCENARIO=file
#   make poc-scenario SCENARIO=network
poc-scenario:
	bash scripts/poc.sh --scenario $(or $(SCENARIO),exec)

# Same as poc-scenario, but opens a 2-pane tmux window (rsclient | rsbeacon)
# for screenshotting the run. See scripts/poc_tmux.sh.
poc-scenario-tmux:
	bash scripts/poc_tmux.sh --scenario $(or $(SCENARIO),exec)

# Arbitrary baseline-vs-evasion comparison — see `bash scripts/poc.sh --help`
# for --cmd/--baseline-cmd/--events/--query.
# Usage:
#   make poc-compare PROFILE=ghost CMD="cat /mnt/target/etc/shadow" \
#       BASELINE_CMD="cat /etc/shadow" QUERY=cat
poc-compare:
	bash scripts/poc.sh --compare --profile $(or $(PROFILE),ghost) \
	  $(if $(CMD),--cmd "$(CMD)",) \
	  $(if $(BASELINE_CMD),--baseline-cmd "$(BASELINE_CMD)",) \
	  $(if $(EVENTS),--events "$(EVENTS)",) \
	  $(if $(QUERY),--query "$(QUERY)",)

# ---------------------------------------------------------------------------
# VM harness — clean state management
# ---------------------------------------------------------------------------

# Delete any leftover pytest-clean snapshots from both VMs.
# Run this after a crashed test run to unblock the next one.
vm-clean:
	virsh snapshot-delete $(VM_DOMAIN)        pytest-clean 2>/dev/null || true
	virsh snapshot-delete $(VM_DOMAIN_BEACON) pytest-clean 2>/dev/null || true
	@echo "Stale pytest-clean snapshots removed (errors above are OK)."

# Full reset: restore VMs to their baseline snapshots, then deploy fresh code.
# Standard command before running tests after a code change.
vm-reset: vm-clean
	@echo "==> Reverting $(VM_DOMAIN) to $(VM_SNAPSHOT)"
	virsh snapshot-revert $(VM_DOMAIN) $(VM_SNAPSHOT) --running
	@echo "==> Reverting $(VM_DOMAIN_BEACON) to $(BEACON_SNAPSHOT)"
	virsh snapshot-revert $(VM_DOMAIN_BEACON) $(BEACON_SNAPSHOT) --running
	@until ssh -o ConnectTimeout=3 $(REMOTE) echo ok 2>/dev/null; do sleep 2; done
	@until ssh -o ConnectTimeout=3 $(BEACON_VM) echo ok 2>/dev/null; do sleep 2; done
	@echo "==> Deploying fresh code"
	$(MAKE) deploy-beacon
	@echo "==> VMs ready for testing."

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# Run evasion-specific tests (tracee on dev-vm-2; no kmod required).
# Usage:
#   make test-evasion                # deploy + run
#   make test-evasion NO_DEPLOY=1    # skip deploy (use existing build)
#   make test-evasion-clean          # vm-reset + run (fresh state, no stale snapshots)
#   make test-evasion NETSTACK=smoltcp-xdp XDP_IFACE=enp1s0   # exercise the smoltcp-xdp backend
test-evasion:
	cd tests/remote && uv run pytest $(if $(NO_DEPLOY),--no-deploy,) \
	  --no-header -v -s \
	  --log-cli-level=INFO \
	  --remote=$(REMOTE) \
	  --beacon-host=$(BEACON_VM) \
	  --beacon-port=$(BEACON_PORT) \
	  --beacon-vm-snapshot=$(BEACON_SNAPSHOT) \
	  --client-vm-snapshot=$(VM_SNAPSHOT) \
	  --netstack=$(NETSTACK) \
	  $(if $(XDP_IFACE),--xdp-iface=$(XDP_IFACE),) \
	  --xdp-queue=$(XDP_QUEUE) \
	  test_evasion.py

# Full clean run: reset VMs, then run evasion tests without a second deploy.
test-evasion-clean: vm-reset
	$(MAKE) test-evasion NO_DEPLOY=1

# Run mount profile overlay tests.
# Usage:
#   make test-mount-profiles                # deploy + run
#   make test-mount-profiles NO_DEPLOY=1    # skip deploy
#   make test-mount-profiles-clean          # vm-reset + run
test-mount-profiles:
	cd tests/remote && uv run pytest $(if $(NO_DEPLOY),--no-deploy,) \
	  --no-header -v -s \
	  --log-cli-level=INFO \
	  --remote=$(REMOTE) \
	  --beacon-host=$(BEACON_VM) \
	  --beacon-port=$(BEACON_PORT) \
	  --beacon-vm-snapshot=$(BEACON_SNAPSHOT) \
	  --client-vm-snapshot=$(VM_SNAPSHOT) \
	  test_mount_profiles.py

test-mount-profiles-clean: vm-reset
	$(MAKE) test-mount-profiles NO_DEPLOY=1

# Run the pytest VM integration suite.
# Usage:
#   make test-vm                     # deploy + run all tests
#   make test-vm NO_DEPLOY=1         # skip deploy (use existing build)
test-vm:
	cd tests/remote && uv run pytest $(if $(NO_DEPLOY),--no-deploy,) \
	  --no-header -q \
	  --remote=$(REMOTE) \
	  --beacon-host=$(BEACON_VM) \
	  --beacon-port=$(BEACON_PORT)