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


handlers:
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
# ---------------------------------------------------------------------------
# Rust workspace
# ---------------------------------------------------------------------------
REMOTE      ?= dev-vm-1
CLIENT      ?=
BEACON_HOST ?= 0.0.0.0
BEACON_PORT ?= 9999
# Libvirt domain names (default to SSH host names)
VM_DOMAIN        ?= $(REMOTE)
VM_SNAPSHOT      ?= clean-base-docker-nokmod
VM_DOMAIN_CLIENT ?= $(CLIENT)

.PHONY: build test integration-tests setup-remote provision deploy deploy-remote deploy-no-snap \
        test-remote test-remote-no-snap test-vm handlers snapshot-create snapshot-restore

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
	$(if $(CLIENT),ansible-playbook -i $(CLIENT), -u ubuntu scripts/provision.yml,)

deploy:
	bash scripts/deploy.sh $(REMOTE)

# Create a clean-state snapshot (run once on a freshly booted VM with no kmod loaded)
snapshot-create:
	virsh snapshot-create-as $(VM_DOMAIN) $(VM_SNAPSHOT) \
	  --description "clean boot, no kmod loaded" --atomic
	$(if $(VM_DOMAIN_CLIENT),virsh snapshot-create-as $(VM_DOMAIN_CLIENT) $(VM_SNAPSHOT) \
	  --description "clean boot" --atomic,)

# Revert to clean snapshot before deploy+test (prevents stuck-module artifacts)
snapshot-restore:
	bash scripts/vm_restore.sh $(VM_DOMAIN) $(VM_SNAPSHOT)
	$(if $(VM_DOMAIN_CLIENT),bash scripts/vm_restore.sh $(VM_DOMAIN_CLIENT) $(VM_SNAPSHOT),)

deploy-remote: snapshot-restore
	bash scripts/deploy.sh $(REMOTE)
	$(if $(CLIENT),bash scripts/deploy.sh $(CLIENT),)
	$(call CARGO,build --release -p rsbeacon)

# Like deploy-remote + test-remote but skips snapshot restore (VM has no snapshots)
deploy-no-snap:
	bash scripts/deploy.sh $(REMOTE)
	$(if $(CLIENT),bash scripts/deploy.sh $(CLIENT),)
	$(call CARGO,build --release -p rsbeacon)

test-remote: deploy-remote
	REMOTE=$(REMOTE) CLIENT=$(CLIENT) BEACON_HOST=$(BEACON_HOST) BEACON_PORT=$(BEACON_PORT) \
	  bash scripts/test_remote.sh $(REMOTE)

test-remote-no-snap: deploy-no-snap
	REMOTE=$(REMOTE) CLIENT=$(CLIENT) BEACON_HOST=$(BEACON_HOST) BEACON_PORT=$(BEACON_PORT) \
	  bash scripts/test_remote.sh $(REMOTE)

# pytest-based VM integration tests
# Usage: make test-vm [REMOTE=dev-vm-1] [CLIENT=dev-vm-2] [NO_DEPLOY=1]
test-vm:
	cd tests/remote && pytest $(if $(NO_DEPLOY),--no-deploy,) \
	  --remote=$(REMOTE) $(if $(CLIENT),--client=$(CLIENT),) \
	  --beacon-port=$(BEACON_PORT)
