PWD := $(shell pwd)
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

.PHONY: kmod kmod_reload

# TODO: download linux kernel sources
# TODO2: use syscall table based on kernel sourcecs

configure: btf bindings handlers
# 	sudo dnf install kernel-devel-$(uname -r)
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