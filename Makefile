PWD := $(shell pwd)
KMOD_DIR := ${PWD}/kmod
SCRIPTS_DIR := scripts
BINDGEN_DIR := rsclient/src/bindings/src

KERNEL_VOLUMES := -v /lib/modules:/lib/modules -v /usr/src/kernels:/usr/src/kernels 
APP_VOLUME := -v ${PWD}:/app
COMMON_VOLUMES := ${KERNEL_VOLUMES} ${APP_VOLUME}

MAKE_CMD := docker run --rm -it ${COMMON_VOLUMES} -w /app gcc:15.1.0 make

.PHONY: kmod kmod_reload

# TODO: download linux kernel sources
# TODO2: use syscall table based on kernel sourcecs

configure: btf bindings handlers
# 	sudo dnf install kernel-devel-$(uname -r)
	git submodule update --init --remote

bindings:
	cd ${BINDGEN_DIR} && cargo run ${KMOD_DIR}/rscaller.h


handlers:
	cd ${SCRIPTS_DIR} && poetry install && \
		ls && poetry run python3 generate_handler_wrappres.py

btf:
	# https://github.com/TuxInvader/focal-mainline-builder
	# Ensure that we have accerss to docker socket
	docker ps > /dev/null 2>/dev/null
	docker run --privileged calico/bpftool /bpftool btf dump file /sys/kernel/btf/vmlinux format c > kmod/vmlinux.h

kmod: 
	${MAKE_CMD} -C kmod

kmod_reload:
	${MAKE_CMD} -C kmod reload

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