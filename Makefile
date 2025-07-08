PWD := $(shell pwd)
KMOD_DIR := ${PWD}/kmod
SCRIPTS_DIR := scripts
BINDGEN_DIR := rsclient/src/bindings/src

.PHONY: kmod kmod_reload

# TODO: download linux kernel sources
# TODO2: use syscall table based on kernel sourcecs

configure: btf bindings handlers
	#sudo apt install clang
	which poetry || pip install poetry
	which bindgen || $(yes | cargo binstall bindgen-cli)

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
	sudo make -C ${KMOD_DIR} 

kmod_reload:
	sudo make -C ${KMOD_DIR} reload
