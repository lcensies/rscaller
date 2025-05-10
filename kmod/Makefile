MODULE_NAME := rscaller
PWD := $(shell pwd)
KMOD_DIR := ${PWD}
LIB_DIR := ${KMOD_DIR}/lib
obj-m := ${MODULE_NAME}.o
ccflags-y := -std=gnu99 
EXTRA_CFLAGS += -DDIRTY=no
# Kernel source directory (update this to match your system)
KDIR := /lib/modules/$(shell uname -r)/build

LIBURING_URL := https://github.com/axboe/liburing/



liburing_dir :="${LIB_DIR}/liburing"
liburing:
	@test -d ${liburing_dir} || git clone "${LIBURING_URL}" ${liburing_dir}
	make -C ${liburing_dir}
	sudo make -C ${liburing_dir} install

configure: liburing


all:
	$(MAKE) -C $(KDIR) M=${KMOD_DIR} modules 

insert:
	sudo rmmod  ${MODULE_NAME} 2>/dev/null || :
	sudo insmod ${MODULE_NAME}.ko

reload: all insert

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

