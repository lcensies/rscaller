# Name of the module

MODULE_NAME := rscaller
# Current directory
PWD := $(shell pwd)
KMOD_DIR := ${PWD}
obj-m := ${MODULE_NAME}.o
ccflags-y := -std=gnu99
EXTRA_CFLAGS += -DDIRTY=no


# Kernel source directory (update this to match your system)
KDIR := /lib/modules/$(shell uname -r)/build


all:
	$(MAKE) -C $(KDIR) M=${KMOD_DIR} modules 

insert:
	sudo rmmod  ${MODULE_NAME} 2>/dev/null || :
	sudo insmod ${MODULE_NAME}.ko

reload: all insert

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

