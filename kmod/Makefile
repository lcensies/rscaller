include      ../lib/khook/Makefile.khook

# EXTRA_CFLAGS=-I$(PWD)/../lib/khook
MODULE_NAME := rscaller
PWD := $(shell pwd)
KMOD_DIR := ${PWD}
LIB_DIR := ${KMOD_DIR}/lib
EXTRA_CFLAGS += -DDIRTY=no
# Pass RSC_DEBUG=1 on the make command line to enable verbose kmod logging
ifdef RSC_DEBUG
ccflags-y += -DRSC_DEBUG
endif
# Kernel source directory 
KDIR := /lib/modules/$(shell uname -r)/build
# Alternatively, create Kbuild file with contents:
obj-m += rscaller.o 
# buffer.o
# obj-m += ${MODULE_NAME}.o 
# rscaller-y +=  $(KHOOK_GOALS)
rscaller-y += buffer.o  buffer_device.o syscalls.o  $(KHOOK_GOALS) main.o remote_fs.o shadow_fd.o
# rscaller-y += buffer.o
ccflags-y += -std=gnu99 $(KHOOK_CCFLAGS)

ldflags-y  += $(KHOOK_LDFLAGS) # use LDFLAGS for old kernels


headers:
	@if [ ! -d /lib/modules/$(shell uname -r)/build ]; then \
		echo "Kernel headers not found. Run: sudo apt-get install linux-headers-$(shell uname -r)"; \
		exit 1; \
	fi

all: headers
	$(MAKE) -C $(KDIR) M=${KMOD_DIR} modules 


unload:
	rmmod  ${MODULE_NAME} || :

insert: unload
	insmod ${MODULE_NAME}.ko

reload: all insert


clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean


# Skip objtool for khook assembly stub (has naked rets that objtool doesn't understand)
OBJECT_FILES_NON_STANDARD_stub.o := y
OBJECT_FILES_NON_STANDARD := y
