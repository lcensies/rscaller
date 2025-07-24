include      ../lib/khook/Makefile.khook

# EXTRA_CFLAGS=-I$(PWD)/../lib/khook
MODULE_NAME := rscaller
PWD := $(shell pwd)
KMOD_DIR := ${PWD}
LIB_DIR := ${KMOD_DIR}/lib
EXTRA_CFLAGS += -DDIRTY=no
# Kernel source directory 
KDIR := /lib/modules/$(shell uname -r)/build
# Alternatively, create Kbuild file with contents:
obj-m += rscaller.o buffer.o
# obj-m += ${MODULE_NAME}.o 
# rscaller-y +=  $(KHOOK_GOALS)
rscaller-y += main.o $(KHOOK_GOALS)
# rscaller-y += buffer.o
ccflags-y += -std=gnu99 $(KHOOK_CCFLAGS)

ldflags-y  += $(KHOOK_LDFLAGS) # use LDFLAGS for old kernels


all:
	$(MAKE) -C $(KDIR) M=${KMOD_DIR} modules 

insert:
	rmmod  ${MODULE_NAME} || :
	insmod ${MODULE_NAME}.ko

reload: all insert

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

