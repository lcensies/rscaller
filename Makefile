MODULE_NAME := rscaller
PWD := $(shell pwd)
KMOD_DIR := ${PWD}/kmod

.PHONY: kmod kmod_reload

kmod: 
	sudo make -C ${KMOD_DIR} 

kmod_reload:
	sudo make -C ${KMOD_DIR} reload


