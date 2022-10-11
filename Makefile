OFA_DIR ?= /usr/src/ofa_kernel/default
OFA_INCLUDE := $(OFA_DIR)/include
OFA_SYMVERS := $(OFA_DIR)/Module.symvers

ifneq ($(LINUXINCLUDE),)

LINUXINCLUDE := \
	-I$(OFA_INCLUDE) \
	${LINUXINCLUDE}
else
export KBUILD_EXTRA_SYMBOLS=$(OFA_SYMVERS)
KDIR := /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
endif

obj-m := prefetch_module.o
prefetch_module-objs := ksocket.o prefetch_queue.o prefetch_rdma.o prefetch_mmap.o prefetch_tracker.o
