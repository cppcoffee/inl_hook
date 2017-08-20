#
# Makefile for the ipvs modules.
#
udis86_extra-objs-y := udis86/decode.o \
	udis86/syn-intel.o \
	udis86/itab.o \
	udis86/syn-att.o \
	udis86/syn.o \
	udis86/udis86.o

hello-objs := hello_core.o inl_hook.o $(udis86_extra-objs-y)

obj-m += hello.o

KDIR := ~/linux-3.10.0-514.26.2.el7
PWD  := $(shell pwd)

EXTRA_CFLAGS += -I$(shell pwd)/udis86/
EXTRA_CFLAGS += -D__KERNEL__
EXTRA_CFLAGS += -O -g 

modules:
	make -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules

clean:
	rm -rf .tmp_versions/
	rm -f *.swp
	rm -f *.o
	rm -f *.ko
	rm -f modules.order
	rm -f Module.symvers
	rm -f modules.order

.PHONY: modules clean

