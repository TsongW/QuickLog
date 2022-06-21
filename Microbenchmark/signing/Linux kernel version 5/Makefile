obj-m += quickmod.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
ccflags-y := -std=gnu99 -Wno-declaration-after-statement -mmmx -mavx -maes -mpreferred-stack-boundary=4


all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
