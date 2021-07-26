CC = gcc
CC_FLAGS = -Wall -g
CC_LIBS = -lnetfilter_queue

PROGS = filter

ifneq ($(KERNELRELEASE),)
	obj-m += syndrv.o
else
	PWD := $(shell pwd)
	KVER := $(shell uname -r)
	KDIR := /lib/modules/$(KVER)/build
default:    
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$(MAKE) -C $(PWD) $(PROGS)

all: kernel $(PROGS)
	
$(PROGS).o: $(PROGS).c
	$(CC) $(CC_FLAGS) -c -o $@ $^ $(CC_LIBS)

$(PROGS): $(PROGS).o
	$(CC) $(CC_FLAGS) -o $@ $^ $(CC_LIBS)

kernel:
	make -C $(KDIR) M=$(PWD) modules 
clean:
	rm -rf *.o *.mod.c *.ko *.symvers *.order *.makers $(PROGS)
endif
