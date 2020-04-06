CC = gcc
DEFS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_SVID_SOURCE -D_POSIX_C_SOURCE=200809L

MODULE_NAME = secvault

KDIR := /lib/modules/`uname -r`/build
MAKE = make

obj-m := $(MODULE_NAME).o

all: module svctl

module:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=um V=1 modules

%.o: %.c
	$(CC) -std=c99 -Wall -pedantic -g $(DEFS) -o $@ -c $^

svctl: svctl.o
	$(CC) -std=c99 -Wall -pedantic -g $(DEFS) -o $@ $^

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=um V=1 clean
	rm -f svctl

install:
	mknod /dev/sv_data0 c 231 0
	mknod /dev/sv_data1 c 231 1
	mknod /dev/sv_data2 c 231 2
	mknod /dev/sv_data3 c 231 3
	mknod /dev/sv_ctl c 231 4

purge:
	rm -f /dev/sv_data0
	rm -f /dev/sv_data1
	rm -f /dev/sv_data2
	rm -f /dev/sv_data3
	rm -f /dev/sv_ctl
