obj-m += patchguard.o

default: all

clean:
	make -C /lib/modules/`uname -r`/build SUBDIRS=`pwd` clean

all:
	make -C /lib/modules/`uname -r`/build SUBDIRS=`pwd` modules
