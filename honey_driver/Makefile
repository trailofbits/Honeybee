KDIR = /lib/modules/`uname -r`/build
obj-m += honey_driver.o
M := make -C ${KDIR} M=`pwd`

all:
	${M} modules
clean:
	${M} clean
build_install:
	`rmmod honey_driver` || echo "Unload failed -- not loaded?"
	${M} modules
	${M} modules_install
	`insmod honey_driver.ko`
	${M} clean
unload:
	`rmmod honey_driver` || echo "Unload failed -- not loaded?"