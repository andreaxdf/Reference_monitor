obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o lib/scth.o

SYS_CALL_TABLE = $(shell sudo cat /sys/module/the_usctm/parameters/sys_call_table_address)


setup: all mount

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

mount:
	sudo insmod ./the_usctm/the_usctm.ko
	sudo insmod the_reference_monitor.ko the_syscall_table=$(SYS_CALL_TABLE)

unmount:
	sudo rmmod ./the_usctm/the_usctm.ko
	sudo rmmod the_reference_monitor.ko
