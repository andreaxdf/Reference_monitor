obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o lib/scth.o utils/sha256_utils.o utils/utils.o utils/state.o

SYS_CALL_TABLE = $(shell sudo cat /sys/module/the_usctm/parameters/sys_call_table_address)
PASSWORD = $(shell cat ./password)


all: compile mount

compile:
	@echo "\nCOMPILING MODULES...\n"

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

	@echo "\nMODULES COMPILED!\n"

clean: unmount clean_compile

clean_compile:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

	@echo "\nCOMPILED CLEANED!\n"

mount: 
	@echo "\nMOUNTING MODULES...\n"

	$(MAKE) mount_usctm 
	$(MAKE) mount_reference_monitor

	@echo "\nMODULES MOUNTED!\n"


mount_usctm:
	sudo insmod ./the_usctm/the_usctm.ko

mount_reference_monitor:
	sudo insmod the_reference_monitor.ko the_syscall_table=$(SYS_CALL_TABLE) the_password=$(PASSWORD)

unmount:
	@echo "\nUNMOUNTING MODULES...\n"

	sudo rmmod ./the_usctm/the_usctm.ko
	sudo rmmod the_reference_monitor.ko

	@echo "\nMODULES UNMOUNTED!\n"
