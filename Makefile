obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o lib/scth.o utils/sha256_utils.o utils/utils.o utils/state.o

SYS_CALL_TABLE = $(shell sudo cat /sys/module/the_usctm/parameters/sys_call_table_address)
PASSWORD = $(shell cat ./password)
LOG_DIRECTORY_PATH = /tmp/refmon_log
SINGLEFILE_FS_DIR = ./singlefile-FS


all: compile mount

compile:
	@echo "\nCOMPILING MODULES...\n"

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

	gcc $(SINGLEFILE_FS_DIR)/singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/singlefile-FS modules

	$(MAKE) create_singlefilefs

	@echo "\nMODULES COMPILED!\n"

clean: unmount clean_compile

clean_compile:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/the_usctm clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	-rm onefilemakefs

	@echo "\nCOMPILED CLEANED!\n"

create_singlefilefs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	-mkdir $(LOG_DIRECTORY_PATH)

mount_fs:
	sudo insmod $(SINGLEFILE_FS_DIR)/singlefilefs.ko
	sudo mount -o loop -t singlefilefs image $(LOG_DIRECTORY_PATH)/

unmount_fs:
	sudo umount $(LOG_DIRECTORY_PATH)/
	rm $(LOG_DIRECTORY_PATH)

mount: 
	@echo "\nMOUNTING MODULES...\n"

	-$(MAKE) mount_usctm 
	$(MAKE) mount_reference_monitor
	$(MAKE) mount_fs
	

	@echo "\nMODULES MOUNTED!\n"

mount_usctm:
	sudo insmod ./the_usctm/the_usctm.ko

mount_reference_monitor:
	sudo insmod the_reference_monitor.ko the_syscall_table=$(SYS_CALL_TABLE) the_password=$(PASSWORD)

unmount:
	@echo "\nUNMOUNTING MODULES...\n"

	-sudo rmmod ./the_usctm/the_usctm.ko
	-sudo rmmod the_reference_monitor.ko
	-$(MAKE) unmount_fs
	-sudo rmmod ./singlefile-FS/singlefilefs.ko

	@echo "\nMODULES UNMOUNTED!\n"
