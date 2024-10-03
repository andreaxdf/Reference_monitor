obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

LOG_DIRECTORY_PATH = /tmp/refmon_log

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

load-FS-driver:
	sudo insmod singlefilefs.ko

unload-FS-driver:
	sudo rmmod singlefilefs

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm singlefilemakefs
	rmdir $(LOG_DIRECTORY_PATH)
	rm image

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	mkdir $(LOG_DIRECTORY_PATH)
	
mount-fs:
	sudo mount -o loop -t singlefilefs image $(LOG_DIRECTORY_PATH)/

unmount-fs:
	sudo umount $(LOG_DIRECTORY_PATH)/
