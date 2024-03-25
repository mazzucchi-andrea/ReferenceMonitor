obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o lib/scth.o file.o dir.o

A = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)
B = the_password

all:
	gcc logfilemakefs.c -o logfilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -r mount
	rm image
	rm logfilemakefs

load:
	insmod the_reference_monitor.ko the_syscall_table=$(A) the_password=$(B)

unload:
	rmmod the_reference_monitor.ko

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./logfilemakefs image
	mkdir mount
	
mount-fs:
	mount -o loop -t logfilefs image ./mount/

unmount-fs:
	umount ./mount/
