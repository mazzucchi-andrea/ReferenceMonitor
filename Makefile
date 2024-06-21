obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o lib/scth.o lib/vtpmo.o lib/usctm.o file.o dir.o paths_list.o wrappers.o

A = the_password

all:
	gcc logfilemakefs.c -o logfilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm logfilemakefs
	rm -r mount
	rm image

load:
	insmod the_reference_monitor.ko the_password=$(A)

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

build:
	make all create-fs

rebuild:
	make clean build
