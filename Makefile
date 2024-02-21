obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o lib/scth.o

A = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)
B = the_password

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

load:
	insmod the_reference_monitor.ko the_syscall_table=$(A) the_password=$(B)

unload:
	rmmod the_reference_monitor.ko

