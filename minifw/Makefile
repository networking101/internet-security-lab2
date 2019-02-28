obj-m += telnetin.o
obj-m += telnetout.o
obj-m += webout.o
obj-m += sshin.o
obj-m += sshout.o
all:	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:	
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
