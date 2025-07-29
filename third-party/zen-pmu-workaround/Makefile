obj-m = zen_workaround.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

signed: all
	sudo /lib/modules/$(shell uname -r)/build/scripts/sign-file sha512 /var/lib/shim-signed/mok/MOK.priv /var/lib/shim-signed/mok/MOK.der zen_workaround.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
