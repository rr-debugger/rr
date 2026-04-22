KERNELRELEASE ?= $(shell uname -r)
KDIR := /lib/modules/$(KERNELRELEASE)/build

DKMS_NAME    := zen_workaround
DKMS_VERSION := 0.1
DKMS_SOURCES := Makefile dkms.conf zen_workaround.c README

obj-m = zen_workaround.o

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

signed: all
	sudo $(KDIR)/scripts/sign-file sha512 /var/lib/shim-signed/mok/MOK.priv /var/lib/shim-signed/mok/MOK.der zen_workaround.ko

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

dkms-install:
	install -d /usr/src/$(DKMS_NAME)-$(DKMS_VERSION)
	install -m 0644 -t /usr/src/$(DKMS_NAME)-$(DKMS_VERSION) $(DKMS_SOURCES)
	-dkms add     -m $(DKMS_NAME) -v $(DKMS_VERSION)
	dkms build    $(DKMS_NAME)/$(DKMS_VERSION) --force
	dkms install  $(DKMS_NAME)/$(DKMS_VERSION) --force

dkms-uninstall:
	-dkms remove $(DKMS_NAME)/$(DKMS_VERSION) --all
	rm -rf /usr/src/$(DKMS_NAME)-$(DKMS_VERSION)
