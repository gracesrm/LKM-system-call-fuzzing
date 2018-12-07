obj-m += hook.o
hook-objs += unpred.o hook3.o
all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
# obj-m += hook32.o
# hook-objs += hook32.o
# all:
# 	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
# clean:
# 	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
