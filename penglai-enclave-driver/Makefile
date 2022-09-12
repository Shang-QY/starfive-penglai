##
## Author: Dong Du
## Description:
## 	The file now assumes the kernel located in ../openeuler-kernel,
##	if you would like to use your own one, please change the path

obj-m += penglai.o
penglai-objs := penglai-enclave-driver.o \
	penglai-enclave-elfloader.o \
	penglai-enclave-page.o \
	penglai-enclave.o \
	penglai-enclave-ioctl.o 

all:
	make -C ../../linux-linux_5.15.10_devel_pwmdac/ CROSS_COMPILE=riscv64-linux-gnu- ARCH=riscv M=$(PWD) modules

clean:
	make -C ../../linux-linux_5.15.10_devel_pwmdac/ ARCH=riscv M=$(PWD) clean
