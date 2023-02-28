#ifndef _PENGLAI_ENCLAVE_IOCTL
#define _PENGLAI_ENCLAVE_IOCTL
#include "penglai-enclave.h"
#include <linux/uaccess.h>
#include <linux/types.h>
#include <asm/timex.h>

#define PENGLAI_IOC_LOAD_AND_RUN_LINUX \
	_IOR(PENGLAI_ENCLAVE_IOC_MAGIC, 0x00, struct penglai_enclave_user_param)

struct penglai_enclave_user_param
{
	unsigned long bin_ptr;
	unsigned long bin_size;
    unsigned long bin_loadaddr;
    unsigned long dtb_ptr;
    unsigned long dtb_size;
    unsigned long dtb_loadaddr;
};

long penglai_enclave_ioctl(struct file* filep, unsigned int cmd, unsigned long args);

#endif
