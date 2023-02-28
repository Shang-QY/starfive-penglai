#ifndef _PL_ENCLAVE
#define _PL_ENCLAVE
#include "elf.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <pthread.h>
#include <string.h>

#define PENGLAI_ENCLAVE_DEV_PATH "/dev/penglai_sec_linux_dev"

#define PENGLAI_ENCLAVE_IOC_MAGIC 0xa4

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

struct PLenclave
{
    struct elf_args *bin_file;
    struct elf_args *dtb_file;
    int fd;
    struct penglai_enclave_user_param user_param;
};

void PLenclave_init(struct PLenclave *PLenclave);
void PLenclave_finalize(struct PLenclave *PLenclave);
int PLenclave_load_and_run(struct PLenclave *PLenclave, struct elf_args *u_bin_file, unsigned long bin_loadaddr, struct elf_args *u_dtb_file, unsigned long dtb_loadaddr);

#endif
