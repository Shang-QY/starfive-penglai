#include "penglai-enclave-ioctl.h"
#include "syscall.h"

int penglai_load_and_run_linux(struct file *filep, unsigned long args)
{
    struct penglai_enclave_user_param *enclave_param = (struct penglai_enclave_user_param *)args;
    int ret = run_linux();

    return ret;
}

long penglai_enclave_ioctl(struct file *filep, unsigned int cmd, unsigned long args)
{
    char ioctl_data[1024];
    int ioc_size, ret;

    ioc_size = _IOC_SIZE(cmd);
    if (ioc_size > sizeof(ioctl_data))
    {
        printk("KERNEL MODULE : ioc_data buff is not enough\n");
        return -EFAULT;
    }

    if (copy_from_user(ioctl_data, (void *)args, ioc_size))
    {
        printk("KERNEL MODULE : copy from the user is failed\n");
        return -EFAULT;
    }

    switch (cmd)
    {
    case PENGLAI_IOC_LOAD_AND_RUN_LINUX:
        ret = penglai_load_and_run_linux(filep, (unsigned long)ioctl_data);
        break;
    default:
        return -EFAULT;
    }

    if (copy_to_user((void *)args, ioctl_data, ioc_size))
    {
        printk("KERNEL MODULE: ioc_data buff is not enough\n");
        return -EFAULT;
    }
    return ret;
}
