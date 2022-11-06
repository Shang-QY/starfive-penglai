#include "penglai-enclave-ioctl.h"
#include "syscall.h"

int penglai_load_and_run_linux(struct file *filep, unsigned long args)
{
    struct penglai_enclave_user_param *enclave_param = (struct penglai_enclave_user_param *)args;
    unsigned long payload_mem_start = (unsigned long)(__va(0x180000000));
    unsigned long payload_mem_size = 0x100000000;
    unsigned long payload_bin_start = (unsigned long)(__va(0x180200000));
    unsigned long payload_dtb_start = (unsigned long)(__va(0x182200000));
    int ret;

    printk("KERNEL MODULE : hello qy\n");
    printk("KERNEL MODULE : linear va start(page offset):   0x%lx, and pa: 0x%lx\n", PAGE_OFFSET, __pa(PAGE_OFFSET));
    printk("KERNEL MODULE : linear va of test_payload:      0x%lx, and pa: 0x%lx\n", (unsigned long)(__va(0x180000000)), 0x180000000);
    printk("KERNEL MODULE : bye\n");

    memset((void*)payload_mem_start, 0, payload_mem_size);

    if(copy_from_user((void*)payload_bin_start, (void*)enclave_param->bin_ptr, enclave_param->bin_size))
	{
		printk("KERNEL MODULE : bin copy from the user is failed\n");
		return -EFAULT;
	}

    if(copy_from_user((void*)payload_dtb_start, (void*)enclave_param->dtb_ptr, enclave_param->dtb_size))
	{
		printk("KERNEL MODULE : dtb copy from the user is failed\n");
		return -EFAULT;
	}

    ret = run_linux();

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
