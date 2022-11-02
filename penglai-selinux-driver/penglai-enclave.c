#include "penglai-enclave.h"

int run_linux(void)
{
	struct sbiret ret = {0};
	int retval;

	ret = SBI_CALL_0(SBI_SM_RUN_SEC_LINUX);
	if (ret.error)
	{
		printk("KERNEL MODULE: sbi call run secure linux is failed \n");
	}
	retval = ret.value;
	return retval;
}
