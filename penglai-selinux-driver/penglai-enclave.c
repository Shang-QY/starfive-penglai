#include "penglai-enclave.h"
#include "penglai-enclave-ioctl.h"

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

int attest_linux(struct tee_report_t *report, unsigned long nonce)
{
	struct sbiret ret = {0};
	int retval;

	ret = SBI_CALL_2(SBI_SM_ATTEST_SEC_LINUX, __pa(report), nonce);
	if (ret.error)
	{
		printk("KERNEL MODULE: sbi call attest secure linux is failed \n");
	}
	retval = ret.value;
	return retval;
}
