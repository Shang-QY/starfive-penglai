#include "penglai-enclave-ioctl.h"
#include "syscall.h"

#define PAGE_UP(addr)	(((addr)+((PAGE_SIZE)-1))&(~((PAGE_SIZE)-1)))

//TODO: improve concurrency
//now we just acqure a big lock before allocating enclave mem, and release the lock
//after initializing mem and returning it back to sm
DEFINE_SPINLOCK(enclave_create_lock);

unsigned int total_enclave_page(int elf_size, int stack_size)
{
  unsigned int total_pages;
  total_pages = PAGE_UP(elf_size) / RISCV_PGSIZE + PAGE_UP(stack_size) / RISCV_PGSIZE + 15;
  return total_pages;
}

int create_sbi_param(enclave_t* enclave, struct penglai_enclave_sbi_param * enclave_sbi_param,
    unsigned long paddr, unsigned long size, unsigned long entry_point,
    unsigned long untrusted_ptr, unsigned long untrusted_size, unsigned long free_mem)
{
  enclave_sbi_param -> eid_ptr = (unsigned int* )__pa(&enclave -> eid);
  enclave_sbi_param -> ecall_arg0 = (unsigned long* )__pa(&enclave -> ocall_func_id);
  enclave_sbi_param -> ecall_arg1 = (unsigned long* )__pa(&enclave -> ocall_arg0);
  enclave_sbi_param -> ecall_arg2 = (unsigned long* )__pa(&enclave -> ocall_arg1);
  enclave_sbi_param -> ecall_arg3 = (unsigned long* )__pa(&enclave -> ocall_syscall_num);
  enclave_sbi_param -> paddr = paddr;
  enclave_sbi_param -> size = size;
  enclave_sbi_param -> entry_point = entry_point;
  enclave_sbi_param -> untrusted_ptr = untrusted_ptr ;
  enclave_sbi_param -> untrusted_size = untrusted_size;
  enclave_sbi_param -> free_mem = free_mem;
  return 0;
}

int alloc_untrusted_mem(unsigned long untrusted_mem_size, unsigned long* untrusted_mem_ptr, enclave_t* enclave)
{
  int ret = 0;
  vaddr_t addr;
  unsigned long order = ilog2((untrusted_mem_size >> RISCV_PGSHIFT)- 1) + 1;

  addr = __get_free_pages(GFP_HIGHUSER,order);
  if(!addr)
  {
    printk("KERNEL MODULE: can not alloc untrusted mem \n");
    return -1;
  }

  *untrusted_mem_ptr = addr;
  map_untrusted_mem(enclave -> enclave_mem, DEFAULT_UNTRUSTED_PTR, __pa(addr), untrusted_mem_size);

  return ret;
}

int check_eapp_memory_size(long elf_size, long stack_size, long untrusted_mem_size)
{
  if((elf_size > MAX_ELF_SIZE) || (stack_size > MAX_STACK_SIZE) || (untrusted_mem_size > MAX_UNTRUSTED_MEM_SIZE))
    return -1;
  return 0;
}

int penglai_enclave_create(struct file * filep, unsigned long args)
{
  struct penglai_enclave_user_param* enclave_param = (struct penglai_enclave_user_param*)args;
  void *elf_ptr = (void*)enclave_param->elf_ptr;
  long elf_size = enclave_param->elf_size;
  long stack_size = enclave_param->stack_size;
  long untrusted_mem_size = enclave_param->untrusted_mem_size;
  unsigned long untrusted_mem_ptr = enclave_param->untrusted_mem_ptr;
  struct penglai_enclave_sbi_param enclave_sbi_param;
  enclave_t* enclave;
  unsigned int total_pages = total_enclave_page(elf_size, stack_size);
  unsigned long free_mem, elf_entry;
  unsigned long order = ilog2(total_pages- 1) + 1;
  struct sbiret ret = {0};

  total_pages = 0x1 << order;
  if(check_eapp_memory_size(elf_size, stack_size, untrusted_mem_size) < 0)
  {
    printk("KERNEL MODULE: eapp memory is out of bound \n");
    return -1;
  }

  spin_lock(&enclave_create_lock);

  enclave = create_enclave(total_pages);
  if(!enclave)
  {
    printk("KERNEL MODULE: cannot create enclave\n");
    goto destroy_enclave;
  }

  elf_entry = 0;
  if(penglai_enclave_eapp_preprare(enclave->enclave_mem, elf_ptr, elf_size,
        &elf_entry, STACK_POINT, stack_size))
  {
    printk("KERNEL MODULE: penglai_enclave_eapp_preprare is failed\n");;
    goto destroy_enclave;
  }
  if(elf_entry == 0)
  {
    printk("KERNEL MODULE: elf_entry reset is failed \n");
    goto destroy_enclave;
  }

  untrusted_mem_size = 0x1 << (ilog2(untrusted_mem_size - 1) + 1);
  if((untrusted_mem_ptr == 0) && (untrusted_mem_size > 0))
  {
    alloc_untrusted_mem(untrusted_mem_size, &untrusted_mem_ptr, enclave);
  }
  enclave->untrusted_mem->addr = (vaddr_t)untrusted_mem_ptr;
  enclave->untrusted_mem->size = untrusted_mem_size;
  printk("[Penglai Driver@%s] untrusted_mem->addr:0x%lx untrusted_mem->size:0x%lx\n",
		  __func__, (vaddr_t)untrusted_mem_ptr, untrusted_mem_size);

  free_mem = get_free_mem(&(enclave->enclave_mem->free_mem));

  create_sbi_param(enclave, &enclave_sbi_param,
      (unsigned long)(enclave->enclave_mem->paddr),
      enclave->enclave_mem->size, elf_entry, __pa(untrusted_mem_ptr),
      untrusted_mem_size, __pa(free_mem));

  printk("[Penglai Driver@%s] enclave_mem->paddr:0x%lx, size:0x%lx\n",
		  __func__, (unsigned long)(enclave->enclave_mem->paddr),
		  enclave->enclave_mem->size);

  ret = SBI_CALL_1(SBI_SM_CREATE_ENCLAVE, __pa(&enclave_sbi_param));

  //if(ret < 0)
  if(ret.error)
  {
    printk("KERNEL  MODULE: SBI_SM_CREATE_ENCLAVE is failed \n");
    goto destroy_enclave;
  }

  enclave_param->eid = enclave_idr_alloc(enclave);

  spin_unlock(&enclave_create_lock);

  return ret.value;

destroy_enclave:

  spin_unlock(&enclave_create_lock);

  if(enclave)
    destroy_enclave(enclave);

  return -EFAULT;
}

int penglai_enclave_destroy(struct file * filep, unsigned long args)
{
  struct penglai_enclave_user_param * enclave_param = (struct penglai_enclave_user_param*) args;
  unsigned long eid = enclave_param ->eid;
  enclave_t * enclave;
  int ret =0;

  enclave = get_enclave_by_id(eid);
  destroy_enclave(enclave);
  enclave_idr_remove(eid);

  return ret;
}

int handle_memory_extend(enclave_t * enclave)
{
  unsigned long pages = enclave ->ocall_arg0;
  unsigned long order = ilog2(pages - 1) + 1;
  unsigned long count = 0x1 << order;
  unsigned long addr;
  struct sbiret ret = {0};

  addr = __get_free_pages(GFP_HIGHUSER,order);
  if (!addr)
  {
    printk("KERNEL MODULE: can not get free pages which order is 0x%lx", order );
    return -1;
  }
  ret = SBI_CALL_2(SBI_SM_MEMORY_EXTEND, __pa(addr), count << RISCV_PGSHIFT);

  return ret.value;
}

int handle_memory_free(enclave_t* enclave)
{
  unsigned long pages = enclave ->ocall_arg0;
  unsigned long paddr = enclave ->ocall_arg1;
  unsigned long order = ilog2(pages - 1) + 1;
  unsigned long count = 0x1 << order;

  if(count != pages)
    return -1;
  free_pages((long unsigned int)__va(paddr), order << RISCV_PGSHIFT);

  return 0;
}

int handle_syscall(enclave_t* enclave, unsigned long ocall_syscall_num)
{
  int ret =0;

  switch(ocall_syscall_num)
  {
    case SYS_write:
      {
        /* FIXME */
        char *print_data = (char*)enclave->untrusted_mem->addr;
        print_data[511] = '\0';
        printk(print_data);
        //printk("");
        break;
      }

  }
  return ret;
}

int penglai_enclave_run(struct file *filep, unsigned long args)
{
  struct penglai_enclave_user_param *enclave_param = (struct penglai_enclave_user_param*) args;
  unsigned long eid = enclave_param ->eid;
  enclave_t * enclave;
  //unsigned long ocall_func_id;
  struct sbiret ret = {0};

  enclave = get_enclave_by_id(eid);
  if(!enclave)
  {
    printk("KERNEL MODULE: enclave is not exist \n");
    return -EINVAL;
  }

  ret = SBI_CALL_1(SBI_SM_RUN_ENCLAVE, enclave->eid);
  /*
      FIXME: handler the ocall from enclave;
   */
  while(ret.value == ENCLAVE_TIMER_IRQ)
  {
    schedule();
    ret = SBI_CALL_3(SBI_SM_RESUME_ENCLAVE, enclave->eid, RESUME_FROM_TIMER_IRQ, get_cycles64() + DEFAULT_CLOCK_DELAY);
  }

  //if(ret < 0)
  if(ret.error)
  {
    printk("KERNEL MODULE: sbi call run enclave is failed \n");
    goto destroy_enclave;
  }else{
    printk("[Penglai Driver@%s] run returned successfully\n",
		    __func__);
  }

//free_enclave:

  destroy_enclave(enclave);
  enclave_idr_remove(eid);
  return ret.value;

destroy_enclave:

  destroy_enclave(enclave);
  enclave_idr_remove(eid);

  return -EFAULT;
}

int penglai_enclave_attest(struct file * filep, unsigned long args)
{
  struct penglai_enclave_ioctl_attest_enclave * enclave_param = (struct penglai_enclave_ioctl_attest_enclave*) args;
  unsigned long eid = enclave_param ->eid;
  enclave_t * enclave;
  struct sbiret ret = {0};

  enclave = get_enclave_by_id(eid);
  if (!enclave)
  {
    printk("KERNEL MODULE: enclave is not exist \n");
    return -EINVAL;
  }

  ret = SBI_CALL_3(SBI_SM_ATTEST_ENCLAVE, enclave->eid, __pa(&(enclave_param->report)), enclave_param->nonce);
  return ret.value;
}

long penglai_enclave_stop(struct file* filep, unsigned long args)
{
  struct penglai_enclave_user_param * enclave_param = (struct penglai_enclave_user_param*) args;
  unsigned long eid = enclave_param ->eid;
  enclave_t * enclave;
  struct sbiret ret = {0};

  enclave = get_enclave_by_id(eid);
  if (!enclave)
  {
    printk("KERNEL MODULE: enclave is not exist \n");
    return -EINVAL;
  }
  ret = SBI_CALL_1(SBI_SM_STOP_ENCLAVE, enclave->eid);
  //if (ret < 0)
  if (ret.error)
  {
    printk("KERNEL MODULE: sbi call stop enclave is failed \n");
    //goto destroy_enclave;
  }

  return ret.value;

  //destroy_enclave:
    destroy_enclave(enclave);
    enclave_idr_remove(eid);
    return -EFAULT;
}

int penglai_enclave_resume(struct file * filep, unsigned long args)
{
  struct penglai_enclave_user_param * enclave_param = (struct penglai_enclave_user_param*) args;
  unsigned long eid = enclave_param ->eid;
  enclave_t * enclave;
  struct sbiret ret = {0};

  enclave = get_enclave_by_id(eid);
  if (!enclave)
  {
    printk("KERNEL MODULE: enclave is not exist \n");
    return -EINVAL;
  }
  ret = SBI_CALL_2(SBI_SM_RESUME_ENCLAVE, enclave->eid, RESUME_FROM_STOP);
  //if (ret < 0)
  if (ret.error)
  {
    printk("KERNEL MODULE: sbi call resume enclave is failed \n");
    goto destroy_enclave;
  }

  return ret.value;

  destroy_enclave:
    destroy_enclave(enclave);
    enclave_idr_remove(eid);
    return -EFAULT;
}

long penglai_enclave_ioctl(struct file* filep, unsigned int cmd, unsigned long args)
{
  char ioctl_data[1024];
  int ioc_size, ret;
  struct sbiret sbiret;

  ioc_size = _IOC_SIZE(cmd);
  if (ioc_size > sizeof(ioctl_data))
  {
    printk("KERNEL MODULE : ioc_data buff is not enough\n");
    return -EFAULT;
  }

  if(copy_from_user(ioctl_data, (void*)args, ioc_size))
    return -EFAULT;

  switch(cmd)
  {
    case PENGLAI_ENCLAVE_IOC_CREATE_ENCLAVE:
     ret = penglai_enclave_create(filep, (unsigned long)ioctl_data);
      break;
    case PENGLAI_ENCLAVE_IOC_RUN_ENCLAVE:
      ret = penglai_enclave_run(filep, (unsigned long)ioctl_data);
      break;
    case PENGLAI_ENCLAVE_IOC_ATTEST_ENCLAVE:
      ret = penglai_enclave_attest(filep, (unsigned long)ioctl_data);
      break;
    case PENGLAI_ENCLAVE_IOC_STOP_ENCLAVE:
      ret = penglai_enclave_stop(filep, (unsigned long)ioctl_data);
      break;
    case PENGLAI_ENCLAVE_IOC_RESUME_ENCLAVE:
      ret = penglai_enclave_resume(filep, (unsigned long)ioctl_data);
      break;
    case PENGLAI_ENCLAVE_IOC_DESTROY_ENCLAVE:
      ret = penglai_enclave_destroy(filep, (unsigned long)ioctl_data);
      break;
    case PENGLAI_ENCLAVE_IOC_DEBUG_PRINT:
      sbiret = SBI_CALL_1(SBI_SM_DEBUG_PRINT, 0);
      ret = sbiret.value;
      break;
     default:
      return -EFAULT;
  }

  if (copy_to_user((void*)args, ioctl_data, ioc_size))
    return -EFAULT;

  return ret;
}
