#include <sm/attest.h>
#include <sm/gm/SM3.h>
#include <sm/gm/SM2_sv.h>
#include <sbi/riscv_encoding.h>
#include <sbi/sbi_string.h>
#include <sm/print.h>
#include <sm/enclave_args.h>

extern struct tee_sbi_param_t tee_sbi_param;

unsigned int key_num = 1;
unsigned char authorized_keys[64] = {
    0xE9, 0x28, 0x20, 0xDD,  0xD9, 0x6A, 0xB1, 0xEF,  0x74, 0xE4, 0x1C, 0x5E,  0x51, 0xFB, 0x55, 0xBA,  
    0xA5, 0x40, 0x0F, 0x7A,  0x93, 0xC1, 0x40, 0xB8,  0xE3, 0x75, 0x10, 0x87,  0x5C, 0x0E, 0x64, 0xE7,  
    0x20, 0xC7, 0xBA, 0xDF,  0x49, 0x2A, 0x3B, 0xC2,  0xC6, 0x6A, 0xD2, 0x7A,  0xCE, 0x0C, 0xD1, 0xD7,  
    0x9F, 0xF3, 0x71, 0xE0,  0x22, 0xB5, 0xA4, 0x0F,  0x52, 0xA8, 0xC7, 0xAB,  0x68, 0xA5, 0x27, 0x08
};

void printHex(unsigned char *c, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        printm_err("0x%02X, ", c[i]);
        if ((i%4) == 3)
            printm_err(" ");
        if ((i%16) == 15)
            printm_err("\n");
    }
    if ((i%16) != 0)
    printm_err("\n");
}

// initailize Penglai Monitor@%s's private key and public key.
void attest_init()
{
    int i;
    struct prikey_t *sm_prikey = (struct prikey_t *)SM_PRI_KEY;
    struct pubkey_t *sm_pubkey = (struct pubkey_t *)SM_PUB_KEY;
    
    i = SM2_Init();
    if(i)
        printm("SM2_Init failed with ret value: %d\n", i);

    i = SM2_KeyGeneration(sm_prikey->dA, sm_pubkey->xA, sm_pubkey->yA);
    if(i)
        printm("SM2_KeyGeneration failed with ret value: %d\n", i);
}

static int hash_enclave_mem(SM3_STATE *hash_ctx, pte_t* ptes, int level,
        uintptr_t va, int hash_va)
{
    uintptr_t pte_per_page = RISCV_PGSIZE/sizeof(pte_t);
    pte_t *pte;
    uintptr_t i = 0;
    int hash_curr_va = hash_va;

    //should never happen
    if(level <= 0)
        return 1;

    for(pte = ptes, i = 0; i < pte_per_page; pte += 1, i += 1)
    {
        if(!(*pte & PTE_V))
        {
            hash_curr_va = 1;
            continue;
        }

        uintptr_t curr_va = 0;
        if(level == ((VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS))
            curr_va = (uintptr_t)(-1UL << VA_BITS) +
                (i << (VA_BITS - RISCV_PGLEVEL_BITS));
        else
            curr_va = va +
                (i << ((level-1) * RISCV_PGLEVEL_BITS + RISCV_PGSHIFT));
        uintptr_t pa = (*pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

        //found leaf pte
        if((*pte & PTE_R) || (*pte & PTE_X))
        {
            if(hash_curr_va)
            {
                SM3_process(hash_ctx, (unsigned char*)&curr_va,
                    sizeof(uintptr_t));
                //update hash with  page attribution
                SM3_process(hash_ctx, (unsigned char*)pte+7, 1);
                hash_curr_va = 0;
            }

            //4K page
            if(level == 1)
            {
                SM3_process(hash_ctx, (void*)pa, 1 << RISCV_PGSHIFT);
            }
            //2M page
            else if(level == 2)
            {
                SM3_process(hash_ctx, (void*)pa,
                    1 << (RISCV_PGSHIFT + RISCV_PGLEVEL_BITS));
            }
        }
        else
        {
            hash_curr_va = hash_enclave_mem(hash_ctx, (pte_t*)pa, level - 1,
                curr_va, hash_curr_va);
        }
    }

    return hash_curr_va;
}

void hash_enclave(struct enclave_t *enclave, void* hash, uintptr_t nonce_arg)
{
    SM3_STATE hash_ctx;
    uintptr_t nonce = nonce_arg;

    SM3_init(&hash_ctx);
    
    SM3_process(&hash_ctx, (unsigned char*)(&(enclave->entry_point)),
        sizeof(unsigned long));
    hash_enclave_mem(
        &hash_ctx,
        (pte_t*)(enclave->thread_context.encl_ptbr << RISCV_PGSHIFT),
        (VA_BITS - RISCV_PGSHIFT) / RISCV_PGLEVEL_BITS, 0, 1
    );
    SM3_process(&hash_ctx, (unsigned char*)(&nonce), sizeof(uintptr_t));
    SM3_done(&hash_ctx, hash);
}

void update_enclave_hash(char *output, void* hash, uintptr_t nonce_arg)
{
    SM3_STATE hash_ctx;
    uintptr_t nonce = nonce_arg;

    SM3_init(&hash_ctx);
    SM3_process(&hash_ctx, (unsigned char*)(hash), HASH_SIZE);
    SM3_process(&hash_ctx, (unsigned char*)(&nonce), sizeof(uintptr_t));
    SM3_done(&hash_ctx, hash);

    sbi_memcpy(output, hash, HASH_SIZE);
}

void sign_enclave(void* signature_arg, unsigned char *message, int len)
{
    struct signature_t *signature = (struct signature_t*)signature_arg;
    struct prikey_t *sm_prikey = (struct prikey_t *)SM_PRI_KEY;
    
    SM2_Sign(message, len, sm_prikey->dA, (unsigned char *)(signature->r),
        (unsigned char *)(signature->s));
}

int verify_enclave(void* signature_arg, unsigned char *message, int len)
{
    int ret = 0;
    struct signature_t *signature = (struct signature_t*)signature_arg;
    struct pubkey_t *sm_pubkey = (struct pubkey_t *)SM_PUB_KEY;
    ret = SM2_Verify(message, len, sm_pubkey->xA, sm_pubkey->yA,
        (unsigned char *)(signature->r), (unsigned char *)(signature->s));
    return ret;
}

void hash_sec_linux()
{
    SM3_STATE hash_ctx;
    unsigned char *hash = (unsigned char*)TEE_HASH;
    unsigned long curr_addr, left_size, counter;
    int hash_granularity = 1 << 20;

    SM3_init(&hash_ctx);

    //hash secure linux image
    sbi_printf("[%s] hash sec-linux image load address: %lx\n", __func__, tee_sbi_param.bin_loadaddr);
    SM3_process(&hash_ctx, (unsigned char*)&tee_sbi_param.bin_loadaddr, sizeof(unsigned long));

    sbi_printf("[%s] Start to hash sec-linux image:\n", __func__);
    curr_addr = tee_sbi_param.bin_loadaddr;
    left_size = tee_sbi_param.bin_size;
    counter = 0;
    while(left_size > hash_granularity){
        SM3_process(&hash_ctx, (unsigned char*)curr_addr, hash_granularity);
        curr_addr += hash_granularity;
        left_size -= hash_granularity;
        counter++;
        sbi_printf("[%s] hashed %ld MB, left %ld MB\n", __func__, counter, left_size >> 20);
    }
    SM3_process(&hash_ctx, (unsigned char*)curr_addr, (int)left_size);
    sbi_printf("[%s] Finish sec-linux image hash, total %ld B\n", __func__, tee_sbi_param.bin_size);

    //hash secure linux dtb
    sbi_printf("[%s] hash sec-linux dtb load address: %lx\n", __func__, tee_sbi_param.dtb_loadaddr);
    SM3_process(&hash_ctx, (unsigned char*)&tee_sbi_param.dtb_loadaddr, sizeof(unsigned long));

    sbi_printf("[%s] Start to hash sec-linux dtb:\n", __func__);
    curr_addr = tee_sbi_param.dtb_loadaddr;
    left_size = tee_sbi_param.dtb_size;
    counter = 0;
    while(left_size > hash_granularity){
        SM3_process(&hash_ctx, (unsigned char*)curr_addr, hash_granularity);
        curr_addr += hash_granularity;
        left_size -= hash_granularity;
        counter++;
        sbi_printf("[%s] hashed %ld MB, left %ld MB\n", __func__, counter, left_size >> 20);
    }
    SM3_process(&hash_ctx, (unsigned char*)curr_addr, (int)left_size);
    sbi_printf("[%s] Finish sec-linux dtb hash, total %ld B\n", __func__, tee_sbi_param.dtb_size);

    SM3_done(&hash_ctx, hash);
}

void sign_sec_linux(void* signature_arg, unsigned char *message, int len)
{
    struct signature_t *signature = (struct signature_t*)signature_arg;
    struct prikey_t *sm_prikey = (struct prikey_t *)SM_PRI_KEY;
    
    SM2_Sign(message, len, sm_prikey->dA, (unsigned char *)(signature->r),
        (unsigned char *)(signature->s));
}

int auth_sec_linux()
{
    sbi_printf("[Penglai Monitor@%s] hash in TEE css:\n", __func__);
	printHex(tee_sbi_param.enclave_css.enclave_hash, HASH_SIZE);

    unsigned char *hash = (unsigned char*)TEE_HASH;
    if(sbi_memcmp(hash, tee_sbi_param.enclave_css.enclave_hash, HASH_SIZE) == 0){
        sbi_printf("[Penglai Monitor@%s] TEE's hash is consistent.\n", __func__);
    } else {
        sbi_printf("[Penglai Monitor@%s] TEE's hash is wrong.\n", __func__);
        goto err_ret;
    }

    struct signature_t *signature = (struct signature_t*)tee_sbi_param.enclave_css.signature;
    struct pubkey_t *user_pubkey = (struct pubkey_t *)tee_sbi_param.enclave_css.user_pub_key;
	if(SM2_Verify(tee_sbi_param.enclave_css.enclave_hash, HASH_SIZE,
              user_pubkey->xA, user_pubkey->yA,
              (unsigned char *)(signature->r),
              (unsigned char *)(signature->s)) == 0){
		sbi_printf("[Penglai Monitor@%s] Verification of the signature in enclave_css succeeded.\n", __func__);
	} else {
        sbi_printf("[Penglai Monitor@%s] Verification of the signature in enclave_css failed.\n", __func__);
        goto err_ret;
    }

    int auth = 0;
    for(int i = 0; i < key_num; ++i){
        struct pubkey_t *auth_pubkey = (struct pubkey_t *)authorized_keys + i;
        if(sbi_memcmp(user_pubkey, auth_pubkey, PUBLIC_KEY_SIZE) == 0){
            auth = 1;
            break;
        }
    }
    if(auth){
        sbi_printf("[Penglai Monitor@%s] user's public key is authorized.\n", __func__);
    } else {
        sbi_printf("[Penglai Monitor@%s] user's public key is not authorized.\n", __func__);
        goto err_ret;
    }

    return 0;

err_ret:
    sbi_printf("[Penglai Monitor@%s] Trusted launch failed.", __func__);
    return -1;
}
