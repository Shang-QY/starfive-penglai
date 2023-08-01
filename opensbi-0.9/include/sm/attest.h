#ifndef _ATTEST_H
#define _ATTEST_H

#include "sm/enclave.h"
#include "sm/domain.h"

void attest_init();

void hash_enclave(struct enclave_t* enclave, void* hash, uintptr_t nonce);

void update_enclave_hash(char *output, void* hash, uintptr_t nonce_arg);

void hash_domain(struct domain_t* dom);

void sign_enclave(void* signature, unsigned char *message, int len);

int verify_enclave(void* signature, unsigned char *message, int len);

void hash_sec_linux();

void sign_sec_linux(void* signature, unsigned char *message, int len);

int auth_sec_linux();

#endif /* _ATTEST_H */
