#include "penglai-enclave.h"
#include <stdlib.h>

void load_and_run(struct elf_args *enclaveFile)
{
    struct PLenclave *enclave = malloc(sizeof(struct PLenclave));
    PLenclave_init(enclave);

    if (PLenclave_load_and_run(enclave, enclaveFile) < 0)
    {
        printf("host: failed to create enclave\n");
    }

    PLenclave_finalize(enclave);
    free(enclave);
}

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        printf("Please input the linux binary file name\n");
    }
    char *eappfile = argv[1];

    struct elf_args *enclaveFile = malloc(sizeof(struct elf_args));
    elf_args_init(enclaveFile, eappfile);

    if (!elf_valid(enclaveFile))
    {
        printf("error when initializing enclaveFile\n");
        goto out;
    }

    load_and_run(enclaveFile);

out:
    elf_args_destroy(enclaveFile);
    free(enclaveFile);

    return 0;
}
