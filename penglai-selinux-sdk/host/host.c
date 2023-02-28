#include "penglai-enclave.h"
#include <stdlib.h>

void load_and_run(struct elf_args *enclaveFile, unsigned long bin_loadaddr, struct elf_args *dtbFile, unsigned long dtb_loadaddr)
{
    struct PLenclave *enclave = malloc(sizeof(struct PLenclave));
    PLenclave_init(enclave);

    if (PLenclave_load_and_run(enclave, enclaveFile, bin_loadaddr, dtbFile, dtb_loadaddr) < 0)
    {
        printf("host: failed to create enclave\n");
    }

    PLenclave_finalize(enclave);
    free(enclave);
}

int main(int argc, char **argv)
{
    if (argc <= 4)
    {
        printf("Please input the linux binary file name and linux dtb file name\n");
    }
    char *eappfile = argv[1];
    unsigned long bin_loadaddr = strtol(argv[2], NULL, 16);

    struct elf_args *enclaveFile = malloc(sizeof(struct elf_args));
    elf_args_init(enclaveFile, eappfile);

    if (!elf_valid(enclaveFile))
    {
        printf("error when initializing enclaveFile\n");
        goto out;
    }

    char *dtbfile = argv[3];
    unsigned long dtb_loadaddr = strtol(argv[4], NULL, 16);

    struct elf_args *dtbFile = malloc(sizeof(struct elf_args));
    elf_args_init(dtbFile, dtbfile);

    if (!elf_valid(dtbFile))
    {
        printf("error when initializing enclaveFile\n");
        goto out;
    }

    load_and_run(enclaveFile, bin_loadaddr, dtbFile, dtb_loadaddr);

out:
    elf_args_destroy(enclaveFile);
    free(enclaveFile);

    return 0;
}
