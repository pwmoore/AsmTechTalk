#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <readline/readline.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

typedef long (*func_t)(void);
int main(void)
{

    ks_engine *ks;
    csh cs_handle;
    
    // Initialize capstone
    cs_err cserr = cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle);

    if (cserr != CS_ERR_OK) {
        printf("Could not initialize capstone\n");
        return cserr;
    }

    // Initialize keystone
    ks_err kserr = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    if (kserr != KS_ERR_OK) {
        printf("Could not initialize keystone\n");
        return kserr;
    }
    char *code = NULL;
    size_t codelen = 0;

    printf("Enter assembly line by line, ending with a ';' on each line. Enter a blank line to execute\n");
    while (1) {
        // Read a line of input
        char *line = readline("> ");

        // If the line is empty, break
        size_t len = strlen(line);
        if (!len || line[0] == '\0' || line[0] == ';') {
            break;
        }

        // Make room for the code
        if (!code) {
            code = calloc(1, len + 1);
        } else { 
            code = realloc(code, codelen + len + 1);
        }

        // Copy the code to the end of the line
        memcpy(&code[codelen], line, len);
        codelen += len;
        code[codelen] = '\0';
        printf("%s\n", code);
    } 

    if (codelen == 0) {
        printf("You must enter some code!\n");
        return -1;
    }

    // Now use keystone to assemble the code
    unsigned char *assembled_code = NULL;
    size_t count = 0;
    size_t code_size = 0;
    if (ks_asm(ks, code, 0, &assembled_code, &code_size, &count)) {
        printf("Could not assemble code\n");
        return -1;
    }

    // Map a page to hold the executable code
    void *executable_code = mmap(NULL, getpagesize(), PROT_WRITE|PROT_READ, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (executable_code == MAP_FAILED) {
        printf("Could not mmap: %s\n", strerror(errno));
        return -1;
    }

    // Copy code into the executable region
    memcpy(executable_code, assembled_code, code_size);
    cs_insn *insn = NULL;

    // Disassemble the code to make sure it's what we expect
    count = cs_disasm(cs_handle, (uint8_t *)executable_code, code_size, (uintptr_t)executable_code, 0, &insn);

    if (count) {
        for (size_t i = 0; i < count; ++i) {
            printf("0x%llx:\t%s\t%s\n", insn[i].address,insn[i].mnemonic, insn[i].op_str);
        }
    }

    // Set the code as executable
    if (mprotect(executable_code, getpagesize(), PROT_READ | PROT_EXEC)) {
        printf("Could not set code to R-X: %s\n", strerror(errno));
        return -1;
    }

    // Do it!
    func_t go = (func_t)executable_code;
    long ret = go();
    printf("JIT returned %ld\n", ret);

}
