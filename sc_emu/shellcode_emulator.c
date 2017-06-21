/* 
 * Simple shellcode emulator for assembly tech talk 
 *
 * Heavily modified from Unicorn Emulator sample code
 */
/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh & Dang Hoang Vu, 2015 */

/* Sample code to trace code with Linux code with syscall */

#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>


// memory address where emulation starts
#define ADDRESS 0x1000000

#define MIN(a, b) (a < b? a : b)

typedef struct _x86_register_state
{
    int32_t eax;
    int32_t ebx;
    int32_t ecx;
    int32_t edx;
    int32_t esi;
    int32_t edi;
    int32_t ebp;
    int32_t esp;
    int32_t eip;
} x86_register_state;

typedef struct _syscall_args
{
    int32_t syscall_no;
    int32_t arg0;
    int32_t arg1;
    int32_t arg2;
    int32_t arg3;
    int32_t arg4;
    int32_t arg5;
} syscall_args;

void get_register_state(uc_engine *uc, x86_register_state *regs)
{
    if (!regs || !uc) {
        return;
    }

    uc_reg_read(uc, UC_X86_REG_EAX, &regs->eax);    
    uc_reg_read(uc, UC_X86_REG_EBX, &regs->ebx);    
    uc_reg_read(uc, UC_X86_REG_ECX, &regs->ecx);    
    uc_reg_read(uc, UC_X86_REG_EDX, &regs->edx);    
    uc_reg_read(uc, UC_X86_REG_ESI, &regs->esi);    
    uc_reg_read(uc, UC_X86_REG_EDI, &regs->edi);    
    uc_reg_read(uc, UC_X86_REG_EBP, &regs->ebp);    
    uc_reg_read(uc, UC_X86_REG_ESP, &regs->esp);    
    uc_reg_read(uc, UC_X86_REG_EIP, &regs->eip);    

    return;
}

void set_register_state(uc_engine *uc, x86_register_state *regs)
{
    if (!regs || !uc) {
        return;
    }
    uc_reg_write(uc, UC_X86_REG_EAX, &regs->eax);    
    uc_reg_write(uc, UC_X86_REG_EBX, &regs->ebx);    
    uc_reg_write(uc, UC_X86_REG_ECX, &regs->ecx);    
    uc_reg_write(uc, UC_X86_REG_EDX, &regs->edx);    
    uc_reg_write(uc, UC_X86_REG_ESI, &regs->esi);    
    uc_reg_write(uc, UC_X86_REG_EDI, &regs->edi);    
    uc_reg_write(uc, UC_X86_REG_EBP, &regs->ebp);    
    uc_reg_write(uc, UC_X86_REG_ESP, &regs->esp);    
    uc_reg_write(uc, UC_X86_REG_EIP, &regs->eip);    

}

void emulate_exit(uc_engine *uc, x86_register_state *regs)
{
    syscall_args *args = (syscall_args *)regs;
    printf("0x%x: exit(%d)\n", regs->eip, args->arg0);
    uc_emu_stop(uc);
}

void get_string(uc_engine *uc, uint64_t address, char *dst, size_t dst_size)
{
    char ch = 0;
    uint64_t cur_addr = address;
    size_t i = 0;

    while (1) {
        if (i == (dst_size - 1)) {
            dst[i] = '\0';
            break;
        }
        
        uc_err err = uc_mem_read(uc, cur_addr, &ch, 1);
        if (err != UC_ERR_OK) {
            printf("Couldn't read string at 0x%llx\n", cur_addr);
            exit(err);
        }

        if (ch == '\0') {
            dst[i] = '\0';
            break;
        }

        dst[i] = ch;
        i += 1;
        cur_addr += 1;
    }
}

static int next_fd = 3;
void emulate_open(uc_engine *uc, x86_register_state *regs)
{
    char file[PATH_MAX + 1] = {0};
    syscall_args *args = (syscall_args *)regs;
    get_string(uc, args->arg0, file, sizeof(file));
    printf("0x%x: open(\"%s\", 0%o, 0%o)\n", regs->eip, file, args->arg1, args->arg2);
    regs->eax = next_fd++;
    set_register_state(uc, regs);
}

void emulate_close(uc_engine *uc, x86_register_state *regs)
{
    syscall_args *args = (syscall_args *)regs;
    printf("0x%x: close(%d)\n", regs->eip, args->arg0);
    regs->eax = 0;
    set_register_state(uc, regs);
}

void emulate_generic(uc_engine *uc, x86_register_state *regs)
{
    syscall_args *args = (syscall_args *)regs;
    printf("0x%x: syscall(%d, %d, %d, %d, %d, %d, %d)\n", regs->eip, args->syscall_no, args->arg0, args->arg1, args->arg2, args->arg3, args->arg4, args->arg5);
    regs->eax = 0;
    set_register_state(uc, regs);
}

void print_data(char *data, size_t data_size, size_t max_size)
{
    size_t to_print = MIN(data_size, max_size);
    for (size_t i = 0; i < to_print; ++i) {
        if (isprint(data[i])) {
            printf("%c", data[i]);
        } else {
            printf("\\x%x", data[i]);
        }
    }

    if (data_size > max_size) {
        printf("...");
    }
}

void emulate_write(uc_engine *uc, x86_register_state *regs)
{
    syscall_args *args = (syscall_args *)regs;
    int32_t write_sz = args->arg2;
    char *data = calloc(1, write_sz);
    uc_err err = uc_mem_read(uc, args->arg1, data, write_sz);
    if (err) {
        printf("Could not read memory from 0x%x\n", args->arg1);
        exit(err);
    }
    printf("0x%x: write(%d, \"", regs->eip, args->arg0);
    print_data(data, write_sz, 20);
    printf("\", %d)\n", args->arg2);
    free(data);
    regs->eax = write_sz;
    set_register_state(uc, regs);
}

void emulate_read(uc_engine *uc, x86_register_state *regs)
{
    syscall_args *args = (syscall_args *)regs;
    printf("0x%x: read(%d, 0x%x, %d)\n", regs->eip, args->arg0, args->arg1, args->arg2);
    regs->eax = args->arg2;
    set_register_state(uc, regs);
}

void emulate_chmod(uc_engine *uc, x86_register_state *regs)
{
    char file[PATH_MAX + 1] = {0};
    syscall_args *args = (syscall_args *)regs;
    get_string(uc, args->arg0, file, sizeof(file));
    printf("0x%x: chmod(\"%s\", 0%o)\n", regs->eip, file, args->arg1);
    regs->eax = 0;
    set_register_state(uc, regs);
}


void emulate_execve(uc_engine *uc, x86_register_state *regs)
{
    syscall_args *args = (syscall_args *)regs;
    char file[PATH_MAX + 1] = {0};
    get_string(uc, args->arg0, file, sizeof(file));
    printf("0x%x: execve(\"%s\", {", regs->eip, file);
    int32_t arg_ptr = 0;
    int32_t arg_addr = args->arg1;
    while (1) {
        uc_mem_read(uc, arg_addr, &arg_ptr, sizeof(arg_ptr));
        if (!arg_ptr) {
            printf("(NULL)");
            break;
        }
        char arg[1025] = {0};
        get_string(uc, arg_ptr, arg, sizeof(arg) - 1);
        printf("\"%s\", ", arg);
        arg_addr += 4;
    }
    printf("}, ");

    int32_t env_ptr = 0;
    int32_t env_addr = args->arg2;
    if (!env_addr) {
        printf("{");
        while (1) {
            uc_mem_read(uc, env_addr, &env_ptr, sizeof(env_ptr));
            if (!env_ptr) {
                printf("(NULL)");
                break;
            }
            char env[1025] = {0};
            get_string(uc, env_ptr, env, sizeof(env) - 1);
            printf("\"%s\", ", env);
            env_addr += 4;
        }
        printf("}");
    } else {
        printf("(NULL)");
    }
    printf(")\n");
    return;
}

// callback for handling interrupt
// ref: http://syscalls.kernelgrok.com/
static void hook_intr(uc_engine *uc, uint32_t intno, void *user_data)
{
    x86_register_state regs;
    (void)user_data;

    // only handle Linux syscall
    if (intno != 0x80)
        return;

    memset(&regs, 0, sizeof(regs));
    get_register_state(uc, &regs);


    switch(regs.eax) {
        case 1: 
            emulate_exit(uc, &regs); 
            break;
        case 4: 
            emulate_write(uc, &regs);
            break;
        case 5:
            emulate_open(uc, &regs);
            break;
        case 6:
            emulate_close(uc, &regs);
            break;
        case 11:
            emulate_execve(uc, &regs);
            break;
        case 15:
            emulate_chmod(uc, &regs);
            break;
        default:
            emulate_generic(uc, &regs);
            break;
    }
}

static void shellcode_emulate(char *shellcode, size_t sc_size)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace2;

    int r_esp = ADDRESS + 0x200000;  // ESP register

    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u\n", err);
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, shellcode, sc_size)) {
        printf("Failed to write emulation code to memory, quit!\n");
        return;
    }

    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ESP, &r_esp);


    // handle interrupt ourself
    uc_hook_add(uc, &trace2, UC_HOOK_INTR, (void *)hook_intr, NULL, 1, 0);

    // emulate machine code in infinite time
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sc_size, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
                err, uc_strerror(err));
    }

    printf("\n>>> Emulation done.\n");

    uc_close(uc);
}

void slurp(const char *file, char **sc, size_t *size)
{
    struct stat sb;
    char *tmp_buf = NULL;
    FILE *fp = NULL;

    if (stat(file, &sb)) {
        printf("Couldn't stat %s: %s\n", file, strerror(errno));
        exit(-1);
    }

    fp = fopen(file, "r");
    if (!fp) {
        printf("Couldn't read %s: %s\n", file, strerror(errno));
        exit(-1);
    }

    tmp_buf = calloc(1, sb.st_size);
    if (!tmp_buf) {
        printf("Couldn't malloc memory: %s\n", strerror(errno));
        exit(-1);
    }

    if (fread(tmp_buf, 1, sb.st_size, fp) != (unsigned long)sb.st_size) {
        printf("Couldn't read %s: %s\n", file, strerror(errno));
        exit(-1);
    }

    *size = (size_t)sb.st_size;
    *sc = tmp_buf;
}

void dump_shellcode(char *sc, size_t sc_size)
{
    csh cs_handle;
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle);
    if (err) {
        printf("Could not initialize captstone\n");
        exit(err);
    }

    cs_insn *insn = NULL;
    size_t count = cs_disasm(cs_handle, (const uint8_t *)sc, sc_size, ADDRESS, 0, &insn);
    if (count) {
        for (size_t i = 0; i < count; ++i) {
            printf("0x%llx:\t%s\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
        }
    }
}

int main(int argc, char **argv)
{
    char *sc = NULL;
    size_t sc_size = 0;
    if (argc < 2) {
        printf("usage: %s [shellcode.bin]\n", argv[0]);
        exit(-1);
    }

    slurp(argv[1], &sc, &sc_size);
    printf("Emulating shellcode from %s... \n", argv[1]);
    dump_shellcode(sc, sc_size);
    printf("\nSyscall Trace\n");
    shellcode_emulate(sc, sc_size);

    return 0;
}
