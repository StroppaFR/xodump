#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>

#define PAGE_MASK       (~(PAGE_SIZE-1))
#define DEFAULT_PROGRAM_OFFSET -0x1000 // There is usually a 0x1000 sized section before .text
#define SIZE_TO_DUMP 0x1000000

static void* libc_text_address = NULL;
static int iterate_phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
    /* we only care about libc */
    if (strstr(info->dlpi_name, "/libc.so") != NULL) {
        /* iterate over ELF segments */
        for (int j = 0; j < info->dlpi_phnum; j++) {
            /* find the first PT_LOAD segment. it should be .text */
            if (info->dlpi_phdr[j].p_type == PT_LOAD) {
                libc_text_address = (void*) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
                return 0;
            }
        }
    }
    return 0;
}

/* try to make the child process dump itself by calling libc write(stdout, .text address, size) */
static void dump_with_libc(pid_t pid, void* program_base, int* status) {
    /* find the addresses of __write and __libc_start_main for the current process */
    void* real___write = dlsym(RTLD_NEXT, "__write");
    void* real___libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
    if (real___write == NULL || real___libc_start_main == NULL) {
        fprintf(stderr, "couldn't resolve the address of __libc_start_main and __write\n");
        exit(EXIT_FAILURE);
    }
    /* find the address of libc .text section for the current process */
    dl_iterate_phdr(iterate_phdr_callback, NULL);
    if (libc_text_address == NULL) {
        fprintf(stderr, "couldn't find the .text address of libc\n");
        exit(EXIT_FAILURE);
    }
    /* calculate the offset from libc base to __write and __libc_start_main */
    if (((unsigned long) real___libc_start_main < (unsigned long) libc_text_address) ||
        ((unsigned long) real___write < (unsigned long) libc_text_address)) {
        fprintf(stderr, "error when resolving libc addresses\n");
        exit(EXIT_FAILURE);
    }
    unsigned long __libc_start_main_offset = (unsigned long) real___libc_start_main - (unsigned long) libc_text_address;
    unsigned long __write_offset = (unsigned long) real___write - (unsigned long) libc_text_address;
    fprintf(stderr, "using 0x%lx as the offset to __libc_start_main in libc\n", __libc_start_main_offset);
    fprintf(stderr, "using 0x%lx as the offset to __write in libc\n", __write_offset);
    /* wait for the child to reach __libc_start_main */
    fprintf(stderr, "waiting for traced process to reach __libc_start_main...\n");
    struct user_regs_struct regs;
    unsigned long child_libc_base = 0;
    while (!WIFEXITED(*status)) {
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        /* this is ugly and won't work on systems with larger ASLR entropy */
        /* or if the program is loaded near the libraries */
        #if __WORDSIZE == 64
        if (((regs.rip >> 40) & 0xff) == 0x7f && (regs.rip % PAGE_SIZE) == ((unsigned long) real___libc_start_main % PAGE_SIZE)) {
            child_libc_base = regs.rip - __libc_start_main_offset;
            break;
        }
        #else
        if (((regs.eip >> 24) & 0xff) == 0xf7 && (regs.eip % PAGE_SIZE) == ((unsigned long) real___libc_start_main % PAGE_SIZE)) {
            child_libc_base = regs.eip - __libc_start_main_offset;
            break;
        }
        #endif
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wait(status);
    }
    if (child_libc_base != 0) {
        fprintf(stderr, "found libc base of traced process: 0x%lx\n", child_libc_base);
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        #if __WORDSIZE == 64
        /* set registers of child for write(1, prog, large) */
        regs.rdi = 1;
        regs.rsi = (unsigned long) program_base;
        regs.rdx = SIZE_TO_DUMP;
        regs.rip = child_libc_base + __write_offset;
        #else
        /* check if we are allowed to POKEDATA the stack */
        if (ptrace(PTRACE_POKEDATA, pid, regs.esp, 0) != 0) {
            perror("PTRACE_POKEDATA call failed");
            exit(EXIT_FAILURE);
        }
        /* set stack of child for write(1, prog, large) */
        ptrace(PTRACE_POKEDATA, pid, regs.esp + 4, 1);
        ptrace(PTRACE_POKEDATA, pid, regs.esp + 8, program_base);
        ptrace(PTRACE_POKEDATA, pid, regs.esp + 12, SIZE_TO_DUMP);
        regs.eip = child_libc_base + __write_offset;
        #endif
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        ptrace(PTRACE_CONT, pid, NULL, NULL);
        wait(status);
    } else {
        fprintf(stderr, "couldn't reach __libc_start_main in traced process");
    }
}

/* find a .text address of the child program */
/* this is done by stepping until we detect a program counter outside of a library (ld.so / libc.so) */
static void* find_program_address(pid_t pid, int* status) {
    struct user_regs_struct regs;
    void* prog_address = NULL;
    fprintf(stderr, "tracing process %d. waiting for it to run outside libraries...\n", pid);
    while (!WIFEXITED(*status)) {
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        /* continue until we reach a non-library address */
        /* this is ugly and won't work on systems with larger ASLR entropy */
        /* or if the program is loaded near the libraries space */
        #if __WORDSIZE == 64
        if (((regs.rip >> 40) & 0xff) != 0x7f) {
            prog_address = (void*) regs.rip;
            break;
        }
        #else
        if (((regs.eip >> 24) & 0xff) != 0xf7) {
            prog_address = (void*) regs.eip;
            break;
        }
        #endif
        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
        wait(status);
    }
    return prog_address;
}

int main(int argc, char* argv[]) {
    char buf[1024];
    char *filename;
    long program_offset = DEFAULT_PROGRAM_OFFSET;
    /* parse args */
    if (argc >= 2) {
        filename = argv[1];
        if (argc >= 3) {
            program_offset = strtol(argv[2], NULL, 0);
        }
    } else {
        fprintf(stderr, "Usage: %s <file> [<offset>]\n"
                "  where <offset> is an offset to add before dumping (should be a multiple of PAGE_SIZE), set to -0x1000 by default\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    /* check that the program file exists */
    struct stat stat_buf;
    if (stat(filename, &stat_buf) != 0) {
        snprintf(buf, sizeof(buf), "couldn't stat file '%s'", filename);
        perror(buf);
        exit(EXIT_FAILURE);
    }
    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        /* prevent setuid */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            perror("couldn't set PR_SET_NO_NEW_PRIVS");
            _exit(EXIT_FAILURE);
        }
        /* disable ASLR if possible */
        if (personality(ADDR_NO_RANDOMIZE) == -1) {
            perror("couldn't set ADDR_NO_RANDOMIZE");
        }
        /* allow parent to trace this process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            perror("ptrace(PTRACE_TRACEME, ...)");
            _exit(EXIT_FAILURE);
        }
        /* execve to start the program to dump */
        execl(filename, filename, NULL);
        snprintf(buf, sizeof(buf), "couldn't exec '%s'", filename);
        perror(buf);
        _exit(EXIT_FAILURE);
    } else {
        /* parent */
        int status;
        if (waitpid(pid, &status, WUNTRACED) != pid) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }
        if (!WIFEXITED(status)) {
            /* SIGTRAP is delivered to child after execve */
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                /* get a .text address of the program to dump */
                void* prog_address = find_program_address(pid, &status);
                if (prog_address == NULL) {
                    fprintf(stderr, "couldn't find a good address of the program to dump\n");
                } else {
                    /* calculate program base, it has to land on a page boundary */
                    prog_address = (void*) ((unsigned long) prog_address & PAGE_MASK) + program_offset;
                    fprintf(stderr, "found probable program address. will start the dump from address %p "
                                    "(use <offset> to tweak this)\n", prog_address);
                    dump_with_libc(pid, prog_address, &status);
                }
            } else {
                fprintf(stderr, "didn't receive SIGTRAP after execve\n");
            }
            /* kill child as we are finished */
            ptrace(PTRACE_KILL, pid, 0, 0);
        }
    }
    return 0;
}
