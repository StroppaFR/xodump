#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <unistd.h>

#define PAGE_MASK       (~(PAGE_SIZE-1))

/* replace the implementation of __libc_start_main by a function that dumps the executable */
int __libc_start_main(int (*main)(int, char **, char **),
        int argc, char **argv,
        int (*init)(int, char **, char **), void (*fini)(void), void (*rtld_fini)(void),
        void *stack_end) {
    /* find the ELF header which should be at the start of a page before main address */
    unsigned long prog_addr = (unsigned long) main;
    prog_addr = prog_addr & PAGE_MASK;
    while (1) {
        int val = *(int*)prog_addr;
        if (val == 0x7f454c46 || val == 0x464c457f) {
            break;
        }
        prog_addr -= PAGE_SIZE;
    }
    fprintf(stderr, "found start of ELF file mapped at 0x%lx\n", prog_addr);
    /* dump memory until we reach a non-mapped page */
    /* this assumes all sections are mapped contiguously */
    unsigned char vec;
    while (mincore((void*)prog_addr, PAGE_SIZE, &vec) == 0) {
        write(1, (void*)prog_addr, PAGE_SIZE);
        prog_addr += PAGE_SIZE;
    }
    fprintf(stderr, "stopped dumping at 0x%lx\n", prog_addr);
    exit(42);
}
