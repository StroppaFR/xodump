#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <unistd.h>

#define PAGE_MASK       (~(PAGE_SIZE-1))
#define EXIT_DUMP_OK    42

static void dump_from_maps() {
    ssize_t pathlen;
    char exe_path[4096];
    FILE* maps_file;
    char* lineptr = NULL;
    size_t n;
    unsigned long start, end, prev_end, total;
    /* find the path of the executable */
    pathlen = readlink("/proc/self/exe", exe_path, 4096);
    if (pathlen < 0) {
        perror("couldn't readlink /proc/self/exe");
        return;
    }
    exe_path[pathlen] = 0;
    fprintf(stderr, "will try to dump mapped executable %s\n", exe_path);
    /* open /proc/self/maps to get memory mappings */
    maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        perror("couldn't open /proc/self/maps");
        return;
    }
    /* iterate over maps to find the one associated with the executable */
    prev_end = 0;
    total = 0;
    while (getline(&lineptr, &n, maps_file) >= 0) {
        if (strstr(lineptr, exe_path)) {
            if (sscanf(lineptr, "%lx-%lx", &start, &end) == 2) {
                if (prev_end != 0 && start != prev_end) {
                    /* should probably not happen */
                    fprintf(stderr, "warning: unmapped region from 0x%lx to 0x%lx\n", prev_end, start);
                }
                fprintf(stderr, "dumping memory mapping from 0x%lx to 0x%lx\n", start, end);
                write(1, (void*) start, end - start);
                total += end - start;
                prev_end = end;
            }
        }
        free(lineptr);
        lineptr = NULL;
    }
    fclose(maps_file);
    if (total > 0) {
        fprintf(stderr, "successfully dumped 0x%lx bytes from mapped executable %s\n", total, exe_path);
        exit(EXIT_DUMP_OK);
    } else {
        fprintf(stderr, "couldn't find any memory map to dump for mapped executable %s\n", exe_path);
    }
}

static void dump_from_main(void* main) {
    unsigned long prog_addr;
    int val;
    unsigned char vec;
    fprintf(stderr, "will try to dump using known main address at %p\n", main);
    /* find the ELF header which should be at the start of a page before main address */
    prog_addr = (unsigned long) main;
    prog_addr = prog_addr & PAGE_MASK;
    while (1) {
        val = *(int*) prog_addr;
        if (val == 0x7f454c46 || val == 0x464c457f) {
            break;
        }
        prog_addr -= PAGE_SIZE;
    }
    fprintf(stderr, "found start of ELF file mapped at 0x%lx\n", prog_addr);
    /* dump memory until we reach a non-mapped page */
    /* this assumes all sections are mapped contiguously */
    while (mincore((void*)prog_addr, PAGE_SIZE, &vec) == 0) {
        write(1, (void*)prog_addr, PAGE_SIZE);
        prog_addr += PAGE_SIZE;
    }
    fprintf(stderr, "stopped dumping at 0x%lx\n", prog_addr);
    exit(EXIT_DUMP_OK);
}

/* replace the implementation of __libc_start_main by a function that dumps the executable mapped in virtual memory */
int __libc_start_main(int (*main)(int, char **, char **),
        int argc, char **argv,
        int (*init)(int, char **, char **), void (*fini)(void), void (*rtld_fini)(void),
        void *stack_end) {
    /* try to dump cleanly by reading /proc/self/maps */
    dump_from_maps();
    fprintf(stderr, "dumping using /proc/self/maps failed\n");
    /* if that fails, try to dump using the known main address */
    dump_from_main((void*) main);
    /* this code is reached only if both method fail */
    exit(EXIT_FAILURE);
}

