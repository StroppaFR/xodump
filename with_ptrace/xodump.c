#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MMAP_SIZE       0x10000

#if defined(__x86_64__)
#define SYSCALL_SIZE 2 // syscall instruction 0x0f 0x05
#define PC_REGISTER             rip
#define SYSCALL_RES_REGISTER    rax
#elif defined(__i386__)
#define SYSCALL_SIZE 2 // int 0x80 instruction 0xcd 0x80
#define PC_REGISTER             eip
#define SYSCALL_RES_REGISTER    eax
#endif

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)
#define ASSERT_WAITPID(pid, status, options) ({ \
    if (waitpid(pid, status, options) != pid) { \
        perror("waitpid failed at line " STR(__LINE__)); \
        exit(EXIT_FAILURE); \
    } \
})
#define ASSERT_PTRACE(request, pid, addr, data) ({ \
    if (ptrace(request, pid, addr, data) != 0) { \
        perror("ptrace(" #request ") failed at line " STR(__LINE__)); \
        exit(EXIT_FAILURE); \
    } \
})
#define ASSERT_WRITE(fd, buf, count) ({ \
    ssize_t n; \
    if ((n = write(fd, buf, count)) < 0) { \
        perror("write failed at line " STR(__LINE__)); \
        exit(EXIT_FAILURE); \
    } \
    n; \
})
#define ASSERT_READ(fd, buf, count) ({ \
    ssize_t n; \
    if ((n = read(fd, buf, count)) < 0) { \
        perror("read failed at line " STR(__LINE__)); \
        exit(EXIT_FAILURE); \
    } \
    n; \
})

typedef struct file_cookie_s {
    int fd;
    void* buf;
} file_cookie_t;

static pid_t child_pid;
static int p_to_c_pipe[2], c_to_p_pipe[2];
static file_cookie_t maps_cookie;

/* put the child process in a good state to start executing syscalls on demand */
void prepare_for_syscalls() {
    struct user_regs_struct regs;
    int status;
    /* find a syscall gadget */
    ASSERT_PTRACE(PTRACE_SYSCALL, child_pid, 0, 0);
    ASSERT_WAITPID(child_pid, &status, 0);
    /* get current registers */
    ASSERT_PTRACE(PTRACE_GETREGS, child_pid, NULL, &regs);
    /* complete the syscall */
    ASSERT_PTRACE(PTRACE_SYSCALL, child_pid, 0, 0);
    ASSERT_WAITPID(child_pid, &status, 0);
    /* go back before the syscall instruction */
    regs.PC_REGISTER -= SYSCALL_SIZE;
    ASSERT_PTRACE(PTRACE_SETREGS, child_pid, NULL, &regs);
    /* now the child process next instruction should be syscall */
}

/* make child process execute an arbitrary syscall */
/* prepare_for_syscalls should have been called first */
long child_syscall(int number, ...) {
    va_list argp;
    struct user_regs_struct regs;
    int status;
    unsigned long original_pc;
    /* get current registers */
    ASSERT_PTRACE(PTRACE_GETREGS, child_pid, NULL, &regs);
    original_pc = regs.PC_REGISTER;
    /* set registers to prepare syscall */
    va_start(argp, number);
    #if defined(__x86_64__)
    regs.rax = number;
    regs.rdi = va_arg(argp, unsigned long);
    regs.rsi = va_arg(argp, unsigned long);
    regs.rdx = va_arg(argp, unsigned long);
    regs.r10 = va_arg(argp, unsigned long);
    regs.r8  = va_arg(argp, unsigned long);
    regs.r9  = va_arg(argp, unsigned long);
    #elif defined(__i386__)
    regs.eax = number;
    regs.ebx = va_arg(argp, unsigned long);
    regs.ecx = va_arg(argp, unsigned long);
    regs.edx = va_arg(argp, unsigned long);
    regs.esi = va_arg(argp, unsigned long);
    regs.edi = va_arg(argp, unsigned long);
    regs.ebp = va_arg(argp, unsigned long);
    #endif
    va_end(argp);
    ASSERT_PTRACE(PTRACE_SETREGS, child_pid, NULL, &regs);
    /* run syscall instruction */
    ASSERT_PTRACE(PTRACE_SINGLESTEP, child_pid, 0, 0);
    ASSERT_WAITPID(child_pid, &status, 0);
    ASSERT_PTRACE(PTRACE_GETREGS, child_pid, NULL, &regs);
    /* go back before the syscall instruction */
    if ((unsigned long) regs.PC_REGISTER != original_pc + SYSCALL_SIZE) {
        fprintf(stderr, "syscall size sanity check failed\n");
        exit(EXIT_FAILURE);
    }
    regs.PC_REGISTER = original_pc;
    ASSERT_PTRACE(PTRACE_SETREGS, child_pid, NULL, &regs);
    return regs.SYSCALL_RES_REGISTER;
}

/* copy data from parent memory area to child memory area */
void copy_to_child(void* from, void* to, size_t size) {
    ssize_t n;
    size_t remaining;
    char *from_ptr, *to_ptr;
    /* send data to child through pipe */
    remaining = size;
    from_ptr = (char*) from;
    while (remaining != 0) {
        n = ASSERT_WRITE(p_to_c_pipe[1], from_ptr, remaining);
        remaining -= n;
        from_ptr += n;
    }
    /* make child read from pipe to its memory area */
    remaining = size;
    to_ptr = (char*) to;
    while (remaining != 0) {
        n = child_syscall(SYS_read, p_to_c_pipe[0], to_ptr, remaining);
        remaining -= n;
        to_ptr += n;
    }
}

void copy_from_child(void* from, void* to, size_t size) {
    ssize_t n;
    size_t remaining;
    char *from_ptr, *to_ptr;
    /* make child send data through pipe */
    remaining = size;
    from_ptr = (char*) from;
    while (remaining != 0) {
        n = child_syscall(SYS_write, c_to_p_pipe[1], from_ptr, remaining);
        remaining -= n;
        from_ptr += n;
    }
    /* read from pipe to parent memory area */
    remaining = size;
    to_ptr = (char*) to;
    while (remaining != 0) {
        n = ASSERT_READ(c_to_p_pipe[0], to_ptr, remaining);
        remaining -= n;
        to_ptr += n;
    }
}

static ssize_t child_fread(void *cookie, char *buf, size_t size) {
    file_cookie_t* file_info = cookie;
    ssize_t n;
    if (size > MMAP_SIZE) {
        size = MMAP_SIZE;
    }
    /* make child process read file content to its mmaped area */
    n = child_syscall(SYS_read, file_info->fd, file_info->buf, size);
    if (n > 0) {
        /* copy child memory to parent process */
        copy_from_child(file_info->buf, buf, n);
    }
    return n;
}

ssize_t child_fwrite(void *cookie, const char *buf, size_t size) {
    return -1; /* not implemented */
}

#if defined(__x86_64__)
int child_fseek(void *cookie, off_t *offset, int whence) {
#elif defined(__i386__)
int child_fseek(void *cookie, long long *offset, int whence) {
#endif
    file_cookie_t* file_info = cookie;
    int res = child_syscall(SYS_lseek, file_info->fd, *offset, whence);
    if (res < 0) {
        return -1;
    }
    *offset = res;
    return 0;
}

int child_fclose(void *cookie) {
    file_cookie_t* file_info = cookie;
    return child_syscall(SYS_close, file_info->fd);
}

cookie_io_functions_t child_file_io_functionss = {
    .read = child_fread,
    .write = child_fwrite,
    .seek = child_fseek,
    .close = child_fclose
};

/* try to make child process open /proc/self/maps */
/* this returns a special FILE structure that can be read from */
FILE* open_child_proc_self_maps() {
    void* child_mem;
    int maps_fd;
    FILE* maps_file;
    /* mmap a region in child that we can use as a buffer */
    #if defined(__x86_64__)
    child_mem = (void*) child_syscall(SYS_mmap, 0, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    #elif defined(__i386__)
    child_mem = (void*) child_syscall(SYS_mmap2, 0, MMAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    #endif
    if (child_mem == MAP_FAILED) {
        fprintf(stderr, "mmap syscall in child failed\n");
        return NULL;
    }
    fprintf(stderr, "successfully allocated memory area in child process at %p\n", child_mem);
    /* make child process open /proc/self/maps */
    copy_to_child("/proc/self/maps\x00", child_mem, strlen("/proc/self/maps") + 1);
    maps_fd = child_syscall(SYS_open, child_mem, O_RDONLY);
    if (maps_fd < 0) {
        fprintf(stderr, "failed opening /proc/self/maps from child process\n");
        return NULL;
    }
    /* create the special FILE* structure that can be used from the parent */
    maps_cookie.fd = maps_fd;
    maps_cookie.buf = child_mem;
    maps_file = fopencookie(&maps_cookie, "r", child_file_io_functionss);
    return maps_file;
}

void dump_from_parent(char* filename) {
    char exe_path[4096];
    FILE* maps_file;
    char* lineptr = NULL;
    char page_buf[PAGE_SIZE];
    size_t n;
    unsigned long i, start, end, prev_end, total;
    /* find the path of the executable */
    /* since the executable can be setuid and this is running from the parent */
    /* we might not be able to read /proc/[pid]/exe so use realpath instead */
    if (!realpath(filename, exe_path)) {
        perror("couldn't resolve executable path");
        return;
    }
    fprintf(stderr, "will try to dump %s from parent using ptrace\n", exe_path);
    /* get a handle to /proc/self/maps opened by the child process */
    prepare_for_syscalls();
    maps_file = open_child_proc_self_maps();
    if (!maps_file) {
        fprintf(stderr, "couldn't get a handle to child /proc/self/maps\n");
        return;
    }
    /* iterate over maps to find the one associated with the executable */
    prev_end = 0;
    total = 0;
    while (getline(&lineptr, &n, maps_file) >= 0) {
        if (strstr(lineptr, exe_path)) {
            if (sscanf(lineptr, "%lx-%lx", &start, &end) == 2) {
                if (prev_end != 0 && start != prev_end) {
                    fprintf(stderr, "warning: unmapped region from 0x%lx to 0x%lx\n", prev_end, start);
                }
                fprintf(stderr, "dumping memory mapping from 0x%lx to 0x%lx\n", start, end);
                /* read all pages from the mapping */
                for (i = 0; i < (end - start) / PAGE_SIZE; i++) {
                    copy_from_child((void*) start, page_buf, PAGE_SIZE);
                    write(1, page_buf, PAGE_SIZE);
                }
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
    } else {
        fprintf(stderr, "couldn't find any memory map to dump for mapped executable %s\n", exe_path);
    }
}

int main(int argc, char* argv[]) {
    char buf[1024];
    char *filename;
    struct stat stat_buf;
    int status;
    /* parse args */
    if (argc >= 2) {
        filename = argv[1];
    } else {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    /* check that the executable file exists */
    if (stat(filename, &stat_buf) != 0) {
        snprintf(buf, sizeof(buf), "couldn't stat file '%s'", filename);
        perror(buf);
        exit(EXIT_FAILURE);
    }
    pipe(p_to_c_pipe);
    pipe(c_to_p_pipe);
    child_pid = fork();
    if (child_pid == 0) {
        /* child */
        close(p_to_c_pipe[1]);
        close(c_to_p_pipe[0]);
        /* prevent setuid */
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            perror("couldn't set PR_SET_NO_NEW_PRIVS");
            _exit(EXIT_FAILURE);
        }
        /* disable ASLR if possible (not important) */
        if (personality(ADDR_NO_RANDOMIZE) == -1) {
            perror("warning: couldn't set ADDR_NO_RANDOMIZE");
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
        close(p_to_c_pipe[0]);
        close(c_to_p_pipe[1]);
        ASSERT_WAITPID(child_pid, &status, WUNTRACED);
        if (!WIFEXITED(status)) {
            /* SIGTRAP is delivered to child after execve */
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                dump_from_parent(filename);
            } else {
                fprintf(stderr, "didn't receive SIGTRAP after execve\n");
            }
            /* kill child as we are finished */
            ASSERT_PTRACE(PTRACE_KILL, child_pid, 0, 0);
        }
    }
    return 0;
}
