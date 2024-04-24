#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    char buf[1024];
    char* filename;
    /* parse args */
    if (argc >= 2) {
        filename = argv[1];
    } else {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    /* check that the executable file exists */
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
        char* child_argv[] = { filename, NULL };
        char* child_envp[] = { "LD_PRELOAD=./xodump_preload_lib.so", NULL };
        /* execve to start the executable to dump */
        execve(child_argv[0], child_argv, child_envp);
        snprintf(buf, sizeof(buf), "couldn't execve '%s'", filename);
        perror(buf);
        _exit(EXIT_FAILURE);
    } else {
        /* parent */
        int status;
        if (waitpid(pid, &status, 0) != pid) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }
        if (WEXITSTATUS(status) == 42) {
            fprintf(stderr, "child process exited correctly after dump\n");
        } else {
            fprintf(stderr, "something went wrong while trying to dump child process\n");
        }
    }
    return 0;
}
