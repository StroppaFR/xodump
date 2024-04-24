# xodump

Make an executable ELF program with no read permissions dump itself.

`xodump` will try to make a non-readable target executable call `write(1, program_address, size)` so that it dumps its own virtual memory to standard output. It also works on executables with the setuid bit set.

This can be used to recover the compiled code and data of the executable for reverse engineering purposes.

## Motivation

This tool is inspired by [xocopy](http://reverse.lostrealm.com/tools/xocopy.html) by Dion Mendel but uses different methods to reach the same goal. Quoting Dion Mendel directly as he explained it very well:

> Sometimes when you're on a Unix system where you do not have admin privileges, you can come across programs with strange permissions such as the following:
> 
> -rwx--x--x    1    root     root     56152 Jul  1 12:37 runme
> 
> The permissions are set so that anyone can execute this program, but only the file owner can read the program. However this is not true. If somebody can execute the program they can copy it by reading it from memory once the program has been loaded.

In 2002, he released the [xocopy](http://reverse.lostrealm.com/tools/xocopy.html) tool which could be used to recover such an executable by dumping it from memory with `PTRACE_PEEKTEXT`. Sadly, this method does not work anymore on recent Linux kernels. Using `PTRACE_PEEKTEXT` (or `PTRACE_PEEKDATA`) now returns -1 if the loaded program has no read permissions for the current user.
 This tool uses alternative methods that are not impacted by this change.

> [PATCH 3.16 199/204] ptrace: Don't allow accessing an undumpable mm

## How to use

There are two versions of this tool. Both versions do not use `PTRACE_PEEKTEXT`.

- The version in [with_ld_preload](./with_ld_preload/) uses `LD_PRELOAD` to preload a shared library that replaces `__libc_start_main` with a function that dumps the executable virtual memory. It should be pretty reliable as long as the executable is linked with libc dynamically.
- The version in [with_ptrace](./with_ptrace/) uses `ptrace` calls like `PTRACE_GETREGS` and `PTRACE_SETREGS` (and `PTRACE_POKETEXT` on the stack for 32-bit executables) which are allowed even without read permissions. It is a work in progress, you probably should not use it (yet).

Both versions use `PR_SET_NO_NEW_PRIVS` before running the executable to disable the setuid bit if present.

You should probably try the [with_ld_preload](./with_ld_preload/README.md) version first. If that doesn't work, you can try [with_ptrace](./with_ptrace/README.md) instead.

TODO: merge both methods into a unique tool.
