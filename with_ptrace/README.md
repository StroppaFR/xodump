# xodump with_ptrace

This version uses `ptrace` calls such as `PTRACE_GETREGS`, `PTRACE_SETREGS` and `PTRACE_SYSCALL` which are permitted even without read permissions.

The idea is to trace the executable and stop it before the first `syscall` instruction, then use that instruction repeatedly to make it execute multiple system calls. The system calls can be used to make the child process read its own mapped memory and exchange data with the parent process.

Contrary to the `LD_PRELOAD` version, this method can be used to dump statically linked executables. Only AMD64 and i386 architectures are supported.

## How to use

Compile `xodump.c` using `make xodump`. If you want to dump a 32-bit executable, `xodump.c` must be compiled with the `-m32` flag.

Here is an example usage, where `xodump` is used to dump and find out the secret password of the `crackme` executable which has no read permissions and is statically linked.

```console
$ make clean && make all

$ cat crackme
cat: crackme: Permission denied
$ ./crackme 
Enter password: idontknow
Wrong password!

$ ./xodump crackme > out
will try to dump /path/to/crackme from parent using ptrace
successfully allocated memory area in child process at 0x7ffff7feb000
dumping memory mapping from 0x400000 to 0x401000
dumping memory mapping from 0x401000 to 0x474000
dumping memory mapping from 0x474000 to 0x49b000
dumping memory mapping from 0x49b000 to 0x4a2000
successfully dumped 0xc2000 bytes from mapped executable /path/to/crackme

$ file out 
out: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, missing section headers
$ strings out
[...]
Enter password: 
S3cr3tP4ssw0rd
[...]
$ ./crackme
Enter password: S3cr3tP4ssw0rd
Good password!
```

## Limitations

This was tested on a regular Debian distro with libc 2.36 and ASLR enabled.

In theory, it should be able to dump any executable as long as it uses a `syscall` (or `int 0x80`) instruction. In practice, this is a PoC, it is not portable at all and it could break at any time for any number of reasons.
