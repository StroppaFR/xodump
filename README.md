# xodump

Make an executable ELF program with no read permissions dump itself.

This tool is inspired by [xocopy](http://reverse.lostrealm.com/tools/xocopy.html) by Dion Mendel but works in a very different way.

`xodump` will try to make a non-readable target executable call `write(1, address_base, size)` by modifying its registers with `ptrace` so that the target executable dumps its own virtual memory to standard output. It also works on executables with the setuid bit set.

The dumped executable will probably segfault when trying to run it because the original ELF file cannot be recovered from a simple virtual memory dump. Still this can be used to recover the compiled code and data for static analysis reverse engineering.

## Motivation

Quoting Dion Mendel directly as he explained it very well:

> Sometimes when you're on a Unix system where you do not have admin privileges, you can come across programs with strange permissions such as the following:
> 
> -rwx--x--x    1    root     root     56152 Jul  1 12:37 runme
> 
> The permissions are set so that anyone can execute this program, but only the file owner can read the program. However this is not true. If somebody can execute the program they can copy it by reading it from memory once the program has been loaded.

In 2002, he released the [xocopy](http://reverse.lostrealm.com/tools/xocopy.html) tool which could be used to recover such an executable by dumping it from memory with `PTRACE_PEEKTEXT`. Sadly, this method does not seem to work anymore on recent Linux kernels. Using `PTRACE_PEEKTEXT` (or `PTRACE_PEEKDATA`) now returns -1 if the loaded program has no read permissions for the current user.

This tool instead only uses `PTRACE_GETREGS` and `PTRACE_SETREGS` (and `PTRACE_POKETEXT` on the stack for 32-bit executables) which are allowed even without read permissions.

## How to use

`xodump.c` must be compiled with gcc and linked dynamically to the same libc used by the target executable you want to dump. This is important because it will calculate libc offsets to important functions by inspecting its own loaded libraries. Usually, simply compiling with `gcc xodump.c -o xodump` on the same system as the executable to dump should be good enough.

You can also use `strace ./target 2>&1 | grep libc` to find out which libc is loaded by the target executable.

Here is an example usage, where `xodump` is used to dump and find out the secret password of the `crackme` program which has no read permissions.

```console
$ make all

$ cat crackme
cat: crackme: Permission denied
$ ./crackme 
Enter password: idontknow
Wrong password!

$ ./xodump crackme -0x1000 > out
tracing process 50199. waiting for it to run outside libraries...
found probable program address. will start the dump from address 0x555555554000 (use <offset> to tweak this)
using 0x29d00 as the offset to __libc_start_main in libc
using 0x100170 as the offset to __write in libc
waiting for traced process to reach __libc_start_main...
found libc base of traced process: 0x7ffff7d97000
starting the dump now

$ file out
out: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
$ strings out
[...]
Enter password: 
S3cr3tP4ssw0rd
Good password!
Wrong password!
[...]
$ chmod +x ./out && ./out
Enter password: S3cr3tP4ssw0rd
Good password!
```

## Limitations

This is mainly a PoC, it was tested on a regular Debian distro with libc 2.36 and ASLR enabled. There are many cases where this tool will simply not work:

- if the target binary is linked statically with libc, the `write` function won't be able to be located, and it might not even even be present in the binary at all,
- if the target binary is loaded near shared libraries, which might be the case if it's compiled itself as a shared library (?),
- on systems with larger ASLR entropy, where shared libraries are loaded at random addresses (e.g will not start with 0x7f on a 64-bit system),
- probably many other reasons and securities might break this.

Note that the dumped program will segfault when trying to run it if it was not compiled with Full RELRO because of how relocations work.
