# xodump with_ptrace

This version uses `ptrace` calls like `PTRACE_GETREGS` and `PTRACE_SETREGS` (and `PTRACE_POKETEXT` on the stack for 32-bit executables).

First the parent process reads the program counter register until it detects an address of the mapped executable. Then it steps until `__libc_start_main` to find the address of the mapped libc and modifies the registers of the child process so that it calls `__write(1, program_base, large_size)`.

## How to use

`xodump.c` must be compiled with gcc and linked dynamically to the same libc used by the target executable you want to dump. This is important because it will calculate libc offsets to important functions by inspecting its own loaded libraries. Usually, simply compiling with `gcc xodump.c -o xodump` on the same system as the executable to dump should be good enough.

You can also use `strace ./target 2>&1 | grep libc` to find out which libc is loaded by the target executable.

If you want to dump a 32-bit executable, `xodump` must be compiled with the `-m32` flag.

Here is an example usage, where `xodump` is used to dump and find out the secret password of the `crackme` executable which has no read permissions.

```console
$ make clean && make all

$ cat crackme
cat: crackme: Permission denied
$ ./crackme 
Enter password: idontknow
Wrong password!

$ ./xodump crackme -0x1000 > out
tracing process 27429. waiting for it to run outside libraries...
found probable program address. will start the dump from address 0x555555554000 (use <offset> to tweak this)
using 0x23f90 as the offset to __libc_start_main in libc
using 0x10e280 as the offset to __write in libc
waiting for traced process to reach __libc_start_main...
found libc base of traced process: 0x7ffff7daa000
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

This was tested on a regular Debian distro with libc 2.36 and ASLR enabled. There are many cases where this tool will simply not work:

- if the target binary is linked statically with libc, the `__write` function won't be able to be located, and it might not even even be present in the executable at all anyway,
- if the target binary is loaded near shared libraries, which might be the case if it's compiled itself as a shared library (?),
- on systems with larger ASLR entropy, where shared libraries are loaded at random addresses (e.g will not start with 0x7f on a 64-bit system),
- probably many other reasons and securities might break this.
