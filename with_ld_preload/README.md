# xodump with_ld_preload

This version uses `LD_PRELOAD` to preload a shared library that replaces `__libc_start_main` with a function that dumps the executable virtual memory.

## How to use

Compile `xodump.c` and `xodump_preload_lib.c` using `make xodump`. If you want to dump a 32-bit executable, `xodump_preload_lib.c` must be compiled with the `-m32` flag.

Here is an example usage, where `xodump` is used to dump and find out the secret password of the `crackme` executable which has no read permissions.

```console
$ make clean && make all

$ cat crackme
cat: crackme: Permission denied
$ ./crackme 
Enter password: idontknow
Wrong password!

$ ./xodump crackme > out
will try to dump mapped executable /path/to/crackme
dumping memory mapping from 0x555555554000 to 0x555555555000
dumping memory mapping from 0x555555555000 to 0x555555556000
dumping memory mapping from 0x555555556000 to 0x555555557000
dumping memory mapping from 0x555555557000 to 0x555555558000
dumping memory mapping from 0x555555558000 to 0x555555559000
successfuly dumped 0x5000 bytes from mapped executable /path/to/crackme
child process exited correctly after dump

$ file out
out: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
$ strings out
[...]
Enter password: 
S3cr3tP4ssw0rd
[...]
$ chmod +x ./out && ./out
Enter password: S3cr3tP4ssw0rd
Good password!
```

## Limitations

This was tested on a regular Debian distro with libc 2.36 and ASLR enabled. There are some cases where this tool will not work.

Notably, if the target executable is statically linked to libc or not linked with libc at all, the `LD_PRELOAD` trick will have no effect on `__libc_start_main` and this method will not work at all (the target executable will run normally instead).

Also note that if the target executable is not compiled with [Full RELRO](https://www.redhat.com/fr/blog/hardening-elf-binaries-using-relocation-read-only-relro), the dumped ELF file will probably crash if you try to run it.
