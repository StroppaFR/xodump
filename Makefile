CC=gcc 
CFLAGS=-Wall -Wextra -Wno-unused-parameter -Wl,--no-as-needed -ldl

xodump: xodump.c
	$(CC) $(CFLAGS) xodump.c -o xodump
crackme: crackme.c
	# If compiled with FULL RELRO, the dumped executable usually won't segfault when ran
	$(CC) $(CFLAGS) -Wl,-z,relro,-z,now crackme.c -o crackme
	chmod 111 crackme

all: xodump crackme
clean:
	rm -f *.o xodump crackme

.PHONY: all clean
.DEFAULT_GOAL=all
