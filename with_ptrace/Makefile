CC=gcc 
CFLAGS=-Wall -Wextra -Wno-unused-parameter -Wl,--no-as-needed -ldl

xodump: xodump.c
	$(CC) $(CFLAGS) xodump.c -o xodump
crackme: ../example/crackme.c
	# If compiled with FULL RELRO, the dumped executable usually won't segfault when ran
	$(CC) $(CFLAGS) -Wl,-z,relro,-z,now $< -o $@
	#$(CC) $(CFLAGS) -Wl,-z,norelro $< -o $@
	chmod 111 $@

all: xodump crackme
clean:
	rm -f *.o *.so xodump crackme out

.PHONY: all clean
.DEFAULT_GOAL=all
