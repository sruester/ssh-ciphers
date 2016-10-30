CC=gcc
CFLAGS=-O2 -Wall -std=gnu99

all:
	$(CC) $(CFLAGS) ssh-ciphers.c -o ssh-ciphers

clean:
	-rm -f ssh-ciphers
