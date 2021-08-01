CC = gcc
CFLAGS = -g -Wall
CLIBSFLAGS = -lssl -lcrypto
PROGS = certVerifier

%:%.c
	$(CC) $(CFLAGS) -o $@ $< $(CLIBSFLAGS)

all:$(PROGS)

clean:
	rm $(PROGS)
