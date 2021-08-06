CC=gcc
CFLAGS= -g -Wall
CLIBS= -lnetfilter_conntrack
PROG=netflow

%:%.c
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

all: $(PROG)

clean:
	rm $(PROG)
