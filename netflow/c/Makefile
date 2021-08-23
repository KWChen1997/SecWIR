CC=gcc
CFLAGS= -g -Wall
SRCS=${wildcard *.c}
OBJS=${patsubst %.c,%.o,$(SRCS)}
CLIBS= -lnetfilter_conntrack
PROG=netflow

.PRECIOUS:$(OBJS)

all: $(PROG)

$(PROG):$(SRCS) 
	$(CC) $(CFLAGS) -o $@ $^ $(CLIBS)

clean:
	rm *.o $(PROG)
