#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#ifndef MYNETFLOW
#define MYNETFLOW

struct track{
	char type[10];
        char ip1[16];
	uint16_t port1;
	uint16_t port2;
        char ip2[16];
        uint64_t packets;
        uint64_t bytes;
};

void track_init();
void track_add(char *type, char *ip1, uint16_t port1, char *ip2, uint16_t port2, uint64_t packets, uint64_t bytes);
void track_expand();
void track_print();
void track_print5();
int track_comp(const void *lhs, const void *rhs);
#endif
