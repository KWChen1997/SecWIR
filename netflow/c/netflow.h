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
	int port1;
	int port2;
        char ip2[16];
        unsigned long packets;
        unsigned long bytes;
};

void track_init();
void track_add(char *type, char *ip1, int port1, char *ip2, int port2, unsigned long packets, unsigned long bytes);
void track_expand();
void track_print();
void track_print5();
int track_comp(const void *lhs, const void *rhs);
#endif
