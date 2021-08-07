#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#ifndef MYNETFLOW
#define MYNETFLOW
#define TRACK_CAP 3

struct track{
        char ip1[15];
        char ip2[15];
        unsigned long packets;
        unsigned long bytes;
};

void track_init();
void track_add(char *ip1, char *ip2, unsigned long packets, unsigned long bytes);
void track_expand();
void track_print();

#endif
