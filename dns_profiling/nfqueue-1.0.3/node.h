#include <stdio.h>

#ifndef NODE
#define NODE

struct node {
	int valid;
	char *key;
	char *val;
};

int node_copy(struct node *dst, struct node *src);

#endif

