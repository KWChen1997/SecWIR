#include "node.h"
#include <string.h>

int node_copy(struct node *dst, struct node *src){
	dst->valid = src->valid;
	dst->key = strdup(src->key);
	if(dst->key == NULL){
		perror("node_copy strdup");
		return -1;
	}
	dst->val = strdup(src->val);
	if(dst->val == NULL){
		perror("node_copy strdup");
		return -1;
	}
	return 0;
}
