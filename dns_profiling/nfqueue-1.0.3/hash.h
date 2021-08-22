#include <stdio.h>

#ifndef HASH
#define HASH

#define PRIME 31
#define MAP_INCREMENT 1000

struct map {
	struct node *list;
	unsigned int cap;
	unsigned int count;
	unsigned int *used;
};

int map_init(struct map *db);
int map_increment(struct map *db);
int map_insert(struct map *db, char *key, char *val);
struct node* map_find(struct map *db, char *key);
void map_print(struct map *db);
unsigned int hash(char *key, unsigned int bucket_size);


#endif


