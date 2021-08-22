#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "node.h"

unsigned int hash(char *key, unsigned int bucket_size){
	unsigned int hashval = 0;
        char *p = key;
	while(*p != '\0'){
		hashval = (hashval * PRIME + *p++) % bucket_size;
	}
	return hashval;
}

int map_init(struct map *db){
	int ret;
	
	db->list = NULL;
	db->cap = 0;
	db->count = 0;
	db->used = NULL;

	ret = map_increment(db);
	if(ret == -1){
		perror("map_increment");
		return -1;
	}

	return 0;
}

int map_increment(struct map *db){
	int i;
	unsigned int newcap = db->cap;
	struct node *newlist = NULL;
	struct node *oldlist = db->list;

	unsigned int *newused = NULL;
	unsigned int *oldused = db->used;

EXPAND:
	newcap += MAP_INCREMENT;
	if(newused)
		free(newused);
	newused = (unsigned int*)malloc(sizeof(unsigned int) * newcap);
	if(newused == NULL){
		perror("malloc");
		return -1;
	}

	if(newlist)
		free(newlist);
      	newlist = (struct node*)malloc(sizeof(struct node) * newcap);
	if(newlist == NULL){
		perror("malloc");
		return -1;
	}

	memset(newlist,0,sizeof(struct node) * newcap);

	// rehash
	for(i = 0; i < db->count; i++){
		struct node *oldnode = oldlist + oldused[i];
		int hashval = hash(oldnode->key, newcap);
		struct node *newnode = newlist + hashval;
		if(newnode->valid){
			// puts("collision");
			goto EXPAND;
		}
		memcpy(newnode,oldnode,sizeof(struct node));
		newused[i] = hashval;
	}

	db->list = newlist;
	db->used = newused;
	if(oldlist)
		free(oldlist);
	if(oldused)
		free(oldused);
	
	db->cap += MAP_INCREMENT;

	return db->cap;
}

int map_insert(struct map *db, char *key, char *val){

	if(map_find(db,key) != NULL)
		return 0;

	int hashval = hash(key,db->cap);

	struct node node = (struct node){.valid = 1, .key = key, .val = val};
	struct node *dst = db->list + hashval;
	while(dst->valid || db->count == db->cap){
		if(map_increment(db) == -1){
			perror("map_increment");
			return -1;
		}
		
		hashval = hash(key,db->cap);
		dst = db->list + hashval;
	}

	node_copy(dst,&node);
	db->used[db->count++] = hashval;
	return 0;
}

struct node* map_find(struct map *db, char *key){
	unsigned int hashval = hash(key,db->cap);
	if(db->list[hashval].valid && strncmp(key,db->list[hashval].key,15) == 0)
		return db->list + hashval;
	return NULL;
}

void map_print(struct map *db){
	int i = 0;
	for(i = 0; i < db->count; i++){
		struct node *tar = db->list + db->used[i];
		printf("used: %u key: %s val: %s\n", db->used[i],  tar->key, tar->val);
	}
	return;
}
