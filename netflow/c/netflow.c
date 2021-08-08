#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "netflow.h"

#define TRACK_CAP 100

unsigned int cap;
unsigned int idx;
struct track *trackList;

void track_init(){
	assert(trackList == NULL);
	trackList = (struct track*)malloc(sizeof(struct track) * TRACK_CAP);
	if(trackList == NULL){
		perror("Track List init failed!");
		exit(1);
	}
	idx = 0;
	cap = 0;
	return;
}

void track_add(char *type, char *ip1, int port1, char *ip2, int port2, unsigned long packets, unsigned long bytes){
	if(idx == cap)
		track_expand();
	strncpy(trackList[idx].type,type,10);
	strncpy(trackList[idx].ip1,ip1,16);
	trackList[idx].port1 = port1;
	strncpy(trackList[idx].ip2,ip2,16);
	trackList[idx].port2 = port2;
	trackList[idx].packets = packets;
	trackList[idx].bytes = bytes;
	idx++;
	return;
}

void track_expand(){
	struct track *tmp;
	tmp = (struct track*)malloc(sizeof(struct track) * (cap + TRACK_CAP));
	memcpy(tmp,trackList,sizeof(struct track) * cap);
	free(trackList);
	trackList = tmp;
	cap += TRACK_CAP;
	return;
};

void track_print(){
	int i = 0;
	printf("%-10s %-15s %-7s %-15s %-7s %10s %10s\n","type", "ip1", "port1", "ip2", "port2", "packets", "bytes");
	for(i = 0; i < idx; i++){
		printf("%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n",trackList[i].type, trackList[i].ip1, trackList[i].port1,trackList[i].ip2,trackList[i].port2, trackList[i].packets, trackList[i].bytes);
	}
	return;
}

void track_print5(){
	int i = 0;
	printf("%-10s %-15s %-7s %-15s %-7s %10s %10s\n","type", "ip1", "port1", "ip2", "port2", "packets", "bytes");
	for(i = 0; i < idx && i < 5; i++){
		printf("%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n",trackList[i].type, trackList[i].ip1, trackList[i].port1,trackList[i].ip2,trackList[i].port2, trackList[i].packets, trackList[i].bytes);
	}
	return;

}

int track_comp(const void *lhs, const void *rhs){
	struct track *tlhs = (struct track*)lhs;
	struct track *trhs = (struct track*)rhs;
	return (trhs->packets - tlhs->packets);
}

struct track* parser(char str[]){
	struct track *res;
	int fip1 = 1;
	int fip2 = 1;
	int fport1 = 1;
	int fport2 = 1;
	res = (struct track*)malloc(sizeof(struct track));
	memset(res,0,sizeof(struct track));

	char *pch;
	pch = strtok(str," ");
	strncpy(res->type,pch,10);
	pch = strtok(NULL, " ");
	while(pch != NULL){
		// printf("%s\n", pch);
		if(fip1 && !strncmp(pch,"src",3)){
			fip1 = 0;
			strncpy(res->ip1,pch+4,15);
		}
		else if(fip2 && !strncmp(pch, "dst",3)){
			fip2 = 0;
			strncpy(res->ip2,pch+4,15);
		}
		else if(fport1 && !strncmp(pch, "sport",5)){
			fport1 = 0;
			res->port1 = atoi(pch+6);
		}
		else if(fport2 && !strncmp(pch, "dport",5)){
			fport2 = 0;
			res->port2 = atoi(pch+6);
		}
		else if(!strncmp(pch,"packets",7)){
			res->packets += strtoul(pch+8,NULL,0);
		}
		else if(!strncmp(pch,"bytes",5)){
			res->bytes += strtoul(pch+6,NULL,0);
		}
		pch = strtok(NULL," ");
	}

	if(fport1)
		res->port1 = -1;
	if(fport2)
		res->port2 = -1;

	return res;
}

int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data){
	char buf[1024];
	struct nf_conntrack *obj = data;

	struct track *res;

	if(!nfct_cmp(obj,ct, NFCT_CMP_ALL|NFCT_CMP_MASK))
		return NFCT_CB_CONTINUE;
	nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);
	// printf("%s\n", buf);
	res = parser(buf);
	track_add(res->type, res->ip1, res->port1, res->ip2, res->port2, res->packets, res->bytes);

	return NFCT_CB_CONTINUE;
}

int main(int argc, char **argv){
	int ret;
	struct nfct_handle *h;
	struct nf_conntrack *ct;
	int family = AF_INET;
	trackList = NULL;

	track_init();

	ct = nfct_new();
	assert(ct != NULL);

	h = nfct_open(CONNTRACK, 0);
	assert(h != NULL);

	ret = nfct_callback_register(h, NFCT_T_ALL, cb, ct);
	if(ret == -1){
		perror(strerror(errno));
	}
	ret = nfct_query(h, NFCT_Q_DUMP, &family);
	if(ret == -1){
		perror(strerror(errno));
	}

	qsort(trackList,idx,sizeof(struct track), track_comp);

	track_print5();

	nfct_close(h);
	nfct_destroy(ct);
	
	return 0;
}
