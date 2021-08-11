#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include "netflow.h"

#define TRACK_CAP 65535
#define HASHSIZE 65535

unsigned int cap;
unsigned int idx;
struct track *history;
unsigned int list[65536];
struct track top[6];

unsigned int min(unsigned int a, unsigned int b){
	return (a < b)? a : b;
}

unsigned int hash(char *ip1, char *ip2, uint16_t port1, uint16_t port2){
	unsigned int hashval;
	for(hashval = 0; *ip1 != '\0'; ip1++){
		hashval = (*ip1 + 31 * hashval) % HASHSIZE;
	}

	for(; *ip2 != '\0'; ip2++){
		hashval = (*ip2 + 31 * hashval) % HASHSIZE;
	}

	hashval = (port1 + 31 * hashval) % HASHSIZE;
	hashval = (port2 + 31 * hashval) % HASHSIZE;

	return hashval;
}

void track_init(){
	assert(history == NULL);

	history = (struct track*)malloc(sizeof(struct track) * TRACK_CAP);
	if(history == NULL){
		perror("history malloc failed!");
		exit(1);
	}
	memset(history, 0, sizeof(struct track) * TRACK_CAP);
	
	memset(list,0,sizeof(unsigned int) * TRACK_CAP);
	idx = 0;
	cap = 0;
	return;
}

void track_add(char *type, char *ip1, uint16_t port1, char *ip2, uint16_t port2, uint64_t packets, uint64_t bytes){
	int hid = hash(ip1,ip2,port1,port2);
	int tid = min(5,idx);
	
	strncpy(top[tid].type,type,10);
	strncpy(top[tid].ip1,ip1,16);
	top[tid].port1 = port1;
	strncpy(top[tid].ip2,ip2,16);
	top[tid].port2 = port2;
	top[tid].packets = packets - history[hid].packets;
	top[tid].bytes = bytes - history[hid].bytes;

	strncpy(history[hid].type,type,10);
	strncpy(history[hid].ip1,ip1,16);
	history[hid].port1 = port1;
	strncpy(history[hid].ip2,ip2,16);
	history[hid].port2 = port2;
	history[hid].packets = packets;
	history[hid].bytes = bytes;
	list[idx] = hid;
	idx++;
	return;
}

void track_history(){
	int i = 0;
	printf("%-10s %-15s %-7s %-15s %-7s %10s %10s\n","type", "ip1", "port1", "ip2", "port2", "packets", "bytes");
	for(i = 0; i < idx; i++){
		printf("%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n",history[list[i]].type, history[list[i]].ip1, history[list[i]].port1, history[list[i]].ip2, history[list[i]].port2, history[list[i]].packets, history[list[i]].bytes);
	}
	return;
}

void track_top(){
	int i = 0;
	printf("%-10s %-15s %-7s %-15s %-7s %10s %10s\n","type", "ip1", "port1", "ip2", "port2", "packets", "bytes");
	for(i = 0; i < 5; i++){
		printf("%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n", top[i].type, top[i].ip1, top[i].port1, top[i].ip2, top[i].port2, top[i].packets, top[i].bytes);
	}
	return;
}

int track_comp(const void *lhs, const void *rhs){
	struct track *tlhs = (struct track*)lhs;
	struct track *trhs = (struct track*)rhs;
	return (trhs->packets - tlhs->packets);
}

int track_list_comp(const void *lhs, const void *rhs){
	struct track *tlhs = history + *(unsigned int*)lhs;
	struct track *trhs = history + *(unsigned int*)rhs;
	return (trhs->packets - tlhs->packets);
}

int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data){
	char buf[1024];
	struct nf_conntrack *obj = data;
	struct in_addr tmp;
	char src[16] = "";
	char dst[16] = "";
	uint16_t sport = 0;
	uint16_t dport = 0;
	int protonum;
	struct protoent *proto;
	uint64_t packets = 0;
	uint64_t bytes = 0;

	if(!nfct_cmp(obj,ct, NFCT_CMP_ORIG))
		return NFCT_CB_CONTINUE;
	nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);
	// printf("%s\n", buf);
	// res = parser(buf);
	// track_add(res->type, res->ip1, res->port1, res->ip2, res->port2, res->packets, res->bytes);
	if(nfct_attr_is_set(ct,ATTR_ORIG_L4PROTO)){	
		protonum = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
		proto = getprotobynumber(protonum);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_IPV4_SRC)){
		tmp.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
		snprintf(src,15,"%s",inet_ntoa(tmp));
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_IPV4_DST)){
		tmp.s_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
		snprintf(dst,15,"%s",inet_ntoa(tmp));
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_PORT_SRC)){
		sport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_PORT_DST)){
		dport = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_COUNTER_PACKETS)){
		packets += nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
	}
	if(nfct_attr_is_set(ct,ATTR_REPL_COUNTER_PACKETS)){
		packets += nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_COUNTER_BYTES)){
		bytes += nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
	}
	if(nfct_attr_is_set(ct,ATTR_REPL_COUNTER_BYTES)){
		bytes += nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
	}
	track_add(proto->p_name,src,sport,dst,dport,packets,bytes);
	qsort(top,6,sizeof(struct track), track_comp);
	
	return NFCT_CB_CONTINUE;
}

int main(int argc, char *argv[]){
	int srcflag = 0;
	int dstflag = 0;
	char src[16] = "";
	char dst[16] = "";
	int ret;
	struct nfct_handle *h;
	struct nf_conntrack *ct;
	int family = AF_INET;

	int opt;
	while((opt = getopt(argc, argv, "hs:d:")) != -1){
		switch(opt){
			case 'h':
				fprintf(stderr,"Usage: ./netflow [-s <ip>] [-d <ip>]\n");
				exit(0);
				break;
			case 's':
				srcflag = 1;
				strncpy(src,optarg,15);
				break;
			case 'd':
				dstflag = 1;
				strncpy(dst,optarg,15);
				break;
			case '?':
				fprintf(stderr,"\tUsage: ./netflow [-s <ip>] [-d <ip>]\n");
				exit(-1);
		}
	}

	track_init();

	ct = nfct_new();
	if(!ct){
		perror("nfct_new");
		exit(-1);
	}

	nfct_set_attr_u8(ct,ATTR_REPL_L3PROTO, AF_INET);
	if(srcflag)
		nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_SRC, inet_addr(src));
	if(dstflag)
		nfct_set_attr_u32(ct, ATTR_ORIG_IPV4_DST, inet_addr(dst));

	h = nfct_open(CONNTRACK, 0);
	if(!h){
		perror("nfct_open");
		exit(-1);
	}

	ret = nfct_callback_register(h, NFCT_T_ALL, cb, ct);
	if(ret == -1){
		perror("nfct_callback_register");
		exit(-1);
	}
	ret = nfct_query(h, NFCT_Q_DUMP, &family);
	if(ret == -1){
		perror("nfct_query");
		exit(-1);
	}

	qsort(list,idx,sizeof(unsigned int),track_list_comp);
	track_history();
	printf("\n");

	sleep(1);

	idx = 0;
	memset(top,0,sizeof(struct track) * 6);
	memset(list,0,sizeof(unsigned int) * TRACK_CAP);

	ret = nfct_query(h, NFCT_Q_DUMP, &family);
	if(ret == -1){
		perror("nfct_query");
		exit(-1);
	}

	qsort(list,idx,sizeof(unsigned int),track_list_comp);
	track_history();
	printf("\n");

	track_top();

	nfct_close(h);
	nfct_destroy(ct);
	
	return 0;
}
