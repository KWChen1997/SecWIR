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

void track_add(char *type, char *ip1, uint16_t port1, char *ip2, uint16_t port2, uint64_t packets, uint64_t bytes){
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
	trackList = NULL;

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

	qsort(trackList,idx,sizeof(struct track), track_comp);

	track_print5();

	nfct_close(h);
	nfct_destroy(ct);
	
	return 0;
}
