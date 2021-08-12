#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>

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
struct nfct_handle *h;
struct nf_conntrack *ct;
int family;
int filefd;


unsigned int min(unsigned int a, unsigned int b){
	return (a < b)? a : b;
}

/*
 * hash function to map (ip1,ip2,port1,port2) -> int
 * */
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


/*
 * initialize the memory for saving connection data and packet rate
 * */
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

/*
 * update the state of the connection and calculate the packet rate
 * */
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

/*
 * print all the tracked connections
 * */
void track_history(){
	int i = 0;
	printf("%-10s %-15s %-7s %-15s %-7s %10s %10s\n","type", "ip1", "port1", "ip2", "port2", "packets", "bytes");
	for(i = 0; i < idx; i++){
		printf("%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n",history[list[i]].type, history[list[i]].ip1, history[list[i]].port1, history[list[i]].ip2, history[list[i]].port2, history[list[i]].packets, history[list[i]].bytes);
	}
	return;
}

/*
 * print the top 5 connection of the highest packet rate
 * */
void track_top(){
	int i = 0;
	struct timeval curTime;
	gettimeofday(&curTime, NULL);
	time_t rawtime;
	struct tm *timeinfo;
	char buf[80];

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(buf, 80, "%H:%M:%S", timeinfo);

	printf("-------------------\n");
	printf("Current time: %s.%03ld\n",buf,curTime.tv_usec/1000);
	printf("%-10s %-15s %-7s %-15s %-7s %10s %10s\n","type", "ip1", "port1", "ip2", "port2", "packets", "bytes");
	for(i = 0; i < 5; i++){
		printf("%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n", top[i].type, top[i].ip1, top[i].port1, top[i].ip2, top[i].port2, top[i].packets, top[i].bytes);
	}
	return;
}

/*
 * clear the packets and bytes store in top list
 * but reserve the ip/port
 * */
void track_clear_top(){
	int i = 0;
	for(i = 0; i < 5; i++){
		top[i].packets = top[i].bytes = 0;
	}
	return;
}

/*
 * sort the top 5 connections by packet rate
 * */
int track_comp(const void *lhs, const void *rhs){
	struct track *tlhs = (struct track*)lhs;
	struct track *trhs = (struct track*)rhs;
	return (trhs->packets - tlhs->packets);
}

/*
 * sort all the tracked connection by packet counts
 * */
int track_list_comp(const void *lhs, const void *rhs){
	struct track *tlhs = history + *(unsigned int*)lhs;
	struct track *trhs = history + *(unsigned int*)rhs;
	return (trhs->packets - tlhs->packets);
}

/*
 * callback function for conntrack query
 * */
int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data){
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

	// simple filter for conntrack data
	if(!nfct_cmp(obj,ct, NFCT_CMP_ORIG))
		return NFCT_CB_CONTINUE;

	// extract information from nf_conntrack object
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

	// update the conntrack data list
	track_add(proto->p_name,src,sport,dst,dport,packets,bytes);
	// keep track of the 5 connections with highest packet rate
	qsort(top,6,sizeof(struct track), track_comp);
	
	return NFCT_CB_CONTINUE;
}

void sigtimer(int signo){
	int ret;
	idx = 0;
	track_clear_top();
	memset(list,0,sizeof(unsigned int) * TRACK_CAP);

	ret = nfct_query(h, NFCT_Q_DUMP, &family);
	if(ret == -1){
		perror("nfct_query");
		exit(-1);
	}
	qsort(list,idx,sizeof(unsigned int),track_list_comp);
	track_top();
	return;	
}

void sigint_h(int signo){
	nfct_close(h);
	nfct_destroy(ct);
	close(filefd);
	signal(SIGINT,SIG_DFL);
	printf("\n");
	exit(0);
}
	

int main(int argc, char *argv[]){
	int srcflag = 0;
	int dstflag = 0;
	char src[16] = "";
	char dst[16] = "";
	struct itimerval value, ovalue;
	int ret;
	family = AF_INET;

	signal(SIGALRM,sigtimer);
	signal(SIGINT,sigint_h);

	// 100 ms setting
	/*
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 1;
	value.it_interval.tv_sec = 0;
	value.it_interval.tv_usec = 100000;
	*/
	// 1 sec setting
	//*
	value.it_value.tv_sec = 0;
	value.it_value.tv_usec = 1;
	value.it_interval.tv_sec = 1;
	value.it_interval.tv_usec = 0;
	//*/

	int opt;
	while((opt = getopt(argc, argv, "hs:d:T:t:o:")) != -1){
		switch(opt){
			case 'h':
				fprintf(stderr,"Usage: ./netflow [-s <ip>] [-d <ip>] [-T <second>] [-t <millisecond>]\n\tNote: -T/-t are exclusive\n");
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
			case 't':
				value.it_interval.tv_usec = atoi(optarg) * 1000;
				value.it_interval.tv_sec = 0;
				break;
			case 'T':
				value.it_interval.tv_sec = atoi(optarg);
				value.it_interval.tv_usec = 0;
				break;
			case 'o':
				filefd = open(optarg, O_WRONLY|O_CREAT, 0666);
				dup2(filefd,1);
				break;
			case '?':
				fprintf(stderr,"\tUsage: ./netflow [-s <ip>] [-d <ip>] [-T <second>] [-t <millisecond>]\n\t\tNote: -T/-t are exclusive\n");
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

	// start query for every 100ms
	ret = setitimer(ITIMER_REAL,&value,&ovalue);
	if(ret == -1){
		perror("setitimer");
		exit(-1);
	}

	for(;;);

	// should not be executed

	nfct_close(h);
	nfct_destroy(ct);
	
	return 0;
}
