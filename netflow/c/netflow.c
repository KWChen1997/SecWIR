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
struct connection *history;
unsigned int list[65536];
struct connection top[6];
struct nfct_handle *h;
int family;
int filefd;


unsigned int min(unsigned int a, unsigned int b){
	return (a < b)? a : b;
}

int test(struct connection *connection, struct filter *filter){
	return (filter->saddr == 0 || ((ntohl(connection->saddr) & filter->smask) == (ntohl(filter->saddr) & filter->smask))) &&
	       (filter->daddr == 0 || ((ntohl(connection->daddr) & filter->dmask) == (ntohl(filter->daddr) & filter->dmask)));
}

uint32_t createmask(int num){
	uint32_t mask = 0xFFFFFFFF;
	mask = (mask >> (32 - num)) << (32 - num);
	return mask;
}

/*
 * hash function to map (ip1,ip2,port1,port2) -> int
 * */
unsigned int hash(uint32_t ip1, uint32_t ip2, uint16_t port1, uint16_t port2){
	unsigned int hashval = 0;

	hashval = (hashval * 31 +  ((unsigned char*)&ip1)[0]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip1)[1]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip1)[2]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip1)[3]) % HASHSIZE;

	hashval = (hashval * 31 +  ((unsigned char*)&ip2)[0]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip2)[1]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip2)[2]) % HASHSIZE;
	hashval = (hashval * 31 +  ((unsigned char*)&ip2)[3]) % HASHSIZE;

	hashval = (port1 + 31 * hashval) % HASHSIZE;
	hashval = (port2 + 31 * hashval) % HASHSIZE;

	return hashval;
}

char *ntoa(uint32_t net){

	char *ip = (char*)malloc(sizeof(char)*16);
	snprintf(ip,16,"%u.%u.%u.%u", NIPQUAD(net));
	return ip;
}


/*
 * initialize the memory for saving connection data and packet rate
 * */
void connection_init(){
	assert(history == NULL);

	history = (struct connection*)malloc(sizeof(struct connection) * TRACK_CAP);
	if(history == NULL){
		perror("history malloc failed!");
		exit(1);
	}
	memset(history, 0, sizeof(struct connection) * TRACK_CAP);
	
	memset(list,0,sizeof(unsigned int) * TRACK_CAP);
	idx = 0;
	cap = 0;
	return;
}

/*
 * update the state of the connection and calculate the packet rate
 * */
void connection_add(struct connection *conn){
	int hid = hash(conn->saddr,conn->daddr,conn->sport,conn->dport);
	int tid = min(5,idx);
	
	memcpy(top + tid, conn, sizeof(struct connection));
	top[tid].packets -= history[hid].packets;
	top[tid].bytes -= history[hid].bytes;

	memcpy(history + hid, conn, sizeof(struct connection));
	list[idx] = hid;
	idx++;
	return;
}

/*
 * print all the tracked connections
 * */
void connection_history(){
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
	for(i = 0; i < idx; i++){
		printf("%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n",
				getprotobynumber(history[list[i]].proto)->p_name,
			       	ntoa(history[list[i]].saddr), history[list[i]].sport,
			       	ntoa(history[list[i]].daddr), history[list[i]].dport,
			       	history[list[i]].packets, history[list[i]].bytes);
	}
	return;
}

/*
 * print the top 5 connection of the highest packet rate
 * */
void connection_top(){
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
		printf("%-10s %-15s %-7d %-15s %-7d %10ld %10ld\n",
			       	getprotobynumber(top[i].proto)->p_name,
			       	ntoa(top[i].saddr), top[i].sport,
			       	ntoa(top[i].daddr), top[i].dport,
			       	top[i].packets, top[i].bytes);
	}
	return;
}

/*
 * clear the packets and bytes store in top list
 * but reserve the ip/port
 * */
void connection_clear_top(){
	int i = 0;
	for(i = 0; i < 5; i++){
	
		top[i].packets = top[i].bytes = 0;
	}
	return;
}

/*
 * sort the top 5 connections by packet rate
 * */
int connection_comp(const void *lhs, const void *rhs){
	struct connection *tlhs = (struct connection*)lhs;
	struct connection *trhs = (struct connection*)rhs;
	return (trhs->packets - tlhs->packets);
}

/*
 * sort all the tracked connection by packet counts
 * */
int connection_list_comp(const void *lhs, const void *rhs){
	struct connection *tlhs = history + *(unsigned int*)lhs;
	struct connection *trhs = history + *(unsigned int*)rhs;
	return (trhs->packets - tlhs->packets);
}

/*
 * callback function for conntrack query
 * */
int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data){
	/*
	char src[16] = "";
	char dst[16] = "";
	uint16_t sport = 0;
	uint16_t dport = 0;
	int protonum;
	struct protoent *proto;
	uint64_t packets = 0;
	uint64_t bytes = 0;
	*/

	struct connection connection;
	struct filter *filter = data;

	memset(&connection,0,sizeof(struct connection));

	

	// extract information from nf_conntrack object
	if(nfct_attr_is_set(ct,ATTR_ORIG_L4PROTO)){	
		connection.proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_IPV4_SRC)){
		connection.saddr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_IPV4_DST)){
		connection.daddr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_PORT_SRC)){
		connection.sport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_PORT_DST)){
		connection.dport = ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_COUNTER_PACKETS)){
		connection.packets += nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
	}
	if(nfct_attr_is_set(ct,ATTR_REPL_COUNTER_PACKETS)){
		connection.packets += nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS);
	}
	if(nfct_attr_is_set(ct,ATTR_ORIG_COUNTER_BYTES)){
		connection.bytes += nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
	}
	if(nfct_attr_is_set(ct,ATTR_REPL_COUNTER_BYTES)){
		connection.bytes += nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
	}

	// simple filter for conntrack data
	if(!test(&connection,filter)){
		return 	NFCT_CB_CONTINUE;
	}

	// update the conntrack data list
	connection_add(&connection);
	// keep track of the 5 connections with highest packet rate
	qsort(top,6,sizeof(struct connection), connection_comp);
	
	return NFCT_CB_CONTINUE;
}

void sigtimer(int signo){
	int ret;
	idx = 0;
	connection_clear_top();
	memset(list,0,sizeof(unsigned int) * TRACK_CAP);

	ret = nfct_query(h, NFCT_Q_DUMP, &family);
	if(ret == -1){
		perror("nfct_query");
		exit(-1);
	}
	qsort(list,idx,sizeof(unsigned int),connection_list_comp);
	connection_history();
	return;	
}

void sigint_h(int signo){
	nfct_close(h);
	close(filefd);
	signal(SIGINT,SIG_DFL);
	printf("\n");
	exit(0);
}
	

int main(int argc, char *argv[]){
	struct itimerval value, ovalue;
	int ret;
	struct filter filter;
	memset(&filter,0,sizeof(filter));
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
	char buf[19] = "";
	char *ptr;
	struct in_addr net;
	while((opt = getopt(argc, argv, "hs:d:T:t:o:")) != -1){
		switch(opt){
			case 'h':
				fprintf(stderr,"Usage: ./netflow [-s <ip>] [-d <ip>] [-T <second>] [-t <millisecond>]\n\tNote: -T/-t are exclusive\n");
				exit(0);
				break;
			case 's':
				strncpy(buf,optarg,19);
				ptr = strtok(buf,"/");
				inet_aton(ptr,&net);
				filter.saddr = net.s_addr;
				ptr = strtok(NULL,"/");
				if(ptr != NULL)
					filter.smask = createmask(atoi(ptr));
				else
					filter.smask = 0xFFFFFFFF;
				break;
			case 'd':
				strncpy(buf,optarg,19);
				ptr = strtok(buf,"/");
				inet_aton(ptr,&net);
				filter.daddr = net.s_addr;
				ptr = strtok(NULL,"/");
				if(ptr != NULL)
					filter.dmask = createmask(atoi(ptr));
				else
					filter.dmask = 0xFFFFFFFF;
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

	connection_init();
	/*
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
	*/

	h = nfct_open(CONNTRACK, 0);
	if(!h){
		perror("nfct_open");
		exit(-1);
	}

	ret = nfct_callback_register(h, NFCT_T_ALL, cb, &filter);
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
	
	return 0;
}
