#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>	
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "filter.h"

#define NFQ_NUM 1

int is_syn(unsigned char *data){
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = (struct iphdr*)data;
	if(iph->protocol != IPPROTO_TCP)goto NOT_SYN;
	tcph = (struct tcphdr*)(data + sizeof(struct iphdr));
	if(tcph->syn == 1 && tcph->ack == 0)goto IS_SYN;
	else goto NOT_SYN;

IS_SYN:
	return 1;
NOT_SYN:
	return 0;
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	int ret;
	unsigned char *data;
	struct iphdr *iph;
	struct tcphdr *tcph;

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		iph = (struct iphdr*)data;
		if(iph->protocol != IPPROTO_TCP)goto EXIT;
		printf("source address=%u.%u.%u.%u ", NIPQUAD(iph->saddr));
		tcph = (struct tcphdr*)(data + sizeof(struct iphdr));
		// printf("window size=%d ", ((tcph->window & 0xff)<<8) + ((tcph->window & 0xff00)>>8));
		printf("window size=%d ", ntohs(tcph->window));
		//processPacketData (data, ret);
	}
	fputc('\n', stdout);

EXIT:
	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
//	u_int32_t id = print_pkt(nfa);
	u_int32_t id;
	
	int ret;
	unsigned char *payload;

        struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);	
	id = ntohl(ph->packet_id);
	
	ret = nfq_get_payload(nfa,&payload);

	if(ret >= 0 && is_syn(payload))
		print_pkt(nfa);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '1'\n");
	qh = nfq_create_queue(h,  NFQ_NUM, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		// printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
