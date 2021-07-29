//It is built on a Big Endian system

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/types.h>

#include <linux/udp.h>
#include <linux/ip.h>
#include <net/protocol.h>
#include <linux/if_ether.h>
#include <linux/net.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/netdevice.h>  
#include <linux/netfilter_ipv4.h>

#include <linux/sched.h>
#include "syndrv.h"

#define NFQ_NUM 1

static struct nf_hook_ops nfho;
struct udphdr *udp_header;          //udp header struct (not used)
struct iphdr *ip_header;          //ip header struct
u_char *payload;    // The pointer for the tcp payload.
char sourceAddr[20];
char myAddr[20] = "140.113.41.24"; 
char destAddr[20];

unsigned int my_func(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{   

    //return NF_QUEUE;
    //printk("%d\n", recorded);
    //if (recorded){
    //    return NF_ACCEPT;
    //}

    register struct iphdr *iph;
    register struct tcphdr *tcph;
    struct tls_hdr *tlsh;
    struct handshake *handshake_h;


    // check if it is TCP package here
    if(skb == 0)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if(iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcph = tcp_hdr(skb);
    sprintf(sourceAddr, "%u.%u.%u.%u", NIPQUAD(iph->saddr));
    
    if(tcph->syn == 1 && tcph->ack == 0){
        printk("A syn packet is redirect to nf_queue 1!\n");
	return NF_QUEUE_NR(NFQ_NUM);
    }

    return NF_ACCEPT;

}


static __init int syndrv_init(void)
{
    //printk("helloworld!\n");
    nfho.hook = my_func;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;
    int ret = 0;
    struct net *n;
    for_each_net(n)
        ret += nf_register_net_hook(n, &nfho);
   printk("kernel module syndrv start!\n");
   printk("nf_register_hook returnd %d\n", ret);
   return 0;
}
 
static __exit void syndrv_exit(void)
{
struct net *n;
    for_each_net(n)
        nf_unregister_net_hook(n, &nfho);
        printk("kernel module syndrv exit!\n");
}
 
module_init(syndrv_init);
module_exit(syndrv_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stone");
