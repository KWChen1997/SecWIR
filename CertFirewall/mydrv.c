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
#include "mydrv.h"



static struct nf_hook_ops nfho;
struct udphdr *udp_header;          //udp header struct (not used)
struct iphdr *ip_header;          //ip header struct
u_char *payload;    // The pointer for the tcp payload.
char sourceAddr[20];
char myAddr[20] = "140.113.41.24"; 
char destAddr[20];

int packettoread = 0;
bool recorded = false;

unsigned int my_func(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{   

    //return NF_QUEUE;
    //printk("%d\n", recorded);
    if (recorded){
        return NF_ACCEPT;
    }

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
    

    if(packettoread > 0){
        if(strcmp(sourceAddr, myAddr) == 0){
            packettoread = packettoread - 1;
            if (packettoread <= 0){
                //recorded = true;
		packettoread = 0;
            }
            printk("Packets to read: %d\n", packettoread);
            return NF_QUEUE; 
        }else{
            return NF_ACCEPT;
        }    
    }
    
    


    
    //sprintf(myAddr, "192.168.10.154");
    
    //printk("a lot of!\n");
    //we will dump all tls packet from a specific website
    if(!(strncmp(sourceAddr, myAddr,8))){
        if (ntohs(tcph->source) == 443){

            //payload = (char *)((unsigned char *)tcph + (tcph->doff));
            payload = (void *)skb->data+tcph->doff*4+iph->ihl*4;

            if(payload[0] == TLS_HANDSHAKE && payload[1] == 3 && payload[2] == 3){
                tlsh = (struct tls_hdr*)(payload);

                printk("This is Handshake!\n");
                packettoread = 0;
                recorded = true;
                return NF_QUEUE;

                
                    
            }
        }
    }
        

    return NF_ACCEPT;

}


static __init int mydrv_init(void)
{
    struct net_device *dev;

    dev = first_net_device(&init_net);
    while(dev){
	    printk("found %s\n",dev->name);
	    if(strcmp(dev->name,"wlp1s0")){
		nfho.dev = dev;
	    }
	    dev = next_net_device(dev);
    }
    
    //printk("helloworld!\n");
    nfho.hook = my_func;
    nfho.pf = NFPROTO_IPV4;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.priority = NF_IP_PRI_FIRST;
    int ret = 0;
    struct net *n;
    for_each_net(n)
        ret += nf_register_net_hook(n, &nfho);
   printk("kernel module mydrv start!\n");
   printk("nf_register_hook returnd %d\n", ret);
   return 0;
}
 
static __exit void mydrv_exit(void)
{
struct net *n;
    for_each_net(n)
        nf_unregister_net_hook(n, &nfho);
        printk("kernel module mydrv exit!\n");
}
 
module_init(mydrv_init);
module_exit(mydrv_exit);
 
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stone");
