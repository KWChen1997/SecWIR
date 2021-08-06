#include <stdio.h>
#include <stdlib.h>    
#include <string.h>    
#include <errno.h>    
#include <unistd.h>    
#include <arpa/inet.h>         

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>    
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>         

int cb(enum nf_conntrack_msg_type type,struct nf_conntrack *ct,void *data)    
{          
        char buf[1024];               
	struct nf_conntrack *obj = data;

	if (!nfct_cmp(obj, ct, NFCT_CMP_ALL | NFCT_CMP_MASK))
		return NFCT_CB_CONTINUE;

        //nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3);    
        nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);    
        printf("%s\n", buf);

        return NFCT_CB_CONTINUE;    
}         

int get()    
{    
        int ret;    
        struct nfct_handle *h;    
        struct nf_conntrack *ct;    
	int family = AF_INET;

        ct = nfct_new();

        if (!ct) {    
                perror("nfct_new");    
                return 0;    
        }    

        //nfct_set_attr_u8(ct, ATTR_REPL_L3PROTO, AF_INET);    
        //nfct_set_attr_u32(ct, ATTR_REPL_IPV4_SRC, inet_addr("192.168.6.10"));    
        //nfct_set_attr_u32(ct, ATTR_REPL_IPV4_DST, inet_addr("192.168.6.231"));             
        //nfct_set_attr_u8(ct, ATTR_REPL_L4PROTO, IPPROTO_TCP);    
        //nfct_set_attr_u16(ct, ATTR_REPL_PORT_SRC, htons(22));    
        //nfct_set_attr_u16(ct, ATTR_REPL_PORT_DST, htons(60299));         

        h = nfct_open(CONNTRACK, 0);    
        if (!h) {    
                perror("nfct_open");    
                nfct_destroy(ct);    
                return -1;    
        }         

        nfct_callback_register(h, NFCT_T_ALL, cb, ct);             
        ret = nfct_query(h, NFCT_Q_DUMP, &family);

        if (ret == -1)    
                printf("(%d)(%s)\n", ret, strerror(errno));    
        else    
                printf("(OK)\n");

        nfct_close(h);
        nfct_destroy(ct);

        return -1;
}

int main()
{    
    get();
    return 1;
}
