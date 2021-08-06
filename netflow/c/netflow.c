#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

int cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data){
	char buf[1024];
	struct nf_conntrack *obj = data;
	
	if(!nfct_cmp(obj,ct, NFCT_CMP_ALL|NFCT_CMP_MASK))
		return NFCT_CB_CONTINUE;
	nfct_snprintf(buf, sizeof(buf), ct, NFCT_T_UNKNOWN, NFCT_O_DEFAULT, 0);
	printf("%s\n", buf);

	return NFCT_CB_CONTINUE;
}

int main(int argc, char **argv){
	int ret;
	struct nfct_handle *h;
	struct nf_conntrack *ct;
	int family = AF_INET;

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

	nfct_close(h);
	nfct_destroy(ct);
	
	return 0;
}
