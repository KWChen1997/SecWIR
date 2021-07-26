#define TLS_HANDSHAKE 22
#define CLIENT_HELLO 1
#define SERVER_HELLO 2
#define TLS_CERT 11


#define SSLv2 0x002
#define SSLv3 0x300
#define TLSv1 0x301
#define TLSv1_1 0x302
#define TLSv1_2 0x303


#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_CHACHA20_POLY1305_SHA256 0x1303
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xc02b
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xc02f
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 0xcca9
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 0xcca8
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xc02c
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0xc030
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 0xc00a
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 0xc009
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 0xc013
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 0xc014
#define TLS_RSA_WITH_AES_128_GCM_SHA256 0x009c
#define TLS_RSA_WITH_AES_256_GCM_SHA384 0x009d
#define TLS_RSA_WITH_AES_128_CBC_SHA 0x002f
#define TLS_RSA_WITH_AES_256_CBC_SHA 0x0035
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA 0x000a

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#define NIP6(addr) \
    ntohs((addr).s6_addr16[0]), \
    ntohs((addr).s6_addr16[1]), \
    ntohs((addr).s6_addr16[2]), \
    ntohs((addr).s6_addr16[3]), \
    ntohs((addr).s6_addr16[4]), \
    ntohs((addr).s6_addr16[5]), \
    ntohs((addr).s6_addr16[6]), \
    ntohs((addr).s6_addr16[7])





struct handshake{
    u_char handshake_type;
    u_char layer_two_len[3];
    u_char version[2];
    u_char rand[32];
    u_char session_id_len;
    u_char session_id[32]; //according to the trace, the length is all 32 bytes
    u_char cipher_suit[2];
};

struct tls_hdr{
    u_char Opaque_Type;
    u_char version[2];
    u_char total_len[2];
    //u_short total_len; 
    //struct handshake;
};
