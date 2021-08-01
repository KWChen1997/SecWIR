#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define CERT_START	"-----BEGIN CERTIFICATE-----\n"
#define CERT_END	"-----END CERTIFICATE-----\n"

#define OPENSSLDIR	"/etc/ssl/certs/"

static const unsigned char base64_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char ca_dir[] = OPENSSLDIR;
static X509_STORE	*store		= NULL;

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
			      size_t *out_len)
{
	unsigned char *out, *pos;
	const unsigned char *end, *in;
	size_t olen;
	int line_len;

	olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
	olen += olen / 64; /* line feeds */
	olen++; /* nul termination */
	if (olen < len)
		return NULL; /* integer overflow */
	out = malloc(olen * sizeof(unsigned char));
	if (out == NULL)
		return NULL;

	end = src + len;
	in = src;
	pos = out;
	line_len = 0;
	while (end - in >= 3) {
		*pos++ = base64_table[in[0] >> 2];
		*pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		*pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
		*pos++ = base64_table[in[2] & 0x3f];
		in += 3;
		line_len += 4;
		if (line_len >= 64) {
			*pos++ = '\n';
			line_len = 0;
		}
	}

	if (end - in) {
		*pos++ = base64_table[in[0] >> 2];
		if (end - in == 1) {
			*pos++ = base64_table[(in[0] & 0x03) << 4];
			*pos++ = '=';
		} else {
			*pos++ = base64_table[((in[0] & 0x03) << 4) |
					      (in[1] >> 4)];
			*pos++ = base64_table[(in[1] & 0x0f) << 2];
		}
		*pos++ = '=';
		line_len += 4;
	}

	if (line_len)
		*pos++ = '\n';

	*pos = '\0';
	if (out_len)
		*out_len = pos - out;
	return out;
}

size_t certlen(unsigned char *slen){
	return ((int)slen[0] << 16) + ((int)slen[1] << 8) + ((int)slen[2]);
}

char* extractCA(unsigned char* payload, unsigned long payload_len){
	char* cert;
	unsigned char* content;
	size_t o_len = 0;
	
	content = base64_encode(payload+3,certlen(payload),&o_len);
	
	cert = (char*)malloc((o_len + 55) * sizeof(char));
	strcpy(cert,CERT_START);
	strncat(cert,(char *)content,o_len);
	strcat(cert,CERT_END);

	return cert;
}

int verify(unsigned char* payload, unsigned long payload_len, const char *openssldir){
	
	char *certStr = NULL;
	
	BIO		*crtmbio 	= NULL;
	BIO		*outbio		= NULL;
	X509		*cert		= NULL;
	X509		*tmpcert	= NULL;
	X509		*err_cert	= NULL;
	X509_STORE_CTX	*vrfy_ctx	= NULL;
	STACK_OF(X509)	*immCert	= NULL;

	X509_NAME	*certsubject	= NULL;

	int ret;

	// These function calls initialize openssl for correct work.
	
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	// Create the I/O bio object
	
	crtmbio	= BIO_new(BIO_s_mem());
	outbio 	= BIO_new_fp(stderr, BIO_NOCLOSE);

	// initialize the global certificate validation store object
	if(!store){
		if(!(store = X509_STORE_new()))
			BIO_printf(outbio, "Error creating X509_STORE object\n");
	
		// Store CA from file to x509 store ctx object
		
		if(!(ret = X509_STORE_load_locations(store, NULL, openssldir)))
			BIO_printf(outbio,"Error loading root Certificates\n");
	}

	// Create the context structure for validation operation

	if( !(vrfy_ctx = X509_STORE_CTX_new()))
		BIO_printf(outbio, "Error creating X509_STORE_CTX object\n");
	
	// Initialize the untrusted CA stack
	
	immCert = sk_X509_new_null();
	
	// Read payload into BIO object
	int certCount = 0;
	int pos = 0;
	while(pos < payload_len){
		certStr = extractCA(payload + pos,certlen(payload + pos));
		pos += 3 + certlen(payload + pos);
		ret = BIO_puts(crtmbio,certStr);
		free(certStr);
		certCount++;
	}
	
	cert = PEM_read_bio_X509(crtmbio,0,0,0);
	certsubject = X509_NAME_new();
	certsubject = X509_get_subject_name(cert);
	BIO_printf(outbio, "Server Cert:\n");
	X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
	BIO_printf(outbio, "\n");
	BIO_printf(outbio, "\n");

	certCount--;
	while((tmpcert = PEM_read_bio_X509(crtmbio,0,0,0))){	// Push the certificate chain to intermediate cert stack
		certsubject = X509_NAME_new();
		certsubject = X509_get_subject_name(tmpcert);
		BIO_printf(outbio, "Intermediate Cert %d:\n",certCount);
		X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
		BIO_printf(outbio, "\n");
		BIO_printf(outbio, "\n");

		sk_X509_push(immCert,tmpcert);
		certCount--;
	}

	// Load the unverified certificate
	

	// Print out the information about the unverified certificate
	
	// certsubject = X509_NAME_new();
	// certsubject = X509_get_subject_name(cert);
	// X509_NAME_print_ex(outbio,certsubject,0,XN_FLAG_MULTILINE);
	// BIO_puts(outbio,"\n");

	// Initialize the ctx structure for a verification operation:
	// Set the trusted cert store, the unvalidated cert, and any potnetial certs that could be needed
	
	X509_STORE_CTX_init(vrfy_ctx,store,cert,immCert);

	// Check the complete cert chain can be build and validated.
	
	ret = X509_verify_cert(vrfy_ctx);

	if( ret == 0 || ret == 1)
		BIO_printf(outbio, "Verification result: %s\n",
				X509_verify_cert_error_string(X509_STORE_CTX_get_error(vrfy_ctx)));
	
	if(ret == 0){
		err_cert  = X509_STORE_CTX_get_current_cert(vrfy_ctx);
		certsubject = X509_NAME_new();
		certsubject = X509_get_subject_name(err_cert);
		BIO_printf(outbio, "Verification failed cert:\n");
		X509_NAME_print_ex(outbio, certsubject, 0, XN_FLAG_MULTILINE);
		BIO_printf(outbio, "\n");
	}

	// free up all structures
	sk_X509_free(immCert);
	X509_STORE_CTX_free(vrfy_ctx);
	X509_free(cert);
	BIO_free_all(crtmbio);
	BIO_free_all(outbio);
	return ret;
}

int main(int argc, char *argv[]){
	int opt;
	int len;
	char *certs = NULL;
	char *openssldir = ca_dir;
	if(argc < 2){
		fprintf(stderr,"Usage: %s [-p trusted directory] <certificate payload>\n", argv[0]);
		exit(-1);
	}
	while((opt = getopt(argc,argv, "p:")) != -1){
		switch(opt){
			case 'p':
				len = strlen(optarg) + 1;
				openssldir = (char*)malloc(len*sizeof(char));
				strncpy(openssldir,optarg,len);
				break;
			default:
				fprintf(stderr,"Usage: %s [-p trusted directory] <certificate payload>\n", argv[0]);
				exit(-1);
				break;
		}
	}

	if(optind == argc){
		fprintf(stderr,"Error: No binary file is given\n");
		exit(-1);
	}

	FILE *fileptr = NULL;
	unsigned long filelen = 0;
	unsigned char *payload = NULL;
	unsigned int valid_count = 0;
	unsigned int invalid_count = 0;
	int ret;
	do{
		fileptr = fopen(argv[optind],"rb");
		if(fileptr == NULL){
			fprintf(stderr,"Failed to open %s\n",certs);
			exit(-1);
		}
		fseek(fileptr,0,SEEK_END);
		filelen = ftell(fileptr);
		rewind(fileptr);
		
		fprintf(stderr,"Verify binary file: %s:\nFile length: %lu\n",argv[optind],filelen);

		payload = (unsigned char*)malloc(filelen * sizeof(unsigned char));
		fread(payload,filelen,1,fileptr);
		fclose(fileptr);
		
		ret = verify(payload,filelen,openssldir);
		if(ret == 1)
			valid_count++;
		else
			invalid_count++;
		optind++;
	}while((optind < argc) && (fprintf(stderr,"\n-----------------------------\n\n")));
	fprintf(stdout,"\nTotal verification count:\t%d\nValid:\t\t\t\t%d\nInvalid:\t\t\t%d\n", valid_count + invalid_count, valid_count, invalid_count);
	free(store);
	return 0;
}
