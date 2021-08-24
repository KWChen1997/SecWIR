# Validate certificate using OpenSSL in C
- Library Dependency
	- libssl-dev
- CertVerifier
	- usage with a binary file:
	   ```=sh
	   ./CertVerifier [-p openssl trusted directory] <certificate payload>
	   ```
	- usage with an integrated function: 
		```=c
		int verify(unsigned char *, unsigned long, const char*)
		```
	  - parameters:
		  - payload of the tls certificate packet (only the payload of the tls handshake certificate but ot the entire handshake)
		  - length of the payload(bytes)
		  - openssl trusted directory
	- Compilation command
	   ```=sh
	   gcc -o CertVerifier CertVerifier.c -lssl -lcrypto
	   ```
	- More details are in the comment section of the code.
- Openssl
	- How to get openssl trusted directory?
	  ```=sh
	  openssl version -d
	  ``` 
	- How to add self-signed CA to the trusted directory?
		- make sure the file is a crt file
		- copy self-signed CA to /usr/local/share/ca-certificates/
		- update the trusted directory (If the verify function is integrated, it should be reinitialized)
		```=sh
		sudo update-ca-certificates
		```
- Examples
	- Success Case: Verifying the certificate of e3.nycu.edu.tw:443 (Certificate payload: cert1.bin)
		```=sh
		./CertVerifier -p /etc/ssl/certs ./keys/cert1.bin 
		```
		The verification result is expected to be the same as the following openssl command. --> Verification success
		```=sh
		openssl s_client -connect e3.nycu.edu.tw:443 -tls1_2
		```
	- Failure Case: Verifying a self-signed certificate (Certificate payload: cert2.bin)
		```=sh
		./CertVerifier -p /etc/ssl/certs ./keys/cert2.bin 
		```
		Verification result --> Failure: Unable to get local issuer certificate

