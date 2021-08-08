# netflow in C
- How to compile
	```sh=
	gcc -o netflow netflow.c -lnetfilter_conntrack
	
	# Makefile is given
	# You can simply compile with 'make' command
	```
- How to use
	```sh=
	# The program must have root privilege
	sudo ./netflow
	```

- Sample output
	if port == -1, conntrack does not give the port number about the traffic
	```sh=
	type: tcp        ip1: 192.168.24.14   port: 22    ip2: 192.168.24.125  port: 12214 packets:      33831 bytes:    2822280
	type: unknown    ip1: 0.0.0.0         port: -1    ip2: 224.0.0.1       port: -1    packets:         15 bytes:        480
	type: unknown    ip1: 192.168.24.38   port: -1    ip2: 224.0.0.251     port: -1    packets:         13 bytes:        416
	type: tcp        ip1: 192.168.24.14   port: 46558 ip2: 34.122.121.32   port: 80    packets:         11 bytes:        823
	type: unknown    ip1: 192.168.24.1    port: -1    ip2: 224.0.0.251     port: -1    packets:          8 bytes:        256
	```

