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
	```sh=
	# if port == -1, conntrack does not give the port number about the traffic
	type       ip1             port1   ip2             port2      packets      bytes
	tcp        192.168.24.14   22      192.168.24.125  12214         1368     112064
	udp        192.168.24.38   5353    224.0.0.251     5353             3        354
	udp        192.168.24.127  9999    255.255.255.255 9999             1         57
	unknown    192.168.24.38   -1      224.0.0.251     -1               1         32
	unknown    0.0.0.0         -1      224.0.0.1       -1               1         32
	```

