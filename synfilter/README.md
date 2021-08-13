# SynFilter
## Part 1: kernel module
- Goal: redirect the tcp syn packets to NFQUEUE with queue number 1
- Related Files:
	- syndrv/syndrv.c
	- syndrv/syndrv.h
- How to compile the kernel module
```sh=
# In the project dir
# The module will be stored in syndrv dir
make kernel

# In the syndrv dir
make
```

- How to install the kernel module
```sh=
sudo insmod syndrv.ko
```

- How to uninstall the kernel module
```sh=
sudo rmmod syndrv
```

- Where to show the debugging message from kernel module
```sh=
dmesg
```

- Sample Output
```
[52339.871851] kernel module syndrv start!
[52339.871852] nf_register_hook returnd 0
[52340.793154] A syn request is captured!
[52341.792331] A syn request is captured!
[52343.792236] A syn request is captured!
[52347.807281] A syn request is captured!
...
[52383.891605] kernel module syndrv exit!
```

## Part 2: user program in C
- Goal: show the source IP and the initial window size of tcp three way handshake
- Library dependency
	- libnetfilter-queue: version 1.0.3
- Related Files:
	- filter/filter.c
	- filter/filter.h
- How to compile the program
```sh=
# In the project dir
# The program will be stored in filter dir
make user

# In the filter dir
make
```

- Sample Output
```
opening library handle
unbinding existing nf_queue handler for AF_INET (if any)
binding nfnetlink_queue as nf_queue handler for AF_INET
binding this socket to queue '0'
setting copy_packet mode
source address=10.42.0.205 window size=14600
source address=10.42.0.205 window size=14600
source address=10.42.0.205 window size=14600
source address=10.42.0.205 window size=14600
source address=10.42.0.205 window size=14600
source address=10.42.0.118 window size=14000
source address=10.42.0.205 window size=14600
...
```

## Part 3: user program in Python
- Goal: show the entire syn packet of the tcp three way handshake
- Related File:
	- filter/filter.py
- Library Dependency:
	- netfilterqueue
	- scapy
- netfilterqueue library installation:
```sh=
# pip install netfilterqueue is not working for my case
# Therefore, the following is an alternative method to 
# install netfilterqueue which works fine for me

pip install -U git+https://github.com/kti/python-netfilterqueue
```

- Sample Output
```
start!
###[ IP ]###
  version   = 4
  ihl       = 5
  tos       = 0x0
  len       = 60
  id        = 42329
  flags     = DF
  frag      = 0
  ttl       = 64
  proto     = tcp
  chksum    = 0x8041
  src       = 10.42.0.205
  dst       = 10.42.0.1
  \options   \
###[ TCP ]###
     sport     = 41923
     dport     = telnet
     seq       = 2639332072
     ack       = 0
     dataofs   = 10
     reserved  = 0
     flags     = S
     window    = 14600
     chksum    = 0xc59
     urgptr    = 0
     options   = [('MSS', 1460), ('SAckOK', b''), ('Timestamp', (8497387, 0)), ('NOP', None), ('WScale', 4)]

None
```

## Part 4: capture.sh
- this shell scipt will install kernel module and start the filter program
- when the script stops with SIGINT it will also remove the kernel module

## Notes
- Simply typing `make` in the project dir will compile both syndrv and filter
- For part 2 and 3, both program should run as root
- The NFQ_NUM in both syndrv.c and filter.c is the target queue the module and program will utilize
