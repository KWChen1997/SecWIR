# SynFilter
## Part 1: kernel module
- Goal: redirect the tcp syn packets to NFQUEUE
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

## Part 2: user program in C
- Goal: show the source IP and the initial window size of tcp three way handshake
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

## Notes
- Simply typing `make` in the project dir will compile both syndrv and filter
- For part 2 and 3, both program should run as root

