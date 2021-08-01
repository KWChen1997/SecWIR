# A simple demo on Linux for stream certificate validation.

Due to the time limitation, I haven't tested it on a pc configured as the Wi-Fi router. But the kernel space hook function should work once the hook point/IP address is configured properly (In the demo, I set the hook point on NF_INET_PRE_ROUTING. On the router, the hook point should be set on INET_FORWARD). 


## Setting (tested): 
1. A vitual machine with Ubuntu 20.04 as the primary device. (IP: 192.168.1.10)
2. A vitual machine with Ubuntu 16.04 as the apache2 server that has the https service enabled. (IP: 192.168.1.30) The certificates & keys are stored in the folder `cert`.  


The user space part is implemented by python3, which can be quickly deployed on the pc.  

This demo contains 3 parts.

# Part 1: Kernel Hook Module

The main folder contains the kernel hook module. 
The kernel module can be compiled by
```
make
```
After it succesfully compiles, the kernel module can be installed by
```
sudo insmod mydrv.ko
```
The module can be removed by
```
sudo rmmod mydrv
```
To check the debug message, we can use the command
```
dmesg
```
# Part 2: Verification

The module can be run by
```
sudo python3 verification.py
```
It will get the packet from NF_QUEUE and turn it into pcap file,
then verify the certificate using openssl library
