from netfilterqueue import NetfilterQueue
#import pyshark
import os
import sys
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapWriter, PcapWriter, PcapReader
import pyshark

from scapy.layers import *
import socket
from cryptography import x509
import codecs
import re
import OpenSSL.crypto 
import json

#############################
# verification section
#############################

# Read public key from file
fd = open('CA-cert.pem', 'r') #
cert_data = fd.read()
fd.close()
trustedcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)

# extract certificate chain from TLS handshake
def get_certs(tls_pkt):
    tls_pkt = str(tls_pkt)
    x = re.findall("certificate[:] [0-9a-z]{2}(?::[0-9a-z]{2}){10,}",tls_pkt)
    binary_pem = map(lambda x:x.replace("certificate: ",'').replace(':',''),x)
    b64 = map(lambda x:\
            "-----BEGIN CERTIFICATE-----\n" + \
            codecs.encode(codecs.decode(x,'hex'),'base64').decode() + \
            "-----END CERTIFICATE-----\n",\
            binary_pem)
    b64 = list(b64)
    cert_list = map(lambda x:OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, x), b64)
    print(b64[0])
    return list(cert_list)

   

# load saved traces
def verify():

    data = pyshark.FileCapture("test.pcap",display_filter='tls.handshake.certificate',use_json = True)



    for pkt in data:
        x = get_certs(pkt['TLS'])
        x509store = OpenSSL.crypto.X509Store()

        x509store.add_cert(trustedcert)

        for cert in reversed(x[:-1]):
            x509store.add_cert(cert)

        print("Expired? " + str(x[0].has_expired()))
        store_ctx = OpenSSL.crypto.X509StoreContext(x509store, x[0])

        try:
            store_ctx.verify_certificate()
        except:
            #print("Verify failed!")
            return False
        else:
            #print("Verify pass!")
            return True

#############################
# packet handling section 
#############################
#create a new file
filename = "test.pcap"

f = open(filename, "w")
f.close()

tls_accum = False
packettoread = -1
tls_blist = list()

writer = PcapWriter(filename, append=True, sync = True)

def checkTLS():
    global tls_blist
    tls_raw = b''.join(tls_blist)
    tls = TLS(tls_raw)
    out = tls.show(dump = True)
    return 'server_hello_done' in out
    

def print_and_accept(pkt):
    global tls_accum
    global tls_blist
    global writer
    _pkt = IP(pkt.get_payload())
    # accumulate the tls handshake packets
    if tls_accum and _pkt.haslayer(TCP):
        print('TLS fragment collecting...')
        tls_blist.append(raw(_pkt[TCP].payload))
        writer.write(_pkt)
        # check if the handshake has finished`
        if checkTLS():
            tls_accum = False
            print('Handshake Complete!')
            print('Start verifying...')
            valid = verify()
            if valid:
                print('Verify Success!')
            else:
                print('Verify Failed!')
            
    # check if it is the first tle handshake packet
    elif _pkt.haslayer(TCP) and _pkt.haslayer(TLS):
        print('First TLS fagment...')
        print(_pkt[TCP].mysummary())
        #print('create new pcap file')
        f = open(filename,'w')
        f.close()
        
        writer = PcapWriter(filename, append=True, sync = True)
        tls_accum = True
        tls_blist = list()
        tls_blist.append(raw(_pkt[TCP].payload))
        writer.write(_pkt)
        # check if the handshake has finished`
        if checkTLS():
            tls_accum = False
            print('Handshake Complete!')
            print('Start verifying...')
            valid = verify()
            if valid:
                print('Verify Succes!')
            else:
                print('Verify Failed!')
    else:
        writer.write(_pkt)
    #print(pkt.lastlayer())
    pkt.accept()
    
print("start!")
load_layer("tls")
nfqueue = NetfilterQueue()
nfqueue.bind(0, print_and_accept)


try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
