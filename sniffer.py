from scapy.all import *
from scapy.layers.http import *
import sys
import argparse

parser = argparse.ArgumentParser(description="Owncast Packet Interceptor")
parser.add_argument("-dst", default="191.168.56.103")
args = parser.parse_args()
host = args.dst

def print_pkt(pkt):
    if not pkt.haslayer(HTTPRequest):
        return
            
    http=pkt[HTTPRequest]
    path=http.Path.decode()
    print(f"Got packet with path {path}")
    
    if not 'stream.m3u8' in path:
        return
    
    pkt.show()

pkt = sniff(filter="dst host " + host, prn=print_pkt)