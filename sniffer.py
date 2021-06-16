from scapy.all import *
from scapy.layers.http import *
import sys
import argparse

parser = argparse.ArgumentParser(description="Owncast Packet Interceptor")
parser.add_argument("-dst", default="191.168.56.103")
parser.add_argument("-port", default="8080")
parser.add_argument("-fake", default="")
parser.add_argument("-fake_port", default="")
args = parser.parse_args()

host = args.dst
port = args.port
fake = args.fake
fake_port = args.fake_port

# By default we use the destination (the real owncast) as the fake host but assume the port is different, this is true in our testing model
if fake == "":
    fake = host
if fake_port == "":
    fake_port = port

print(f"Binding port {port} as an HTTP connection port")
bind_layers(TCP, HTTP, dport=int(port))
bind_layers(TCP, HTTP, sport=int(port))

print(f"Redirecting stream on {host}:{port} to {fake}:{fake_port}")

def print_pkt(pkt):
    if not pkt.haslayer(HTTPRequest):
        return
            
    http = pkt[HTTPRequest]
    path = http.Path.decode()
    print(f"Got packet with path {path}")
    
    if not 'stream.m3u8' in path:
        return
    
    pkt.show()

filter = "dst host " + host + " and dst port " + port
print(f"Filtering packets on {filter}")
pkt = sniff(filter=filter, prn=print_pkt)