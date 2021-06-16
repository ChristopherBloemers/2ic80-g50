from scapy.all import *

def print_pkt(pkt): 
    pkt.show() 

pkt = sniff(filter="length == 379", prn=print_pkt)
#and tcp and host 191.168.56.103