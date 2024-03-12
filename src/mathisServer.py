from scapy.all import *

a = sniff(filter="icmp", count=2)
a.nsummary()
print(a[1])
