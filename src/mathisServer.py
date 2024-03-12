from scapy.all import *

a = sniff(filter="icmp", count=2)
#a.nsummary()
receivedMessage = a[1][3].fields.get("load").decode("utf-8")

print("receivedMessage : "+receivedMessage)

