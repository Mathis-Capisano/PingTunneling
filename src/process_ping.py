#!/bin/python3
from scapy.all import *
import base64
import binascii

def hexToASCII(hexx):
 
    # initialize the ASCII code string as empty.
    ascii = ""
 
    for i in range(0, len(hexx), 2):
 
        # extract two characters from hex string
        part = hexx[i : i + 2]
 
        # change it into base 16 and
        # typecast as the character 
        ch = chr(int(part, 16))
 
        # add this char to final ASCII string
        ascii += ch
     
    return ascii

def response(command):
    print(f"Command is {command}")
    if "$HELP" in command:
        print("1")
        response = "SEND COMMAND $LS $EXE $CAT"
    elif "$LS" in command:
        response = ". .. flag.txt"
    elif "$EXE" in command:
        response = "COMMAND NOT SUPPORTED"
    elif "$CAT flag.txt" in command:
        response = "bj bg"
    else:
        response = ("UKNOWN COMMAND USE $HELP")
    
    return response

def custom_ping_responder(pkt):
    
    if ICMP in pkt and pkt[ICMP].type == 8:  # ICMP Echo Request
            # Analyze the payload of the received packet
        if Raw in pkt:
            received_payload = pkt[Raw].load
            #received_payload = hexdump(received_payload)
            print(type(received_payload))
            received_payload =  binascii.hexlify(received_payload)
            print(received_payload)

            received_payload = received_payload.decode("ascii")
            #print(hexToASCII(received_payload))
            received_payload = hexToASCII(received_payload)
            custom_data = response(received_payload)
            #print(f"Received Payload: {received_payload}")
        print(f"response = {custom_data}")
        print(f"answering to {pkt[IP].src}")
        ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        icmp_layer = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        response_pkt = ip_layer / icmp_layer / custom_data
        send(response_pkt, verbose=0)

if __name__ == "__main__":
    print("Starting server...")
    # Sniff ICMP packets and invoke the custom responder function
    sniff(prn=custom_ping_responder, filter="icmp",iface="lo", store=0)
