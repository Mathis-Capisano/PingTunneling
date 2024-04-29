from scapy.all import *
import base64

sniffInterface = "VMware Network Adapter VMnet8"


while True:
    a = sniff(iface=sniffInterface, filter="icmp", count=1)
    receivedMessage = a[0][3].fields.get("load").decode("utf-8")

    print("receivedMessage : "+receivedMessage)

    if receivedMessage == "file":
        # Receive 3 ICMP as 2 firsts are going to be the request and reply from the file name
        # Then, the 3rd one is going to be the request of the file 
        icmpReceived = sniff(iface=sniffInterface, filter="icmp", count=3)
        
        fileName = icmpReceived[0][3].fields.get("load").decode("utf-8")
        base64File = icmpReceived[2][3].fields.get("load")

        print("fileName : "+fileName)
        print("base64File : "+base64File.decode("utf-8"))
        with open(fileName, "wb") as fh:
            fh.write(base64.decodebytes(base64File))
