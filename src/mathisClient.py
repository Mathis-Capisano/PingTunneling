from scapy.all import sr1,IP,ICMP

p = sr1(IP(dst="www.slashdot.org")/ICMP()/"XXXXXXXXXXX")
