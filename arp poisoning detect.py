import scapy.all as scapy
from collections import defaultdict

pkts = scapy.rdpcap('ettercap2.pcap')

addr_dict = defaultdict(list)

for packet in pkts:
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
		#print(packet[scapy.ARP])
		print("psrc:", packet[scapy.ARP].psrc)
		print("hwsrc:", packet[scapy.ARP].hwsrc)
		print('\n')
		if packet[scapy.ARP].hwsrc not in addr_dict[packet[scapy.ARP].psrc]:
			if not addr_dict[packet[scapy.ARP].psrc]:
				addr_dict[packet[scapy.ARP].psrc].append(packet[scapy.ARP].hwsrc)
			else:
				addr_dict[packet[scapy.ARP].psrc].append(packet[scapy.ARP].hwsrc)
				print('[*] ALERT!!! You are under attack, ARP table is being poisoned.!\n')
				print('Original MAC adress :',addr_dict[packet[scapy.ARP].psrc][0])
				
print('\n', dict(addr_dict),'\n')

