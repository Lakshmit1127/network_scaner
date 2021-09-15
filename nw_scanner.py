#!/usr/bin/python3
#Menu driven network scanning tool:
import nmap
import os
os.system("banner NETSCAN") 


def main_menu():
	print("Enter 1 for Scan single host")
	print("\nEnter 1 for Scan single host")
	print("Enter 2 for scan range")
	print("Enter 3 for Scan network")
	print("Enter 4 for Agressive scan")
	print("Enter 5 for Scan ARP packet")
	print("Enter 6 for Scan All port only")
	print("Enter 7 for Scan in verbose mode")
	print("Enter 8 for exit")
	
def scan_single_host():
	nm = nmap.PortScanner() #Create object of nmap port scannet class
	ip_address = input("\tEnter the IP : ")
	print("Wait.......................")
	try:
		scan = nm.scan(hosts=ip_address,ports="1-2000",arguments = "-v -sS -O -Pn") #Returns Dictionary
		print(scan)
		#print(scan['scan'][ip]['addresses']['mac'])
		print("________single_host__________")
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
			print(f"{port[0]}, {port[1]['state']},{port[1]['reason']} , {port[1]['name']}")
	except:
		print("Use root priviliege")
def scan_range():
	nm = nmap.PortScanner() #Create object of nmap port scannet class
	ip_address = input("\tEnter the IP : ")
	print("Wait.......................")
	try:
		scan = nm.scan(hosts=ip_address,ports="1-2000",arguments = "-sS -O -Pn") #Returns Dictionary
		print(scan)
	
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("Use root priviliege")
def scan_network():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"Name -> {i['name']}")
			print(f"Accuracy -> {i['accuracy']}")
			print(f"OSClass -> {i['osclass']}\n")
	except:
		print("Use root priviliege")
def agressive_scan():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn -T4")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"Name -> {i['name']}")
			print(f"Accuracy -> {i['accuracy']}")
			print(f"OSClass -> {i['osclass']}\n")
	except:
		print("Use root priviliege")
def scan_arp_packet():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -PR")
		print(scan)
	except:
		print("Use root priviliege")
		
def scan_all_port_only():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts = ip_address,ports = "1-3",arguments = "-sS -O -Pn")
		scan = nm.scan(hosts = ip_address,ports = "1-4",arguments = "-sS -O -Pn")
		for port in scan["scan"][ip_address]['tcp'].items():
			print(f"{port[0]}, {port[1]['state']} , {port[1]['name']}")
	except:
		print("Use root priviliege")
def scan_verbose_mode():
	nm = nmap.PortScanner() #create object of nmap port scanner class
	ip_address = input("\tEnter the IP : ")
	print("Wait........................")
	try:
		scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn -v")
		for i in scan["scan"][ip_address]['osmatch']:
			print(f"Name -> {i['name']}")
			print(f"Accuracy -> {i['accuracy']}")
			print(f"OSClass -> {i['osclass']}\n")
	except:
		print("Use root priviliege")
while True:
	main_menu()
	ch =  int(input("Enter choice: "))
	if ch == 1:
		scan_single_host()
		
	elif ch == 2:
		scan_range()
	elif ch ==3:
		scan_network()
	elif ch ==4:
		scan_arp_packet()
	elif ch ==5:
		agressive_scan()
	elif ch ==6:
		scan_all_port_only()
	elif ch ==7:
		scan_verbose_mode()
	elif ch == 8:
		break;
	else:
		print("Wrong Choice")
	
