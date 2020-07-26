#!/usr/bin/env python

import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP or IP range.")
    (options, arguments) = parser.parse_args()
    return options


def scan(ip):
    # especify the network
    arp_request = scapy.ARP(pdst=ip)

    # where we are going to sent de question
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_package = broadcast / arp_request

    # send the package
    answered = scapy.srp(final_package, timeout=1, verbose=False)[0]

    devices_list = []
    for elem in answered:
        device_dict = {"ip": elem[1].psrc, "mac": elem[1].hwsrc}
        devices_list.append(device_dict)
    return devices_list


def print_result(results):
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    for device in results:
        print(device["ip"] + "\t\t" + device["mac"])


options = get_arguments()
result = scan(options.target)
print_result(result)
