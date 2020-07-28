# Ethical-Hacking

Some scrpits to get started in ethical hacking with python.
For all of them there are other easier ways to approach but the point here is to understand deep down what is going on and to learn python.

# Mac Changer (mac_changer.py)

  - This simple program allows to change the MAC address specifyng the interface.
  - The objetive is achieved by using the **subprocess** library to be able to execute shell commands.

# Network Scanner (network_scanner.py)

  - This network scanner allows you to specify an IP address or an IP range and then scan that network in search for the devices that are connected to it.
  - It specifies the IP address and the MAC address of each device founded.
  - The objetive is achieved by using the **scapy** library  and sending an ARP request in broadcast.
  - That is similar to use the **netdiscover** command.

# ARP Spoofer (arp_spoof.py)

  - This ARP spoofer allows you to specify a target and a router and perfoms the attack 'ARP spoofing'.
  - This is made by poisoning the ARP tables of the target and the router.
  - The objetive is achieved by using the **scapy** library  and sending an ARP responses to both router and target.
  - That is similar to use the **arpspoof** tool.
  - This attack can be performed due to the insecurity of the ARP protocol: It allows that clients accept responses even though they didn't make any request, and the clients just trust the responses they get without any kind of verification.


# Packet Sniffer (packet_sniffer.py)

  - Once you become the woman in the middle with ARP Spoofing (for exemple), this program allows you to sniff the packets.
  - It designed to sniff the http packets but it can be modified to add other filters.
  - The objetive is achieved by using the **scapy** library  and sending an ARP responses to both router and target.
  - That is similar to use the **arpspoof** tool.
  - This attack can be performed due to the insecurity of the ARP protocol: It allows that clients accept responses even though they didn't make any request, and the clients just trust the responses they get without any kind of verification.
