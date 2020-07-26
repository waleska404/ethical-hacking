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
