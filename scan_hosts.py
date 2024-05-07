"""
    scan for hosts on the network
"""

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

# Define the network you want to scan
NETWORK = "10.2.32.0/19"

# Create an ARP request packet to send to the network
arp = ARP(pdst=NETWORK)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether/arp

# Send the packet and get the list of responses
result = srp(packet, timeout=3, verbose=0)[0]

# Extract the IP addresses from the responses
hosts = []
for sent, received in result:
    hosts.append({'ip': received.psrc, 'mac': received.hwsrc})

# Print the list of IP addresses
for host in hosts:
    print("IP address: " + host['ip'])
