"""
    utility functions
"""
from scapy.config import conf
from scapy.layers.l2 import ARP
from scapy.sendrecv import sr

conf.iface = "en0"
conf.verb = 0
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def get_mac(ip: str) -> None | str:
    """
        Get the MAC address of the given IP address

        Broadcast ARP request for a IP address. Should recieve an ARP
        reply with MAC Address
    """
    answered, _ = sr(  # send/receive a layer 3 packet
        ARP(
            op=1,  # request MAC for destination IP
            hwdst=BROADCAST_MAC,  # request from every host
            pdst=ip  # destination IP
            # source MAC is this host
        ),
        retry=2,
        timeout=10
    )

    for _, packet in answered:
        return packet[ARP].hwsrc  # MAC of IP
    return None
