"""
    sniff for access points
"""
import os
import random
import time
from multiprocessing import Process
from signal import SIGINT, signal

from scapy.config import conf
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11ProbeResp
from scapy.packet import Packet
from scapy.sendrecv import sniff

conf.iface = "en0"
conf.verb = 0


def add_network(pckt: Packet, known_aps: dict) -> None:
    """
        Add an access point to the list of known access points
    """
    bssid = pckt[Dot11].addr3  # MAC address of access point
    print(bssid)
    if bssid in known_aps:
        return  # access point already in list

    essid = "Hidden SSID"
    if pckt[Dot11Elt].info != "" and "\x00" not in pckt[Dot11Elt].info:
        essid = pckt[Dot11Elt].info  # name of access point

    channel = int(ord(pckt[Dot11Elt:3].info))  # channel of access point
    known_aps[bssid] = (essid, channel)  # add access point to known networks
    print("{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid))


def channel_hopper(interface) -> None:
    """
        Hop from one channel to another a network interface has access to
    """
    while True:
        try:
            channel = random.randrange(1, 149)
            print(f"Hopping to channel {channel}")
            os.system(f"airport en0 --channel={channel}")
            time.sleep(1)
        except KeyboardInterrupt:
            break


def stop_channel_hop(sig, frame) -> None:
    """
        Set the stop_sniff variable to True to stop the sniffer
    """
    global STOP_SNIFF
    STOP_SNIFF = True
    channel_hop.terminate()
    channel_hop.join()


def keep_sniffing(pckt: Packet) -> bool:
    """
        Whether to keep sniffing
    """
    return STOP_SNIFF


def filter_packets(packet: Packet) -> None:
    """
        filter packets
    """
    resp = packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)
    print(f"[*] {resp}")
    return resp


if __name__ == "__main__":
    networks = {}
    STOP_SNIFF = False
    print("Press CTRL+C to stop sniffing...")
    print("="*100 + "\n{0:5}\t{1:30}\t{2:30}\n".format(
        "Channel",
        "ESSID",
        "BSSID"
    ) + "="*100)
    channel_hop = Process(target=channel_hopper, args=("en0",))
    channel_hop.start()

    signal(SIGINT, stop_channel_hop)
    # Sniff Beacon and Probe Response frames to extract AP info
    sniff(
        # lfilter=filter_packets,
        stop_filter=keep_sniffing,
        prn=lambda x: add_network(x, networks)
    )
