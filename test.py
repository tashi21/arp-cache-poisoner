import socket
import netifaces

# Get the default gateway IP address
gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]
subnet_mask = ""
# Get the subnet mask of the interface that has the gateway IP address
interfaces = netifaces.interfaces()
for interface in interfaces:
    addrs = netifaces.ifaddresses(interface)
    print(addrs)
    if netifaces.AF_INET in addrs:
        for addr in addrs[netifaces.AF_INET]:
            if 'netmask' in addr and addr['addr'] == gateway_ip:
                subnet_mask = addr['netmask']
                break

# Print the subnet mask
print(f"Subnet mask: {subnet_mask}")


# Replace 'WIFI_NETWORK_NAME' with the name of the Wi-Fi network you are connected to
wifi_network_name = 'Ashoka_Students'
local_ip = ""

# Get the IP address of the default network interface for the specified Wi-Fi network
interfaces = netifaces.interfaces()
for interface in interfaces:
    addrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in addrs:
        for addr in addrs[netifaces.AF_INET]:
            if 'broadcast' in addr and addr['broadcast'] == f"{wifi_network_name}.local":
                local_ip = addr['addr']
                break

# Print the local IP address
print(f"Local IP address: {local_ip}")
