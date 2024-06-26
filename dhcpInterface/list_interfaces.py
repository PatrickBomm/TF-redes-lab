import psutil
import socket


def get_network_interfaces():
    interfaces = psutil.net_if_addrs()
    if not interfaces:
        print("No network interfaces found.")
        return

    for interface_name, interface_addresses in interfaces.items():
        print(f"Interface: {interface_name}")
        for address in interface_addresses:
            if str(address.family) == "AddressFamily.AF_INET":
                print(f"  IP Address: {address.address}")
                print(f"  Netmask: {address.netmask}")
                print(f"  Broadcast IP: {address.broadcast}\n")


if __name__ == "__main__":
    print("Listing network interfaces and their IPs:")
    get_network_interfaces()
