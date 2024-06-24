from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, get_if_list, get_if_hwaddr, get_if_raw_hwaddr
import psutil

def list_interfaces():
    interfaces = psutil.net_if_addrs()
    friendly_names = {}
    print("Available network interfaces:")
    for name, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:
                friendly_names[addr.address] = name
                print(f" - {addr.address} ({name})")
    return friendly_names

def send_dhcp_discover(interface):
    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(interface), type=0x0800)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=[get_if_hwaddr(interface).replace(':', '')], xid=0x10000000, flags=0x8000)
        / DHCP(options=[("message-type", "discover"), ("end")])
    )
    sendp(dhcp_discover, iface=interface, verbose=True)

def send_dhcp_request(interface, offered_ip):
    dhcp_request = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(interface), type=0x0800)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=[get_if_hwaddr(interface).replace(':', '')], xid=0x10000000, flags=0x8000)
        / DHCP(
            options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("end"),
            ]
        )
    )
    sendp(dhcp_request, iface=interface, verbose=True)

if __name__ == "__main__":
    interface_map = list_interfaces()
    interface_guid = input("Enter the interface GUID you want to use: ").strip()
    interface = interface_map.get(interface_guid)

    if not interface:
        print(f"Interface with GUID {interface_guid} not found.")
    else:
        offered_ip = "192.168.1.100"  # Example IP, change if you know the offered IP

        send_dhcp_discover(interface)
        # Simulate a wait for the offer
        import time
        time.sleep(2)
        send_dhcp_request(interface, offered_ip)
