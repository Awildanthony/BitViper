import socket
import struct
from general import *

# Function to generate indentation strings dynamically
indent = lambda n: '\t' * n + ' - '
data_tab = lambda n: '\t' * n + '   '

# Dictionary for protocol number -> protocol name mapping
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    8: "IPv4",
    17: "UDP",
    80: "HTTP"
    # Add more protocols as needed
}


# Modify your ethernet_frame function to return protocol name along with number
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    proto_name = PROTOCOLS.get(socket.htons(proto), str(socket.htons(proto)))
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), proto_name, data[14:]


# Unpack IPv4 packet
def ipv4_packet(data): 
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Returns properly-formatted IPv4 address
def ipv4(addr):
    return '.'.join(map(str, addr))


# Unpack ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment
def tcp_segment(data):
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dst_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Unpack UDP segment
def udp_segment(data):
    src_port, dst_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dst_port, size, data[8:]
