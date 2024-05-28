import re
import socket
import struct
from urllib.parse import urlparse
from typing import Optional, Union


# Most recent HTTP(S) domain name.
recent_domain = None

# Dictionary for protocol names.
PORT_TO_PROTOCOL = {
    1:      "ICMP",
    6:      "TCP",
    8:      "IPv4",
    17:     "UDP",
    53:     "DNS",
    80:     "HTTP",
    443:    "HTTPS",
    1544:   "ARP",
    56710:  "DNS"
}

# Dictionary for DNS record types.
DNS_TYPES = {
    1:   "A",     # ipv4
    2:   "NS",
    5:   "CNAME",
    15:  "MX",
    28:  "AAAA",  # ipv6
    33:  "SRV",
    65:  "HTTPS"
}


def get_proto_name(port: int) -> str:
    """
    Match `port` number to protocol.
    If none, return `port` as a string.
    """
    return PORT_TO_PROTOCOL.get(port, str(port))
    
def get_dns_type(record: int) -> str:
    """
    Match `record` number to DNS type.
    If none, return `record` as a string.
    """
    return DNS_TYPES.get(record, str(record))

def digits_in(s: str) -> bool:
    """
    Returns whether `s` contains one of "0123456789".
    """
    return any(character.isdigit() for character in s)

def str_mac(mac_addr: bytes) -> str:
    """
    Converts `mac_addr` from bytes to a string.
    """
    byte_str = map('{:02x}'.format, mac_addr)
    mac_str = ':'.join(byte_str).upper()
    return mac_str

def ethernet_frame(packet_header: bytes) -> tuple[str, str, str, bytes]:
    """
    Extracts the destination MAC address, source MAC address, protocol name, 
    and payload data from a network packet into an Ethernet frame.
    """
    header_info = packet_header[:14]
    payload = packet_header[14:]
    dst_mac, src_mac, proto = struct.unpack("! 6s 6s H", header_info)
    proto_name = get_proto_name(socket.htons(proto))
    return str_mac(dst_mac), str_mac(src_mac), proto_name, payload

def unpack_ipv4(data: bytes) -> tuple[int, int, int, int, str, str, bytes]:
    """
    Unpacks an IPv4 packet (at the Ethernet layer) by extracting its
    IP version (always 4), header length, time-to-live (TTL), protocol, 
    source IP address, destination IP address, and payload data.
    """
    ver_hdr_len = data[0]
    ver = ver_hdr_len >> 4
    hdr_len = (ver_hdr_len & 15) * 4
    payload = data[hdr_len:]
    ttl, proto, src_ip, dst_ip = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    src_ip, dst_ip = ".".join(map(str, src_ip)), ".".join(map(str, dst_ip))
    return ver, hdr_len, ttl, proto, src_ip, dst_ip, payload

def unpack_icmp(data: bytes) -> tuple[int, int, int, bytes]:
    """
    Unpacks an identified ICMP packet by extracting its ICMP type, code,
    checksum, and payload data.
    """
    header_info = data[:4]
    payload = data[4:]
    icmp_type, code, checksum = struct.unpack("! B B H", header_info)
    return icmp_type, code, checksum, payload

def unpack_tcp(data: bytes) -> tuple[int, int, int, int, int, int, int, 
                                     int, int, int, Optional[str], 
                                     Optional[str], Optional[str], str]:
    """
    Unpacks an identified TCP packet by extracting its source port,
    destination port, sequence number, acknowledgement number, TCP
    flags, HTTP method and url (if applicable), and payload data.
    """
    # Unpack the TCP packet according to its known architecture.
    src_port, dst_port, \
        seq, ack, tcp_flags = struct.unpack("! H H L L H", data[:14])

    # Reserved TCP flags are offset; un-offset them.
    offset = (tcp_flags >> 12) * 4
    flag_urg = (tcp_flags & 32) >> 5
    flag_ack = (tcp_flags & 16) >> 4
    flag_psh = (tcp_flags & 8) >> 3
    flag_rst = (tcp_flags & 4) >> 2
    flag_syn = (tcp_flags & 2) >> 1
    flag_fin = (tcp_flags & 1)

    # Checking conventional ports (e.g., 80/443 for HTTP(S) data) is a
    # necessary but not sufficient condition for supporting said protocol.
    http_method, http_url, status_code = parse_http_data(data[offset:])

    # Packet contains HTTP(S) data; distinguish response vs request.
    display_data = ""
    if http_method and http_url:
        if status_code:
            display_data = f"{http_method} {http_url} {status_code}"
        else:
            display_data = f"{http_method} {http_url}"

    return src_port, dst_port, seq, ack, \
           flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
           http_method, http_url, status_code, display_data

def set_tcp_flags(urg, ack, psh, rst, syn, fin):
    """
    Takes in the TCP flags as arguments and returns a string 
    containing the names of the flags that are set.
    """
    flags = [urg, ack, psh, rst, syn, fin]
    flag_names = ["URG", "ACK", "PSH", "RST", "SYN", "FIN"]
    set_flags = [flag_names[i] for i in range(len(flags)) if flags[i] == 1]
    return "[" + ", ".join(set_flags) + "]"


def unpack_udp(data: bytes) -> tuple[int, int, int, bytes]:
    """
    Unpacks an identified UDP packet by extracting its
    source port, destination port, size, and payload data.
    """
    header_info = data[:8]
    payload = data[8:]
    src_port, dst_port, size = struct.unpack("! H H 2x H", header_info)
    return src_port, dst_port, size, payload

def format_dns_data(dns_data: bytes) -> str:
    """
    Formats DNS packet data into a human-readable string to
    eventually be displayed in the GUI's "Data" column.
    """
    transaction_id, flags, questions, answer_rrs, authority_rrs, \
        additional_rrs = struct.unpack('! H H H H H H', dns_data[:12])
    data = dns_data[12:]
    q_name, q_type, q_class, data = parse_dns_question(data)
    q_type = get_dns_type(q_type)
    answers = []
    cnames = ''
    for _ in range(answer_rrs):
        a_type, data, answer = parse_dns_answer(data)
        answers.append(answer)
        if get_dns_type(answer['Type']) == "CNAME":
            cnames += f' CNAME {answer["RD Data"]}'

    if flags & 0x8000:
        return (f'Standard query response 0x{transaction_id:04X} '
                f'{q_type} {q_name}{cnames}')
    else:
        return (f'Standard query 0x{transaction_id:04X} '
                f'{q_type} {q_name}{cnames}')

def parse_dns_name(data: bytes) -> tuple[str, bytes]:
    """
    Parses DNS name data to extract the domain name and remaining data.
    """
    labels = []
    while data:
        length, = struct.unpack('! B', data[:1])
        if length == 0:
            data = data[1:]
            break
        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack('! H', data[:2])
            offset = pointer & 0x3FFF
            data = data[2:]
            if offset < len(data):
                labels.append(parse_dns_name(data[offset:])[0])
            break
        else:
            try:
                labels.append(data[1:1 + length].decode())
            # Ignore labels that cannot be decoded.
            except UnicodeDecodeError:
                pass
            data = data[1 + length:]
    return '.'.join(labels), data

def parse_dns_question(data: bytes) -> tuple[str, int, int, bytes]:
    """
    Parses DNS question data to extract the question name, 
    type, class, and remaining data.
    """
    q_name, data = parse_dns_name(data)
    q_type, q_class = struct.unpack('! H H', data[:4])
    return q_name, q_type, q_class, data[4:]

def parse_dns_answer(data: bytes) -> tuple[int, bytes, dict[str, Union[str, int]]]:
    """
    Parses DNS answer data to extract the answer type, class, time-to-live (TTL), 
    resource data length, resource data, and remaining data.
    """
    a_name, data = parse_dns_name(data)
    a_type, a_class, a_ttl, a_rdlength = struct.unpack('! H H I H', data[:10])
    a_rdata, data = data[10:10 + a_rdlength], data[10 + a_rdlength:]
    if get_dns_type(a_type) == "CNAME":
        a_rdata = parse_dns_name(a_rdata)[0]
    return a_type, data, {'Name': a_name, 
                          'Type': a_type, 
                          'Class': a_class, 
                          'TTL': a_ttl, 
                          'RD Length': a_rdlength, 
                          'RD Data': a_rdata}

def parse_http_data(data: bytes) -> tuple[Optional[str], 
                                          Optional[str], 
                                          Optional[str]]:
    """
    Parses HTTP data to extract the HTTP method, URL, and status code.
    """
    global recent_domain

    http_method, http_url, status_code = None, None, None
    try:
        decoded_data = data.decode('utf-8')
    except UnicodeDecodeError:
        return http_method, http_url, status_code
    
    if not decoded_data or decoded_data.isspace():
        return http_method, http_url, status_code

    lines = decoded_data.split('\r\n')
    if lines:
        request_line = lines[0].split(' ')
        if len(request_line) >= 2:
            http_method = request_line[0]
            parsed_url = urlparse(request_line[1])

            # Distinguish an HTTP(S) request vs HTTP(S) response.
            if not recent_domain:
                recent_domain = parsed_url.netloc
                http_url = recent_domain
            else:
                http_url = recent_domain
                recent_domain = None

        for line in lines:
            if line.startswith('HTTP'):
                status_parts = line.split(' ', 2)
                status_code = status_parts[1]
                if len(status_parts) > 2:
                    status_code += ' ' + status_parts[2]

            # Extract host from the "Host" header.
            host_match = re.match(r'Host:\s*(.*)', line)
            if host_match:
                recent_domain = host_match.group(1).strip()
                http_url = recent_domain

    return http_method, http_url, status_code

def filter_non_hex(s: str) -> str:
    """
    TODO: fix if this is necessary, or remove if not.

    Shitty work-around that might be unnecessary altogether.
    Filters non-hexadecimal characters from a string.
    """
    # May not work properly if "\"" or "x" aren't used to designate a byte ...
    return ''.join(c for c in s if c in '0123456789abcdexfABCDEF\\\'')
