import socket
import struct
from urllib.parse import urlparse
import re

# Global var to store the most recent (HTTP/S) domain name
recent_domain = None

# Dictionary for port number -> protocol name mapping
PORT_TO_PROTOCOL = {
    1: "ICMP",
    6: "TCP",
    8: "IPv4",
    17: "UDP",
    80: "HTTP",
    443: "HTTPS"
    # Add more as needed
}

# Dictionary for DNS record types
DNS_TYPES = {
    1: 'A',         # ipv4
    2: 'NS',
    5: 'CNAME',
    15: 'MX',
    28: 'AAAA',     # ipv6
    33: 'SRV',
    65: 'HTTPS'
    # Add more as needed
}


# Returns MAC as string from bytes (e.g., AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


# Modify your ethernet_frame function to return protocol name along with port number
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
    proto_name = PORT_TO_PROTOCOL.get(socket.htons(proto), str(socket.htons(proto)))
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), proto_name, data[14:]


# Unpack IPv4 packet
def unpack_ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
    return version, header_length, ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]


# Returns properly-formatted IPv4 address
def format_ipv4(addr):
    return '.'.join(map(str, addr))


# Unpack ICMP packet
def unpack_icmp(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpack TCP segment
def unpack_tcp(data):
    src_port, dst_port, seq, ack, offset_reserved_flags = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    # Don't just check conventional ports 80/443 for HTTP(S) data
    http_method, http_url, status_code = None, None, None
    http_method, http_url, status_code = parse_http_data(data[offset:])

    # Packet contains HTTP(S) data
    if http_method and http_url:
        # HTTP(S) response
        if status_code:
            data = f"{http_method} {http_url} {status_code}"
        # HTTP(S) request
        else:
            data = f"{http_method} {http_url}"

    return src_port, dst_port, seq, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, http_method, http_url, status_code, data


# Unpack UDP segment
def unpack_udp(data):
    src_port, dst_port, size = struct.unpack("! H H 2x H", data[:8])
    return src_port, dst_port, size, data[8:]


# Format data column for DNS
def format_dns_data(dns_data):
    transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = struct.unpack('! H H H H H H', dns_data[:12])
    data = dns_data[12:]

    q_name, q_type, q_class, data = parse_dns_question(data)

    q_type = DNS_TYPES.get(q_type, q_type)

    answers = []
    cnames = ''
    for _ in range(answer_rrs):
        a_type, answer, data = parse_dns_answer(data)
        answers.append(answer)
        if answer['Type'] == 5:  # CNAME record
            cnames += f' CNAME {answer["RD Data"]}'

    if flags & 0x8000:
        return f'Standard query response 0x{transaction_id:04X} {q_type} {q_name}{cnames}'
    else:
        return f'Standard query 0x{transaction_id:04X} {q_type} {q_name}{cnames}'


def parse_dns_question(data):
    q_name, data = parse_dns_name(data)
    q_type, q_class = struct.unpack('! H H', data[:4])
    return q_name, q_type, q_class, data[4:]


def parse_dns_answer(data):
    a_name, data = parse_dns_name(data)
    a_type, a_class, a_ttl, a_rdlength = struct.unpack('! H H I H', data[:10])
    a_rdata, data = data[10:10 + a_rdlength], data[10 + a_rdlength:]
    if a_type == 5:  # CNAME record
        a_rdata = parse_dns_name(a_rdata)[0]
    return a_type, {'Name': a_name, 'Type': a_type, 'Class': a_class, 'TTL': a_ttl, 'RD Length': a_rdlength, 'RD Data': a_rdata}, data


def parse_dns_name(data):
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
            except UnicodeDecodeError:
                pass  # Ignore labels that cannot be decoded
            data = data[1 + length:]
    return '.'.join(labels), data


def parse_http_data(data):
    global recent_domain

    http_method, http_url, status_code = None, None, None
    try:
        decoded_data = data.decode('utf-8')
    except UnicodeDecodeError:
        return http_method, http_url, status_code
    
    if not decoded_data or decoded_data.isspace():
        return http_method, http_url, status_code

    # print(decoded_data)

    lines = decoded_data.split('\r\n')
    if lines:
        request_line = lines[0].split(' ')
        if len(request_line) >= 2:
            http_method = request_line[0]
            parsed_url = urlparse(request_line[1])

            # HTTP(S) request
            if not recent_domain:
                recent_domain = parsed_url.netloc
                http_url = recent_domain
            # HTTP(S) response
            else:
                http_url = recent_domain
                recent_domain = None

        for line in lines:
            if line.startswith('HTTP'):
                status_parts = line.split(' ', 2)
                status_code = status_parts[1]
                if len(status_parts) > 2:
                    status_code += ' ' + status_parts[2]

            # Extract host from the "Host" header
            host_match = re.match(r'Host:\s*(.*)', line)
            if host_match:
                recent_domain = host_match.group(1).strip()
                http_url = recent_domain

    # print(f"Method: {http_method}, URL: {http_url}, Status: {status_code}")
    return http_method, http_url, status_code


def filter_non_hex(string):
    # possibility to not work properly if \ or x aren't used to designate a byte
    # ... but icba
    return ''.join(c for c in string if c in '0123456789abcdexfABCDEF\\\'')
