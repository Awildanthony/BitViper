import re
import socket
import struct
from meta import *
from typing import Union
from urllib.parse import urlparse


def port_to_proto(port: int) -> str:
    """
    Match `port` number to protocol number supported by this program;
    if none, then the IANA-recognized protocol belonging to that number.
    If none, return `port` as a string.
    """
    return PORT_TO_PROTOCOL.get(port, ALL_PROTOCOLS.get(port, str(port)))


def record_to_dns(record: int) -> str:
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


def mac_str(mac_addr: bytes) -> str:
    """
    Converts `mac_addr` from bytes to a string.
    """
    byte_str = map('{:02x}'.format, mac_addr)
    mac_str = ':'.join(byte_str).upper()
    return mac_str


def parse_net_frame(packet_header: bytes) -> tuple[str, str, str, bytes]:
    """
    Extracts the destination MAC address, source MAC address, protocol name, 
    and payload data from a network packet into an Ethernet frame.
    """
    header_info = packet_header[:14]
    payload = packet_header[14:]
    dst_mac, src_mac, proto = struct.unpack("! 6s 6s H", header_info)
    if dst_mac == "FF:FF:FF:FF:FF:FF":
        dst_mac = "Broadcast"
    proto_name = port_to_proto(socket.htons(proto))
    return mac_str(dst_mac), mac_str(src_mac), proto_name, payload


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

    # Even if we don't support a protocol, we want its name to be in `proto`.
    if proto not in PORT_TO_PROTOCOL.keys():
        if proto in ALL_PROTOCOLS.keys():
            proto = ALL_PROTOCOLS[proto]

    src_ip, dst_ip = ".".join(map(str, src_ip)), ".".join(map(str, dst_ip))
    return ver, hdr_len, ttl, proto, src_ip, dst_ip, payload


def unpack_icmp(data: bytes) -> tuple[str, bytes]:
    """
    Unpacks an identified ICMP packet by extracting its `icmp_type`,
    `code`, `checksum`, `display_data`, and `payload` data.
    """
    header_info = data[:4]
    payload = data[4:]
    type, code, checksum = struct.unpack("! B B H", header_info)
    
    # Get the description for icmp_type.
    icmp_type_desc = ICMP_TYPES.get(type, "Unknown type.")
    
    # Get the description for the icmp_code based on icmp_type.
    icmp_code_desc = ICMP_CODE_DICT.get(type, {}).get(code, "Unknown code.")
    
    display_data = f'type={type} code={code} "{icmp_type_desc} {icmp_code_desc}"'
    return display_data, payload


def unpack_tcp(data: bytes) -> tuple[int, int, int, int, list[int], 
                                     str | None, str | None, str | None, str]:
    """
    Extracts from a TCP packet its `src_port`, `dst_port`, `seq`, 
    `ack`, `tcp_flags`, `http_method`, `http_url`, and `display_data`.
    """
    # Unpack the TCP packet according to its known architecture.
    src_port, dst_port, seq, ack, \
        tcp_flags_bitstring = struct.unpack("! H H L L H", data[:14])

    # Reserved TCP flags are offset; un-offset them.
    offset = (tcp_flags_bitstring >> 12) * 4
    flag_urg = (tcp_flags_bitstring & 32) >> 5
    flag_ack = (tcp_flags_bitstring & 16) >> 4
    flag_psh = (tcp_flags_bitstring & 8) >> 3
    flag_rst = (tcp_flags_bitstring & 4) >> 2
    flag_syn = (tcp_flags_bitstring & 2) >> 1
    flag_fin = (tcp_flags_bitstring & 1)
    tcp_flags = [flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin]

    # Checking conventional ports (e.g., 80/443 for HTTP(S) data) is a
    # necessary but not sufficient condition for supporting said protocol.
    http_method, http_url, status_code = parse_http_data(data[offset:])

    # Packet contains HTTP(S) data; distinguish response vs request.
    display_data = ""
    if http_method and http_url:
        display_data = f"{http_method} {http_url}"
        if status_code:
            display_data += f" {status_code}"

    return src_port, dst_port, seq, ack, tcp_flags, \
           http_method, http_url, status_code, display_data


def set_tcp_flags(flags: list[int]) -> str:
    """
    Takes in the TCP flags as arguments and returns a string 
    containing the names of the flags that are set.
    """
    flag_names = ["URG", "ACK", "PSH", "RST", "SYN", "FIN"]
    set_flags = [flag_names[i] for i in range(len(flags)) if flags[i] == 1]
    return "[" + ", ".join(set_flags) + "]"


def unpack_udp(data: bytes) -> tuple[int, int, int, bytes]:
    """
    Unpacks an identified UDP packet by extracting its
    `src_port`, `dst_port`, `size`, and `payload` data.
    """
    header_info = data[:8]
    payload = data[8:]
    src_port, dst_port, size = struct.unpack("! H H 2x H", header_info)
    return src_port, dst_port, size, payload


def unpack_arp(data: bytes):
    """
    Unpacks an identified ARP packet by extracting the sender
    and receiver MAC and IP addresses. Returns the source IP 
    address, a formatted info string from the packet, and the 
    remaining payload itself (if any).
    """
    # Unpack the ARP packet according to its known architecture.
    htype, ptype, hlen, plen, oper, \
        sha, spa, tha, tpa = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
    
    # Convert the numeric values to their respective representations.
    sha_str = mac_str(sha)              # Source MAC
    tha_str = mac_str(tha)              # Target MAC
    spa_str = '.'.join(map(str, spa))   # Source IP
    tpa_str = '.'.join(map(str, tpa))   # Target IP
    
    # Determine operation type (1: request, 2: reply).
    if oper == 1:
        info = f"Who has {tpa_str}? Tell {spa_str}"
    elif oper == 2:
        info = f"{spa_str} is at {sha_str}"
    else:
        info = f"Unknown operation {oper}"
    
    return spa_str, info, data[28:]


def format_dns_data(dns_data: bytes) -> str:
    """
    Formats DNS packet data into a human-readable string to
    eventually be displayed in the GUI's "Data" column.
    """
    transaction_id, flags, questions, answer_rrs, authority_rrs, \
        additional_rrs = struct.unpack('! H H H H H H', dns_data[:12])
    data = dns_data[12:]
    q_name, q_type, q_class, data = parse_dns_question(data)
    q_type = record_to_dns(q_type)
    answers = []
    cnames = ''
    for _ in range(answer_rrs):
        a_type, data, answer = parse_dns_answer(data)
        answers.append(answer)
        if record_to_dns(answer['Type']) == 'CNAME':
            cnames += f" CNAME {answer['RD Data']}"
    
    # Construct return string; distinguish between DNS query and response.
    s = "Standard query "
    if flags & 0x8000:
        s += "response "
    s += f"0x{transaction_id:04X} {q_type} {q_name}{cnames}"
    return s


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
    if record_to_dns(a_type) == "CNAME":
        a_rdata = parse_dns_name(a_rdata)[0]
    return a_type, data, {'Name': a_name, 
                          'Type': a_type, 
                          'Class': a_class, 
                          'TTL': a_ttl, 
                          'RD Length': a_rdlength, 
                          'RD Data': a_rdata}


def parse_http_data(data: bytes) -> tuple[str | None, str | None, str | None]:
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


def parse_eth_frame(eth_proto: str, frame: bytes) -> tuple[str, str, bytes]:
    """
    Provided a packet's ethernet protocol and ethernet frame, 
    returns its source IP address, destination IP address,
    network protocol, display data, and payload data.
    """
    # Set defaults.
    soln = {'src_ip': "", 'dst_ip': "", 'proto': eth_proto, 'info': str(frame), 'pl': frame}

    # Check the Ethernet protocol and unpack accordingly.
    if eth_proto == 'IPv4':
        ver, hdr_len, ttl, proto, src_ip, dst_ip, ipv4_pl = unpack_ipv4(frame)
        proto_name = port_to_proto(proto)
        soln.update({
            'src_ip': src_ip, 'dst_ip': dst_ip, 'proto': f"{proto}", 'pl': ipv4_pl
        })

        # Check the IPv4 protocol and unpack accordingly.
        if proto_name == 'ICMP':
            display, pl = unpack_icmp(ipv4_pl)
            soln.update({'proto': "ICMP", 'info': display, 'pl': pl})

        elif proto_name == 'TCP':
            src_port, dst_port, seq, ack, tcp_flags, \
                http_method, http_url, status, tcp_data = unpack_tcp(ipv4_pl)
            tcp_flags = set_tcp_flags(tcp_flags)
            soln['proto'], soln['info'] = "TCP", tcp_data
            # TODO: we aren't unpacking the tcp payload at all???

            # Call to `unpack_tcp()` found HTTP(S) data.
            if http_method and http_url:
                dst_port = port_to_proto(dst_port) 
                # Check if from a non-conventional port for HTTP(S).
                soln['proto'] = "HTTP(S)" if digits_in(dst_port) else dst_port
            else:
                try:
                    soln['info'] = (f"{src_port} → {dst_port} "
                                       f"{tcp_flags} Seq={seq} Ack={ack}")
                except UnicodeDecodeError as error:
                    soln['info'] = f"Decoding error:\n{error}"

        elif proto_name == 'UDP':
            src_port, dst_port, len, pl = unpack_udp(ipv4_pl)
            soln['proto'], soln['pl'] = "UDP", pl

            # Call to `unpack_udp` found use of conventional DNS port(s).
            if src_port in DNS_PORTS or dst_port in DNS_PORTS:
                soln['proto'], soln['info'] = "DNS", format_dns_data(pl)
            else:
                try:
                    soln['info'] = f"{src_port} → {dst_port} Len={len}"
                except UnicodeDecodeError as error:
                    soln['info'] = f"Decoding error:\n{error}"

    # TODO: everything below this is a result of poor input specs/formatting!!!

    # We have a port number.
    elif digits_in(eth_proto):
        # DNS (non-IPv4).
        if eth_proto in map(str, DNS_PORTS):
            src_port, dst_port, len, pl = unpack_udp(frame)
            soln.update({'proto': "DNS", 'info': format_dns_data(pl), 'pl': pl})

        # ARP.
        elif eth_proto in map(str, ARP_PORTS):
            src_ip, info, pl = unpack_arp(frame)
            soln.update({
                'src_ip': src_ip, 'dst_ip': "Broadcast", 
                'proto': "ARP", 'info': info, 'pl': pl
            })
    
    # We have a specific IPV4 network protocol's name.
    elif eth_proto in IPV4_PROTOS:
        if eth_proto == 'DNS':
            src_port, dst_port, len, pl = unpack_udp(frame)
            soln.update({'proto': "DNS", 'info': format_dns_data(pl), 'pl': pl})
        
        elif eth_proto == 'ARP':
            src_ip, info, pl = unpack_arp(frame)
            soln.update({
                'src_ip': src_ip, 'dst_ip': "Broadcast", 
                'proto': "ARP", 'info': info, 'pl': pl
            })

    return soln['src_ip'], soln['dst_ip'], soln['proto'], soln['info'], soln['pl']
