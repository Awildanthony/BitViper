
# Dictionary for protocol names.
PORT_TO_PROTOCOL: dict[int, str] = {
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


# All currently supported IPv4 network protocols.
IPV4_PROTOS = [
    "ICMP", 
    "TCP",
        "HTTP", 
        "HTTPS", 
        "HTTP(S)", 
    "UDP", 
    "DNS"
]


# Most recent HTTP(S) domain name.
recent_domain = None


# Dictionary for DNS record types.
DNS_TYPES: dict[int, str] = {
    1:   "A",     # ipv4
    2:   "NS",
    5:   "CNAME",
    15:  "MX",
    28:  "AAAA",  # ipv6
    33:  "SRV",
    65:  "HTTPS"
}
DNS_PORTS = [53, 56710]


# Dictionary for ICMP types; dictionary for ICMP codes.
# https://www.ibm.com/docs/en/qsip/7.5?topic=applications-icmp-type-code-ids
ICMP_TYPES: dict[int, str] = {
    0:   "Echo reply.",
    3:   "Destination unreachable.",
    4:   "Source quench.",
    5:   "Redirect.",
    8:   "Echo.",
    9:   "Router advertisement.",
    10:  "Router selection.",
    11:  "Time exceeded.",
    12:  "Parameter problem.",
    13:  "Timestamp.",
    14:  "Timestamp reply.",
    15:  "Information request.",
    16:  "Information reply.",
    17:  "Address mask reqest.",
    18:  "Address mask reply.",
    30:  "Traceroute."
}
# ... ICMP Destination Unreachable Codes:
ICMP_TYPE3_CODES: dict[int, str] = {
    0:   "Net is unreachable.",
    1:   "Host is unreachable.",
    2:   "Protocol is unreachable.",
    3:   "Port is unreachable.",
    4:   "Fragmentation was needed and `Don't Fragment` was set.",
    5:   "Source route failed.",
    6:   "Destination network is unknown.",
    7:   "Destination host is unknown.",
    8:   "Source host is isolated.",
    9:   "Communication with destination network is administratively prohibited.",
    10:  "Communication with destination host is administratively prohibited.",
    11:  "Destionation network is unreachable for type of service.",
    12:  "Destination host in unreachable for type of service.",
    13:  "Communication is administritively prohibited.",
    14:  "Host precedence violation.",
    15:  "Precedence cutoff is in effect."
}
# ... ICMP Redirect Codes:
ICMP_TYPE5_CODES: dict[int, str] = {
    0:  "Redirect datagram for the network (or subnet).",
    1:  "Redirect datagram for the host.",
    2:  "Redirect datagram for the type of service and network.",
    3:  "Redirect datagram for the type of service and host."
}
# ... ICMP Time Exceeded Codes:
ICMP_TYPE11_CODES: dict[int, str] = {
    0:  "`Time to Live` exceeded in transit.",
    1:  "Fragment reassembly time exceeded."
}
# ... ICMP Parameter Problem Codes:
ICMP_TYPE12_CODES: dict[int, str] = {
    0:  "Pointer indicates the error.",
    1:  "Missing a required option.",
    2:  "Bad length."
}
# Dictionary mapping ICMP types to dictionaries of ICMP code IDs.
ICMP_CODE_DICT: dict[int, dict[int, str]] = {
    3:   ICMP_TYPE3_CODES,
    5:   ICMP_TYPE5_CODES,
    11:  ICMP_TYPE11_CODES,
    12:  ICMP_TYPE12_CODES
}


ARP_PORTS = [1544]
