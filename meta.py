

# Dictionary of all assigned protocol numbers.
# Pulled from the IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
ALL_PROTOCOLS = {
    # Values with "*** + ###", where "###" is just its key value, designate
    # a lack of a name. The starts distinguish it from unassigned protocols.

    0:   "HOPOPT",       # IPv6 Hop-by-Hop Option
    1:   "ICMP",         # Internet Control Message
    2:   "IGMP",         # Internet Group Management
    3:   "GGP",          # Gateway-to-Gateway Protocol
    4:   "IPv4",         # IPv4 encapsulation
    5:   "ST",           # Stream
    6:   "TCP",          # Transmission Control Protocol
    7:   "CBT",          # CBT
    8:   "EGP",          # Exterior Gateway Protocol
    9:   "IGP",          # any private interior gateway (used by Cisco for their IGRP)
    10:  "BBN-RCC-MON",  # BBN RCC Monitoring
    11:  "NVP-II",       # Network Voice Protocol
    12:  "PUP",          # PUP
    13:  "ARGUS",        # ARGUS (deprecated)
    14:  "EMCON",        # EMCON
    15:  "XNET",         # Cross Net Debugger
    16:  "CHAOS",        # Chaos
    17:  "UDP",          # User Datagram Protocol
    18:  "MUX",          # Multiplexing Protocol
    19:  "DCN-MEAS",     # DCN Measurement Subsystems
    20:  "HMP",          # Host Monitoring Protocol
    21:  "PRM",          # Packet Radio Measurement
    22:  "XNS-IDP",      # Xerox NS IDP
    23:  "TRUNK-1",      # Trunk-1
    24:  "TRUNK-2",      # Trunk-2
    25:  "LEAF-1",       # Leaf-1
    26:  "LEAF-2",       # Leaf-2
    27:  "RDP",          # Reliable Data Protocol
    28:  "IRTP",         # Internet Reliable Transaction Protocol
    29:  "ISO-TP4",      # ISO Transport Protocol Class 4
    30:  "NETBLT",       # Bulk Data Transfer Protocol
    31:  "MFE-NSP",      # MFE Network Services Protocol
    32:  "MERIT-INP",    # MERIT Internodal Protocol
    33:  "DCCP",         # Datagram Congestion Control Protocol
    34:  "3PC",          # Third Party Connect Protocol
    35:  "IDPR",         # Inter-Domain Policy Routing Protocol
    36:  "XTP",          # XTP
    37:  "DDP",          # Datagram Delivery Protocol
    38:  "IDPR-CMTP",    # IDPR Control Message Transport Proto
    39:  "TP++",         # TP++ Transport Protocol
    40:  "IL",           # IL Transport Protocol
    41:  "IPv6",         # IPv6 encapsulation
    42:  "SDRP",         # Source Demand Routing Protocol
    43:  "IPv6-Route",   # Routing Header for IPv6
    44:  "IPv6-Frag",    # Fragment Header for IPv6
    45:  "IDRP",         # Inter-Domain Routing Protocol
    46:  "RSVP",         # Reservation Protocol
    47:  "GRE",          # Generic Routing Encapsulation
    48:  "DSR",          # Dynamic Source Routing Protocol
    49:  "BNA",          # BNA
    50:  "ESP",          # Encap Security Payload
    51:  "AH",           # Authentication Header
    52:  "I-NLSP",       # Integrated Net Layer Security TUBA
    53:  "SWIPE",        # IP with Encryption
    54:  "NARP",         # NBMA Address Resolution Protocol
    55:  "MOBILE",       # IP Mobility
    56:  "TLSP",         # Transport Layer Security Protocol using Kryptonet key management
    57:  "SKIP",         # SKIP
    58:  "IPv6-ICMP",    # ICMP for IPv6
    59:  "IPv6-NoNxt",   # No Next Header for IPv6
    60:  "IPv6-Opts",    # Destination Options for IPv6
    61:  "*** 61",       # any host internal protocol
    62:  "CFTP",         # CFTP
    63:  "*** 63",       # any local network
    64:  "SAT-EXPAK",    # SATNET and Backroom EXPAK
    65:  "KRYPTOLAN",    # Kryptolan
    66:  "RVD",          # MIT Remote Virtual Disk Protocol
    67:  "IPPC",         # Internet Pluribus Packet Core
    68:  "*** 68",       # any distributed file system
    69:  "SAT-MON",      # SATNET Monitoring
    70:  "VISA",         # VISA Protocol
    71:  "IPCV",         # Internet Packet Core Utility
    72:  "CPNX",         # Computer Protocol Network Executive
    73:  "CPHB",         # Computer Protocol Heart Beat
    74:  "WSN",          # Wang Span Network
    75:  "PVP",          # Packet Video Protocol
    76:  "BR-SAT-MON",   # Backroom SATNET Monitoring
    77:  "SUN-ND",       # SUN ND PROTOCOL-Temporary
    78:  "WB-MON",       # WIDEBAND Monitoring
    79:  "WB-EXPAK",     # WIDEBAND EXPAK
    80:  "ISO-IP",       # ISO Internet Protocol
    81:  "VMTP",         # VMTP
    82:  "SECURE-VMTP",  # SECURE-VMTP
    83:  "VINES",        # VINES
    84:  "TTP",          # TTP
    85:  "NSFNET-IGP",   # NSFNET-IGP
    86:  "DGP",          # Dissimilar Gateway Protocol
    87:  "TCF",          # TCF
    88:  "EIGRP",        # EIGRP
    89:  "OSPFIGP",      # OSPFIGP
    90:  "Sprite-RPC",   # Sprite RPC Protocol
    91:  "LARP",         # Locus Address Resolution Protocol
    92:  "MTP",          # Multicast Transport Protocol
    93:  "AX.25",        # AX.25 Frames
    94:  "IPIP",         # IP-within-IP Encapsulation Protocol
    95:  "MICP",         # Mobile Internetworking Control Protocol
    96:  "SCC-SP",       # Semaphore Communications Sec. Pro
    97:  "ETHERIP",      # Ethernet-within-IP Encapsulation
    98:  "ENCAP",        # Encapsulation Header
    99:  "*** 99",       # any private encryption scheme
    100: "GMTP",         # GMTP
    101: "IFMP",         # Ipsilon Flow Management Protocol
    102: "PNNI",         # PNNI over IP
    103: "PIM",          # Protocol Independent Multicast
    104: "ARIS",         # ARIS
    105: "SCPS",         # SCPS
    106: "QNX",          # QNX
    107: "A/N",          # Active Networks
    108: "IPComp",       # IP Payload Compression Protocol
    109: "SNP",          # Sitara Networks Protocol
    110: "Compaq-Peer",  # Compaq Peer Protocol
    111: "IPX-in-IP",    # IPX in IP
    112: "VRRP",         # Virtual Router Redundancy Protocol
    113: "PGM",          # PGM Reliable Transport Protocol
    114: "*** 114",      # any 0-hop protocol
    115: "L2TP",         # Layer Two Tunneling Protocol
    116: "DDX",          # D-II Data Exchange (DDX)
    117: "IATP",         # Interactive Agent Transfer Protocol
    118: "STP",          # Schedule Transfer Protocol
    119: "SRP",          # SpectraLink Radio Protocol
    120: "UTI",          # UTI
    121: "SMP",          # Simple Message Protocol
    122: "SM",           # SM
    123: "PTP",          # Performance Transparency Protocol
    124: "ISIS over IPv4",  # ISIS over IPv4
    125: "FIRE",         # FIRE
    126: "CRTP",         # Combat Radio Transport Protocol
    127: "CRUDP",        # Combat Radio User Datagram
    128: "SSCOPMCE",     # Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment
    129: "IPLT",         # IPLT
    130: "SPS",          # Secure Packet Shield
    131: "PIPE",         # Private IP Encapsulation within IP
    132: "SCTP",         # Stream Control Transmission Protocol
    133: "FC",           # Fibre Channel
    134: "RSVP-E2E-IGNORE",  # RSVP-E2E-IGNORE
    135: "Mobility Header",  # Mobility Header
    136: "UDPLite",      # UDPLite
    137: "MPLS-in-IP",   # MPLS-in-IP
    138: "manet",        # MANET Protocols
    139: "HIP",          # Host Identity Protocol
    140: "Shim6",        # Shim6 Protocol
    141: "WESP",         # Wrapped Encapsulating Security Payload
    142: "ROHC",         # Robust Header Compression
    143: "Ethernet"      # Ethernet

    # The rest (through 255) are reserved.
    # All others can be whatever (even including the above).
}


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
    "DNS",
    "ARP"
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
