"""Small helpers shared by the detectors."""

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def ip_pair(pkt):
    """Return (src, dst) for IPv4 or IPv6 packets, else None."""
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None


def transport(pkt):
    """Return (protocol name, src port, dst port). Ports are None when not TCP/UDP."""
    if TCP in pkt:
        return "TCP", pkt[TCP].sport, pkt[TCP].dport
    if UDP in pkt:
        return "UDP", pkt[UDP].sport, pkt[UDP].dport
    if ICMP in pkt:
        return "ICMP", None, None
    if IP in pkt or IPv6 in pkt:
        return "other IP", None, None
    return "non-IP", None, None


def tcp_flags(pkt):
    """Integer TCP flags, or None if the packet has no TCP layer."""
    return int(pkt[TCP].flags) if TCP in pkt else None


def is_connection_start(pkt):
    """A TCP SYN without ACK: the first packet of a new connection."""
    flags = tcp_flags(pkt)
    return flags is not None and flags & SYN and not flags & ACK


def ts(pkt):
    """Packet timestamp as a float (Scapy uses a Decimal type)."""
    return float(pkt.time)
