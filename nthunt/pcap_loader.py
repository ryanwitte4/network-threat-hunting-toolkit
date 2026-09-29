"""Load packets from a PCAP/PCAPNG file."""

from pathlib import Path

from scapy.all import PcapReader


def iter_packets(path):
    """Yield packets one at a time so large captures don't fill memory."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"No such capture: {path}")
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            yield pkt
