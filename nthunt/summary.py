"""Capture overview: top talkers, protocols, conversations, DNS queries.

Run this first on every case. It gives the "lay of the land" (who talks the
most, over what, and what names were looked up) so later findings can be
judged against what is normal for this capture.
"""

from collections import Counter

from scapy.layers.dns import DNS, DNSQR

from nthunt.packet_utils import ip_pair, transport, ts


def summarize(packets, top_n=10):
    """Return a dict summarizing the capture.

    Top talkers are ranked by packets sent. Conversations are
    (source, destination, destination port) tuples, the same grouping that
    Wireshark's Statistics > Conversations uses for TCP/UDP.
    """
    if not packets:
        return {"packet_count": 0}

    protocols = Counter()
    sent_packets, sent_bytes = Counter(), Counter()
    conv_packets, conv_bytes = Counter(), Counter()
    dns_queries = Counter()
    total_bytes = 0
    times = []

    for pkt in packets:
        size = len(pkt)
        total_bytes += size
        times.append(ts(pkt))
        proto, _sport, dport = transport(pkt)
        protocols[proto] += 1

        pair = ip_pair(pkt)
        if pair:
            src, dst = pair
            sent_packets[src] += 1
            sent_bytes[src] += size
            key = (src, dst, dport, proto)
            conv_packets[key] += 1
            conv_bytes[key] += size

        if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
            name = pkt[DNSQR].qname.decode(errors="replace").rstrip(".").lower()
            dns_queries[name] += 1

    first, last = min(times), max(times)
    return {
        "packet_count": len(packets),
        "total_bytes": total_bytes,
        "first_seen": first,
        "last_seen": last,
        "duration_seconds": round(last - first, 3),
        "unique_source_ips": len(sent_packets),
        "unique_dns_names": len(dns_queries),
        "protocols": dict(protocols.most_common()),
        "top_talkers": [
            {"ip": ip, "packets_sent": n, "bytes_sent": sent_bytes[ip]}
            for ip, n in sent_packets.most_common(top_n)
        ],
        "top_conversations": [
            {"src": s, "dst": d, "dst_port": p, "protocol": proto, "packets": n, "bytes": conv_bytes[(s, d, p, proto)]}
            for (s, d, p, proto), n in conv_packets.most_common(top_n)
        ],
        "top_dns_queries": [{"query": q, "count": n} for q, n in dns_queries.most_common(top_n)],
    }
