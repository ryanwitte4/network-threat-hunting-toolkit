"""Scan detection: hosts probing many ports or hosts in a short time."""

from collections import Counter, defaultdict, deque

from scapy.layers.inet import TCP

from nthunt.packet_utils import ACK, RST, SYN, ip_pair, tcp_flags, ts


def _max_distinct_in_window(events, window_seconds):
    """events: sorted (time, value). Return the most distinct values seen in any window."""
    best, window, counts = 0, deque(), Counter()
    for t, value in events:
        window.append((t, value))
        counts[value] += 1
        while window and t - window[0][0] > window_seconds:
            _, old = window.popleft()
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
        best = max(best, len(counts))
    return best


def find_scanners(packets, port_threshold=20, host_threshold=20, window_seconds=60, max_open_ratio=0.5):
    """Return suspected scanning sources.

    A "probe" is any TCP packet with neither ACK nor RST set: a SYN scan,
    connect scan, or the FIN / NULL / Xmas stealth scans nmap can send.

      - Vertical scan: one source probes >= port_threshold distinct ports on
        one target within window_seconds.
      - Horizontal scan: one source probes the same port on
        >= host_threshold distinct targets within window_seconds.

    Replies are used to show what the scanner learned: a SYN-ACK means the
    port was open, a RST means it was closed.

    A busy web browser can easily open port 443 on 20+ servers in a minute,
    which looks like a horizontal scan by count alone. The difference is
    that a browser's connections succeed. So a horizontal finding is only
    kept when at most max_open_ratio of the probed hosts answered "open".

    Validate it with a capture of your own nmap scan from the
    Network and Internet Technology course exercises.
    """
    probes = []  # (time, src, dst, dport, flags)
    replies = defaultdict(set)  # (scanner, target, port) -> {"open", "closed"}
    for pkt in packets:
        flags = tcp_flags(pkt)
        pair = ip_pair(pkt)
        if flags is None or not pair:
            continue
        src, dst = pair
        if not flags & (ACK | RST):
            probes.append((ts(pkt), src, dst, pkt[TCP].dport, flags))
        elif flags & SYN and flags & ACK:
            replies[(dst, src, pkt[TCP].sport)].add("open")
        elif flags & RST:
            replies[(dst, src, pkt[TCP].sport)].add("closed")
    probes.sort()

    by_target = defaultdict(list)  # (src, dst) -> [(t, port)]
    by_port = defaultdict(list)    # (src, port) -> [(t, dst)]
    flag_names = defaultdict(set)
    for t, src, dst, dport, flags in probes:
        by_target[(src, dst)].append((t, dport))
        by_port[(src, dport)].append((t, dst))
        flag_names[src].add(str(TCP(flags=flags).flags))

    findings = []
    for (src, dst), events in by_target.items():
        peak = _max_distinct_in_window(events, window_seconds)
        if peak < port_threshold:
            continue
        ports = {p for _, p in events}
        states = [replies.get((src, dst, p), set()) for p in ports]
        findings.append({
            "source": src,
            "type": "vertical",
            "target": dst,
            "distinct_ports": len(ports),
            "distinct_hosts": 1,
            "peak_in_window": peak,
            "probes": len(events),
            "open_replies": sum("open" in s for s in states),
            "closed_replies": sum("closed" in s for s in states),
            "probe_flags": ", ".join(sorted(flag_names[src])),
            "first_seen": events[0][0],
            "last_seen": events[-1][0],
        })

    for (src, port), events in by_port.items():
        peak = _max_distinct_in_window(events, window_seconds)
        if peak < host_threshold:
            continue
        hosts = {h for _, h in events}
        states = [replies.get((src, h, port), set()) for h in hosts]
        if sum("open" in s for s in states) / len(hosts) > max_open_ratio:
            continue  # mostly successful connections: normal client behavior
        findings.append({
            "source": src,
            "type": "horizontal",
            "target": f"port {port}",
            "distinct_ports": 1,
            "distinct_hosts": len(hosts),
            "peak_in_window": peak,
            "probes": len(events),
            "open_replies": sum("open" in s for s in states),
            "closed_replies": sum("closed" in s for s in states),
            "probe_flags": ", ".join(sorted(flag_names[src])),
            "first_seen": events[0][0],
            "last_seen": events[-1][0],
        })

    findings.sort(key=lambda f: -f["peak_in_window"])
    return findings
