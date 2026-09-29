"""Beacon detection: find hosts calling out at regular intervals.

Malware often "checks in" with its command-and-control server on a timer.
Humans browsing the web are irregular; malware is suspiciously consistent.
"""

import statistics
from collections import defaultdict

from scapy.layers.inet import TCP

from nthunt.packet_utils import ip_pair, is_connection_start, ts


def find_beacons(packets, min_connections=5, max_jitter=0.2, min_interval_seconds=1.0):
    """Return candidate beacons as a list of dicts, most regular first.

    How it works:
      1. Every TCP SYN (without ACK) marks a new connection. SYN
         retransmissions reuse the same source port, so each
         (src, sport, dst, dport) is only counted once.
      2. Connections are grouped by (src_ip, dst_ip, dst_port).
      3. For groups with >= min_connections, the gaps between consecutive
         connections are measured.
      4. Regularity is scored two ways:
           jitter        = stdev / mean of the gaps (coefficient of variation)
           robust_jitter = 1.4826 * MAD / median of the gaps
         The robust score ignores a few odd gaps, such as a missed check-in
         or a laptop waking from sleep, which would otherwise hide a beacon.
      5. A group is flagged when either score is <= max_jitter and the
         median gap is >= min_interval_seconds (so a burst of parallel
         connections when a web page loads is not mistaken for a timer).

    Malware that adds heavy random jitter (e.g. 50%) will score above the
    default threshold. Raising max_jitter catches it at the cost of more
    false positives from automated but benign software (updaters, NTP,
    telemetry), which is why every hit still needs analyst review.
    """
    starts = {}
    for pkt in packets:
        if not is_connection_start(pkt):
            continue
        pair = ip_pair(pkt)
        if not pair:
            continue
        key = (pair[0], pkt[TCP].sport, pair[1], pkt[TCP].dport)
        starts.setdefault(key, ts(pkt))  # keep the first SYN, drop retransmits

    groups = defaultdict(list)
    for (src, _sport, dst, dport), t in starts.items():
        groups[(src, dst, dport)].append(t)

    findings = []
    for (src, dst, dport), times in groups.items():
        if len(times) < min_connections:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(gaps)
        median = statistics.median(gaps)
        if median < min_interval_seconds or mean <= 0:
            continue
        jitter = statistics.pstdev(gaps) / mean
        mad = statistics.median(abs(g - median) for g in gaps)
        robust = 1.4826 * mad / median
        if min(jitter, robust) > max_jitter:
            continue
        findings.append({
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": dport,
            "connections": len(times),
            "median_interval_s": round(median, 2),
            "mean_interval_s": round(mean, 2),
            "jitter": round(jitter, 3),
            "robust_jitter": round(robust, 3),
            "first_seen": times[0],
            "last_seen": times[-1],
        })

    findings.sort(key=lambda f: (f["robust_jitter"], -f["connections"]))
    return findings
