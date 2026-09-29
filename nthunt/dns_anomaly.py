"""DNS anomaly detection: DGA-style domains and possible DNS tunneling."""

import math
from collections import Counter, defaultdict

from scapy.layers.dns import DNS, DNSQR

from nthunt.packet_utils import ip_pair

# Names that are noisy by design and not useful here (reverse lookups, mDNS).
IGNORED_SUFFIXES = (".in-addr.arpa", ".ip6.arpa", ".local")


def shannon_entropy(text):
    """Return the Shannon entropy of a string (bits per character).

    Random-looking strings score higher than real words:
    "google" ≈ 1.92, "xk2j9qpz7vbw4m" ≈ 3.81. A string of n characters can
    never score above log2(n), so short labels are skipped by the detector.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def parent_domain(name):
    """Approximate the registered domain as the last two labels.

    This is a simplification: suffixes like .co.uk need a public-suffix list
    to be handled correctly.
    """
    labels = name.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def find_suspicious_domains(
    packets,
    entropy_threshold=3.5,
    max_label_len=40,
    min_entropy_len=10,
    subdomain_threshold=20,
):
    """Return suspicious DNS query names with the reason each was flagged.

    Checks, per queried name:
      - high entropy: any label (other than the top-level domain) at least
        min_entropy_len characters long with entropy >= entropy_threshold.
        Typical of domain generation algorithms (DGA).
      - long label: any label longer than max_label_len characters. Data
        smuggled out through DNS is usually packed into long subdomains.
      - many subdomains: the parent domain was queried with at least
        subdomain_threshold different subdomains, another tunneling sign.

    Each finding also shows whether the name failed to resolve (NXDOMAIN),
    which is common for DGA malware trying many domains until one answers.
    Known false positives: CDN and cloud hostnames with random-looking IDs.
    """
    queries = Counter()
    clients = defaultdict(set)
    nxdomain = set()
    for pkt in packets:
        if not pkt.haslayer(DNSQR):
            continue
        name = pkt[DNSQR].qname.decode(errors="replace").rstrip(".").lower()
        if not name or name.endswith(IGNORED_SUFFIXES):
            continue
        dns = pkt[DNS]
        if dns.qr == 0:
            queries[name] += 1
            pair = ip_pair(pkt)
            if pair:
                clients[name].add(pair[0])
        elif dns.rcode == 3:
            nxdomain.add(name)

    subdomains = defaultdict(set)
    for name in queries:
        parent = parent_domain(name)
        if name != parent:
            subdomains[parent].add(name)

    findings = []
    for name, count in queries.items():
        labels = name.split(".")
        candidates = labels[:-1] if len(labels) > 1 else labels  # skip the TLD
        longest = max(candidates, key=len)
        scored = [l for l in candidates if len(l) >= min_entropy_len]
        entropy = max((shannon_entropy(l) for l in scored), default=0.0)
        parent = parent_domain(name)
        siblings = len(subdomains.get(parent, ()))

        reasons = []
        if entropy >= entropy_threshold:
            reasons.append(f"high entropy ({entropy:.2f})")
        if len(longest) > max_label_len:
            reasons.append(f"long label ({len(longest)} chars)")
        if siblings >= subdomain_threshold:
            reasons.append(f"{siblings} unique subdomains of {parent}")
        if not reasons:
            continue

        findings.append({
            "query": name,
            "reasons": "; ".join(reasons),
            "entropy": round(entropy, 2),
            "longest_label": len(longest),
            "parent_domain": parent,
            "queries": count,
            "clients": ", ".join(sorted(clients[name])),
            "nxdomain": name in nxdomain,
        })

    findings.sort(key=lambda f: (f["parent_domain"], -f["entropy"]))
    return findings
