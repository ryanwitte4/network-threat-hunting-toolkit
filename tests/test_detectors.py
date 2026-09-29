"""Detector tests.

Unit tests use a few hand-built packets. The sample tests run each detector
on web/samples/synthetic-lab.pcap, whose planted activity is documented in
web/README.md, so a change that breaks detection (or adds noise) fails here.
"""

from pathlib import Path

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP

from nthunt import beacon, dns_anomaly, scan_detect, summary
from nthunt.pcap_loader import iter_packets

SAMPLE = Path(__file__).parents[1] / "web" / "samples" / "synthetic-lab.pcap"


def syn(t, src, dst, dport, sport=40000):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
    pkt.time = t
    return pkt


def dns_query(t, src, name):
    pkt = IP(src=src, dst="10.0.0.2") / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
    pkt.time = t
    return pkt


@pytest.fixture(scope="module")
def sample():
    return list(iter_packets(SAMPLE))


# --- entropy -----------------------------------------------------------------

def test_entropy_random_higher_than_word():
    assert dns_anomaly.shannon_entropy("xk2j9qpz7vbw4m") > dns_anomaly.shannon_entropy("google")


def test_entropy_edge_cases():
    assert dns_anomaly.shannon_entropy("") == 0
    assert dns_anomaly.shannon_entropy("aaaa") == 0
    assert dns_anomaly.shannon_entropy("ab") == pytest.approx(1.0)


# --- unit tests --------------------------------------------------------------

def test_beacon_regular_vs_irregular():
    regular = [syn(i * 30.0, "10.0.0.5", "203.0.113.9", 443, sport=40000 + i) for i in range(10)]
    irregular_gaps = [1, 50, 3, 120, 7, 2, 90, 15, 4]
    t, irregular = 0.0, []
    for i, gap in enumerate([0] + irregular_gaps):
        t += gap
        irregular.append(syn(t, "10.0.0.6", "198.51.100.1", 443, sport=41000 + i))
    hits = beacon.find_beacons(regular + irregular)
    assert [(h["src_ip"], h["dst_ip"]) for h in hits] == [("10.0.0.5", "203.0.113.9")]


def test_beacon_ignores_syn_retransmissions():
    pkts = []
    for i in range(6):
        pkts.append(syn(i * 60.0, "10.0.0.5", "203.0.113.9", 443, sport=50000 + i))
        pkts.append(syn(i * 60.0 + 1, "10.0.0.5", "203.0.113.9", 443, sport=50000 + i))  # retransmit
    hits = beacon.find_beacons(pkts)
    assert hits and hits[0]["connections"] == 6


def test_vertical_scan_threshold():
    pkts = [syn(i * 0.1, "10.0.0.66", "10.0.0.10", port) for i, port in enumerate(range(1, 26))]
    assert scan_detect.find_scanners(pkts, port_threshold=25)[0]["type"] == "vertical"
    assert scan_detect.find_scanners(pkts, port_threshold=26) == []


def test_scan_window():
    # 25 ports, but spread over 25 minutes: never 20 inside one 60 s window
    pkts = [syn(i * 60.0, "10.0.0.66", "10.0.0.10", port) for i, port in enumerate(range(1, 26))]
    assert scan_detect.find_scanners(pkts) == []


def test_dns_flags_long_label():
    name = "a" * 45 + ".example.com"
    hits = dns_anomaly.find_suspicious_domains([dns_query(0, "10.0.0.5", name)])
    assert hits and "long label" in hits[0]["reasons"]


def test_dns_ignores_normal_names():
    names = ["www.google.com", "outlook.office.com", "canvas.instructure.com", "github.com"]
    assert dns_anomaly.find_suspicious_domains([dns_query(i, "10.0.0.5", n) for i, n in enumerate(names)]) == []


# --- synthetic lab capture ---------------------------------------------------

def test_sample_summary(sample):
    s = summary.summarize(sample)
    assert s["packet_count"] == len(sample)
    assert s["protocols"] == {"TCP": 2570, "UDP": 466}
    assert s["top_talkers"][0]["ip"] == "10.0.0.23"


def test_sample_beacon(sample):
    hits = beacon.find_beacons(sample)
    assert [(h["src_ip"], h["dst_ip"], h["dst_port"]) for h in hits] == [("10.0.0.23", "203.0.113.66", 443)]
    assert 59 < hits[0]["median_interval_s"] < 61


def test_sample_scans(sample):
    hits = {(h["source"], h["type"], h["target"]) for h in scan_detect.find_scanners(sample)}
    assert hits == {("10.0.0.66", "vertical", "10.0.0.10"), ("10.0.0.66", "horizontal", "port 445")}


def test_sample_dns(sample):
    hits = dns_anomaly.find_suspicious_domains(sample)
    tunnel = [h for h in hits if h["query"].endswith("exfil.example.org")]
    others = [h for h in hits if not h["query"].endswith("exfil.example.org")]
    assert len(tunnel) == 30
    assert len(others) >= 15  # DGA-style names; short ones can fall under the entropy threshold
    assert all(h["clients"] == "10.0.0.37" for h in hits)  # no normal workstation flagged
