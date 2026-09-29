"""Generate web/samples/synthetic-lab.pcap: a small synthetic capture with known
activity (beaconing, DGA-style DNS, DNS tunneling, port scans) for testing nthunt.
Uses documentation/private address space only. No real malware traffic.

Run from web/samples/:  python make_sample.py
"""
import random
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, wrpcap

random.seed(7)
T0 = 1767225600.0  # 2026-01-01 00:00:00 UTC
DURATION = 30 * 60
pkts = []
GW_DNS = "10.0.0.2"
MAC_C, MAC_S = "02:00:00:00:00:01", "02:00:00:00:00:02"

def add(t, p):
    p.time = t
    pkts.append((t, p))

def tcp_session(t, src, dst, dport, sport=None, payload=200):
    sport = sport or random.randint(49152, 65000)
    seq = random.randint(1, 2**31)
    add(t, Ether(src=MAC_C, dst=MAC_S)/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S", seq=seq))
    add(t+0.02, Ether(src=MAC_S, dst=MAC_C)/IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="SA", seq=1000, ack=seq+1))
    add(t+0.021, Ether(src=MAC_C, dst=MAC_S)/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="A", seq=seq+1, ack=1001))
    add(t+0.03, Ether(src=MAC_C, dst=MAC_S)/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="PA", seq=seq+1, ack=1001)/(b"\x16\x03\x01" + bytes(payload)))
    add(t+0.09, Ether(src=MAC_S, dst=MAC_C)/IP(src=dst, dst=src)/TCP(sport=dport, dport=sport, flags="PA", seq=1001, ack=seq+1+payload+3)/bytes(random.randint(300, 1400)))
    add(t+0.2, Ether(src=MAC_C, dst=MAC_S)/IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="FA"))

def dns_lookup(t, src, name, answer):
    qid = random.randint(1, 65535)
    sport = random.randint(49152, 65000)
    add(t, Ether(src=MAC_C, dst=MAC_S)/IP(src=src, dst=GW_DNS)/UDP(sport=sport, dport=53)/DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
    add(t+0.015, Ether(src=MAC_S, dst=MAC_C)/IP(src=GW_DNS, dst=src)/UDP(sport=53, dport=sport)/DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=answer) if answer else None, rcode=0 if answer else 3))

# 1) Normal, irregular browsing from several workstations
sites = {"www.rutgers.edu": "198.51.100.10", "outlook.office.com": "198.51.100.20",
         "github.com": "198.51.100.30", "www.wikipedia.org": "198.51.100.40",
         "canvas.instructure.com": "198.51.100.50", "www.nist.gov": "198.51.100.60",
         "attack.mitre.org": "198.51.100.70", "docs.python.org": "198.51.100.80"}
for host in ["10.0.0.11", "10.0.0.12", "10.0.0.14", "10.0.0.23"]:
    t = T0 + random.uniform(0, 60)
    while t < T0 + DURATION:
        name, ip = random.choice(list(sites.items()))
        dns_lookup(t, host, name, ip)
        for _ in range(random.randint(1, 3)):
            tcp_session(t + random.uniform(0.05, 2), host, ip, 443)
        t += random.expovariate(1 / 45)

# 2) Beaconing: 10.0.0.23 -> 203.0.113.66:443 every ~60s with small jitter
t = T0 + 95
dns_lookup(t - 1, "10.0.0.23", "update-check.example.net", "203.0.113.66")
while t < T0 + DURATION:
    tcp_session(t, "10.0.0.23", "203.0.113.66", 443, payload=64)
    t += 60 + random.uniform(-1.5, 1.5)

# 3) DGA-style lookups (NXDOMAIN) from 10.0.0.37
alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
t = T0 + 400
for i in range(25):
    name = "".join(random.choice(alpha) for _ in range(random.randint(13, 19))) + random.choice([".com", ".net", ".info"])
    dns_lookup(t, "10.0.0.37", name, None)
    t += random.uniform(2, 6)
dns_lookup(t + 1, "10.0.0.37", "qz7xk2vplm9w4rt.com", "203.0.113.99")

# 4) DNS tunneling-style lookups from 10.0.0.37 under one parent domain
b32 = "abcdefghijklmnopqrstuvwxyz234567"
t = T0 + 900
for i in range(30):
    label = "".join(random.choice(b32) for _ in range(52))
    dns_lookup(t, "10.0.0.37", f"{label}.{i:04d}.exfil.example.org", "203.0.113.120")
    t += random.uniform(0.5, 1.5)

# 5) Vertical scan: 10.0.0.66 -> 10.0.0.10 ports 1-150 in ~15s (RST from closed)
t = T0 + 1200
open_ports = {22, 80, 135, 139, 443, 445}
for port in range(1, 151):
    sport = random.randint(40000, 60000)
    add(t, Ether(src=MAC_C, dst=MAC_S)/IP(src="10.0.0.66", dst="10.0.0.10")/TCP(sport=sport, dport=port, flags="S"))
    if port in open_ports:
        add(t + 0.001, Ether(src=MAC_S, dst=MAC_C)/IP(src="10.0.0.10", dst="10.0.0.66")/TCP(sport=port, dport=sport, flags="SA"))
        add(t + 0.002, Ether(src=MAC_C, dst=MAC_S)/IP(src="10.0.0.66", dst="10.0.0.10")/TCP(sport=sport, dport=port, flags="R"))
    else:
        add(t + 0.001, Ether(src=MAC_S, dst=MAC_C)/IP(src="10.0.0.10", dst="10.0.0.66")/TCP(sport=port, dport=sport, flags="RA"))
    t += 0.1

# 6) Horizontal scan: 10.0.0.66 -> 10.0.0.100-139 on 445 in ~8s
t = T0 + 1300
for h in range(100, 140):
    sport = random.randint(40000, 60000)
    add(t, Ether(src=MAC_C, dst=MAC_S)/IP(src="10.0.0.66", dst=f"10.0.0.{h}")/TCP(sport=sport, dport=445, flags="S"))
    t += 0.2

pkts.sort(key=lambda x: x[0])
wrpcap("synthetic-lab.pcap", [p for _, p in pkts])
print(len(pkts), "packets")
