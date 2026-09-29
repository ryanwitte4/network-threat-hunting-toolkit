# Methodology

## Hunting workflow

1. **Orient** — Run `nthunt summary` and Wireshark's Statistics menus (Conversations, Protocol Hierarchy, Endpoints) to learn what's normal in the capture.
2. **Identify the victim** — Find internal hosts, their hostnames (DHCP, NBNS, Kerberos), and user accounts.
3. **Hunt** — Run the detection modules and manual filters:
   - `dns` — suspicious lookups
   - `http.request` / `tls.handshake.type == 1` — outbound web and TLS connections
   - `beacon` — periodic callbacks
   - `scan` — reconnaissance or lateral movement
4. **Pivot** — From each suspicious indicator, look for related activity before and after.
5. **Build the timeline** — Order events from initial access to C2.
6. **Assess and report** — Write key judgments with confidence levels and map to ATT&CK.

## Detection design notes

Record your threshold choices, what you tested, false positives you hit, and how you adjusted. This section is what shows reviewers you think like a detection engineer.

### Beacon detection
Connection starts are TCP SYNs without ACK, de-duplicated by source port so SYN retransmissions don't create fake short gaps. Starts are grouped by (source, destination, destination port) and the gaps between them are scored two ways: the coefficient of variation (stdev ÷ mean) and a robust version (1.4826 × MAD ÷ median). The robust score tolerates a few odd gaps, like a missed check-in or a host waking from sleep. A group is flagged if either score is at or below `max_jitter` (default 0.2) and the median gap is at least `min_interval_seconds` (default 1 s), so a burst of parallel connections from a single page load isn't mistaken for a timer.

**Handling jitter:** malware that randomizes its sleep (for example ±50%) will score above 0.2. Raising `max_jitter` catches it, but also flags benign automated traffic (updaters, telemetry, NTP-like polling), so hits need review.

**Synthetic lab result:** flags only 10.0.0.23 → 203.0.113.66:443 (29 connections, median 60.06 s, jitter 0.013). No normal workstation flagged.

### DNS anomaly detection
Three checks per queried name: Shannon entropy of any non-TLD label at least `min_entropy_len` (10) characters long ≥ `entropy_threshold` (3.5); any label longer than `max_label_len` (40); and a parent domain (last two labels) with ≥ `subdomain_threshold` (20) unique subdomains. Reverse lookups (`in-addr.arpa`, `ip6.arpa`) and mDNS (`.local`) are skipped. Each finding records whether the name returned NXDOMAIN.

Short labels are skipped for entropy because a string of n characters can't score above log2(n), so short names are unreliable either way.

**Synthetic lab result:** all 30 tunneling-style queries flagged, 17 of 26 DGA-style names flagged, no normal names flagged. The 9 missed DGA names are 13–17 characters with entropy between 2.93 and 3.46; random strings this short often repeat characters, which pulls entropy down. Lowering the threshold catches more but starts to approach long real words.

**Known false positives:** CDN/cloud hostnames with random-looking IDs; large legitimate domains with many subdomains in long captures. The two-label parent is wrong for suffixes like `.co.uk` (a public-suffix list would fix this).

### Scan detection
A probe is any TCP packet with neither ACK nor RST, which covers SYN and connect scans plus FIN/NULL/Xmas stealth scans. A sliding `window_seconds` (60 s) window counts distinct ports per (source, target) for vertical scans (≥ `port_threshold`, 20) and distinct targets per (source, port) for horizontal scans (≥ `host_threshold`, 20). SYN-ACK and RST replies show which ports were open or closed.

A browser can open port 443 on 20+ servers in a minute, which looks like a horizontal scan by count alone. Its connections succeed, though, so horizontal findings are dropped when more than `max_open_ratio` (0.5) of targets answered open.

**Synthetic lab result:** flags 10.0.0.66 vertical against 10.0.0.10 (150 ports, 4 open, 146 closed) and horizontal on port 445 (40 hosts, no replies). No false positives.

**Not covered yet:** UDP scans, and slow scans spread over longer than the window.

## Limitations

Detectors read packet metadata only, so encrypted payloads aren't inspected. Short captures give beacon detection too few connections to judge. All thresholds are tuned on synthetic data so far and need checking against real benign and malicious captures.
