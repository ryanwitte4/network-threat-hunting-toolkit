# Roadmap

Roughly 12 weeks at a few hours per week. Adjust around coursework.

## Phase 0 — Setup (Week 1)
- [ ] Create GitHub repo and push this scaffold
- [ ] Python virtual environment + `pip install -r requirements.txt`
- [ ] Install Wireshark
- [ ] Download a benign sample capture and open it
- [ ] Turn on GitHub Pages (Settings › Pages › Source: GitHub Actions) and check the web analyzer loads

## Phase 1 — Manual analysis first (Weeks 2–3)
- [ ] Complete one malware-traffic-analysis.net exercise entirely in Wireshark
- [ ] Write Case 01 using the report template, then compare against the answer key
- [ ] Note what was tedious to do by hand (that's what to automate)

## Phase 2 — Summary tool (Weeks 4–5)
- [x] Implement `summary.summarize`
- [ ] Run it against Case 01 and confirm it matches what Wireshark shows

## Phase 3 — Beacon detection (Weeks 6–7)
- [x] Implement `beacon.find_beacons`
- [ ] Test against a capture with known C2 traffic
- [ ] Document thresholds in methodology.md

## Phase 4 — DNS and scan detection (Weeks 8–9)
- [x] Implement `shannon_entropy` + tests
- [x] Implement `dns_anomaly.find_suspicious_domains`
- [x] Implement `scan_detect.find_scanners`
- [ ] Validate scan detection with your own nmap capture

## Phase 5 — Casework (Weeks 10–11)
- [ ] Write Cases 02–04 using both Wireshark and the toolkit
- [ ] Record where the tools helped and where they missed things

## Phase 6 — Polish (Week 12)
- [ ] Update README tables and status
- [ ] Add screenshots or a short demo GIF
- [ ] Write resume bullets and a LinkedIn post
- [ ] Pin the repo on your GitHub profile
