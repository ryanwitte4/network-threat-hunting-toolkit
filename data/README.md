# Data

PCAP files are kept locally in `data/pcaps/` and are git-ignored. Do not commit them.

## Sources

- **malware-traffic-analysis.net** — real infection traffic with training exercises and answer keys. Archives are password-protected; the password is listed on the site's About page.
- **Wireshark sample captures** — https://wiki.wireshark.org/SampleCaptures (benign/protocol examples, good for testing tools).

## Safe handling

- Many malicious PCAPs contain real malware that can be carved out of the traffic. Analyze the capture; never extract and open files from it on your personal machine.
- Opening a PCAP in Wireshark does not execute anything, but avoid "Export Objects" unless you know what you're doing and are in an isolated environment.
- Keep the password-protected zips as they are until you're ready to analyze.
- In reports, **defang** indicators: `hxxp://evil[.]com`, `192.0.2[.]10`.

## Case log

| Case | Source file | Date downloaded |
|---|---|---|
| 01 | | |
