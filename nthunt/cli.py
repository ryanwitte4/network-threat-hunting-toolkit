"""Command-line interface: python -m nthunt <command> <pcap>."""

import argparse
import json
import sys

from nthunt import beacon, dns_anomaly, scan_detect, summary
from nthunt.pcap_loader import iter_packets

COMMANDS = {
    "summary": summary.summarize,
    "beacon": beacon.find_beacons,
    "dns": dns_anomaly.find_suspicious_domains,
    "scan": scan_detect.find_scanners,
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="nthunt", description="Network Threat Hunting Toolkit"
    )
    parser.add_argument("command", choices=COMMANDS.keys())
    parser.add_argument("pcap", help="path to a .pcap or .pcapng file")
    args = parser.parse_args(argv)

    try:
        result = COMMANDS[args.command](list(iter_packets(args.pcap)))
    except NotImplementedError as exc:
        print(f"[not built yet] {exc}", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
