#!/usr/bin/env python3
"""
network_traffic_analyzer.py

This script uses scapy to capture a specified number of packets from the default
interface and summarises them by protocol.  It prints a summary to stdout when
complete.  Run as root or with sufficient privileges to capture packets.

Example:
    sudo python3 network_traffic_analyzer.py --count 200
"""

import argparse
from collections import Counter
import sys

try:
    from scapy.all import sniff
except ImportError:
    print(
        "Error: scapy is not installed.  Install it with 'pip install scapy'.",
        file=sys.stderr,
    )
    sys.exit(1)


def analyse_packets(packet_count: int) -> None:
    """Capture packet_count packets and print protocol summary."""
    print(f"Capturing {packet_count} packets... Press Ctrl+C to abort.")
    counters = Counter()

    def handle_packet(pkt):
        if pkt.haslayer('TCP'):
            counters['TCP'] += 1
        elif pkt.haslayer('UDP'):
            counters['UDP'] += 1
        elif pkt.haslayer('ICMP'):
            counters['ICMP'] += 1
        else:
            counters['Other'] += 1

    # Capture packets
    sniff(count=packet_count, prn=handle_packet, store=False)

    # Print summary
    print("\nPacket summary:")
    total = sum(counters.values())
    for proto, count in counters.items():
        percentage = (count / total) * 100 if total else 0
        print(f"{proto}: {count} packets ({percentage:.1f}%)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple network packet analyzer")
    parser.add_argument(
        "--count",
        type=int,
        default=100,
        help="Number of packets to capture (default 100)",
    )
    args = parser.parse_args()
    analyse_packets(args.count)


if __name__ == "__main__":
    main()
