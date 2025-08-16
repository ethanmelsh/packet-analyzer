# Packet Analyzer

Simple packet analysis tool written in Python.  It uses the `scapy` library to sniff network packets on the local interface and then summarises the results by protocol.  The script is intended as a minimal example of network‑traffic analysis for educational and monitoring purposes.

## Features

- Captures a configurable number of packets from the default network interface.
- Counts packets by protocol (TCP, UDP, ICMP, others).
- Prints a summary report at the end of the capture.

## Requirements

The analyzer relies on `scapy`, which you can install via pip.  It requires root privileges to sniff network traffic.

```
pip install -r requirements.txt
sudo python3 network_traffic_analyzer.py --count 100
```

## Usage

```
sudo python3 network_traffic_analyzer.py [--count N]

Options:
  --count N    Number of packets to capture (default: 100)
```

**Note:** Sniffing network traffic typically requires administrative permissions.  Run the script with `sudo` or equivalent privileges.

## Security and Privacy

This script simply counts packets by protocol; it does not store payload data.  Be mindful of applicable laws and regulations when capturing network traffic.
