# CodeAlpha_NetworkSniffer

**CodeAlpha Cybersecurity Internship — Task 1: Basic Network Sniffer**

A Python network sniffer built with [Scapy](https://scapy.net/) that captures live traffic on a network interface and displays structured, human-readable information about each packet: protocol, source/destination IP and port, TTL, TCP flags, and a safe printable preview of the payload.

## Why build a sniffer?

Understanding how packets travel through a network — and what protocols like TCP, UDP, ICMP and ARP look like at the byte level — is foundational to network security. A sniffer makes traffic analysis, protocol learning, and basic anomaly spotting tangible instead of abstract.

## Features

- Live packet capture on any interface (or auto-selected default)
- Protocol detection: **TCP, UDP, ICMP, ARP** (and raw IP/IPv6 fallback)
- Well-known port labeling (HTTP, HTTPS, DNS, SSH, FTP, etc.)
- Color-coded terminal output per protocol
- TCP flag and ICMP type/code display
- Safe payload preview (non-printable bytes are redacted, not raw-dumped)
- Optional BPF filter (e.g. `tcp port 80`, `udp port 53`, `icmp`)
- Optional packet count limit
- Optional export of the capture to a `.pcap` file for later analysis in Wireshark

## Requirements

- Python 3.8+
- [Npcap](https://npcap.com/) (Windows) or libpcap (Linux/macOS) — required by Scapy for raw capture
- Administrator / root privileges (raw sockets require elevated permissions)

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Sniff everything on the default interface
sudo python3 sniffer.py

# Choose a specific interface
sudo python3 sniffer.py -i eth0

# Only capture HTTP traffic
sudo python3 sniffer.py -f "tcp port 80"

# Stop automatically after 100 packets
sudo python3 sniffer.py -c 100

# Save the capture for Wireshark
sudo python3 sniffer.py -o capture.pcap

# Hide payload preview (metadata only)
sudo python3 sniffer.py --no-payload
```

### Example output

```
=== CodeAlpha Network Sniffer ===
Interface : eth0
Filter    : tcp port 80
Count     : unlimited
Press Ctrl+C to stop.

[14:32:01] TCP    192.168.1.12:54213 -> 142.250.74.46:80 (HTTP)  len=74  ttl=64  flags=S
[14:32:01] TCP    142.250.74.46:80 (HTTP) -> 192.168.1.12:54213  len=74  ttl=51  flags=SA
    payload> GET / HTTP/1.1..Host: example.com....
```

## How it works (high level)

1. `scapy.sniff()` opens a raw socket on the chosen interface and hands every captured packet to a callback function.
2. `describe_packet()` inspects the packet's layers (`Ether`, `IP`/`IPv6`, `TCP`/`UDP`/`ICMP`/`ARP`, `Raw`) to extract the relevant fields.
3. `print_packet()` formats and color-codes that information for the terminal.
4. If a BPF filter is supplied, it is applied at the kernel level (via libpcap) before packets even reach Python — this is far more efficient than filtering in user-space.

## Ethical use disclaimer

This tool is built strictly for **educational purposes** as part of the CodeAlpha internship. Only run it on networks you own or have explicit authorization to monitor. Capturing traffic on networks without permission may be illegal depending on your jurisdiction.

## Author

Othmane — IACS Engineering Student, ENSA Béni Mellal (USMS)
CodeAlpha Cybersecurity Internship
