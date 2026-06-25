#!/usr/bin/env python3
"""
CodeAlpha Cybersecurity Internship - Task 1
Basic Network Sniffer

Captures live network traffic and displays structured information about
each packet: source/destination IP & MAC, protocol, ports, TTL, flags,
and a safe preview of the payload.

Author: Othmane
Usage:
    sudo python3 sniffer.py                       # sniff all traffic on default interface
    sudo python3 sniffer.py -i eth0                # choose interface
    sudo python3 sniffer.py -f "tcp port 80"       # BPF filter (e.g. http only)
    sudo python3 sniffer.py -c 50                  # stop after 50 packets
    sudo python3 sniffer.py -o capture.pcap        # save capture to a pcap file
    sudo python3 sniffer.py --no-payload           # hide payload preview

Requires root/admin privileges to open a raw socket.
"""

import argparse
import datetime
import sys

try:
    from scapy.all import sniff, wrpcap, Ether, IP, IPv6, TCP, UDP, ICMP, ARP, Raw
except ImportError:
    print("[!] Scapy is not installed. Install it with: pip install scapy --break-system-packages")
    sys.exit(1)

# ANSI colors for readable terminal output
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GREY = "\033[90m"


PROTO_COLOR = {
    "TCP": C.BLUE,
    "UDP": C.GREEN,
    "ICMP": C.YELLOW,
    "ARP": C.MAGENTA,
    "OTHER": C.GREY,
}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-ALT",
}

captured_packets = []
packet_count = 0


def port_label(port):
    name = WELL_KNOWN_PORTS.get(port)
    return f"{port} ({name})" if name else str(port)


def safe_payload_preview(payload_bytes, max_len=64):
    """Return a printable preview of raw bytes, redacting non-printable chars."""
    if not payload_bytes:
        return None
    snippet = payload_bytes[:max_len]
    printable = "".join(
        chr(b) if 32 <= b <= 126 else "." for b in snippet
    )
    suffix = "..." if len(payload_bytes) > max_len else ""
    return printable + suffix


def describe_packet(pkt):
    """Build a dict of human-readable fields from a scapy packet."""
    info = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "proto": "OTHER",
        "src": "?",
        "dst": "?",
        "src_port": None,
        "dst_port": None,
        "length": len(pkt),
        "flags": None,
        "ttl": None,
        "payload": None,
    }

    if Ether in pkt:
        info["src_mac"] = pkt[Ether].src
        info["dst_mac"] = pkt[Ether].dst

    if ARP in pkt:
        info["proto"] = "ARP"
        info["src"] = pkt[ARP].psrc
        info["dst"] = pkt[ARP].pdst
        return info

    ip_layer = None
    if IP in pkt:
        ip_layer = pkt[IP]
        info["ttl"] = ip_layer.ttl
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]

    if ip_layer is not None:
        info["src"] = ip_layer.src
        info["dst"] = ip_layer.dst

        if TCP in pkt:
            info["proto"] = "TCP"
            info["src_port"] = pkt[TCP].sport
            info["dst_port"] = pkt[TCP].dport
            info["flags"] = str(pkt[TCP].flags)
        elif UDP in pkt:
            info["proto"] = "UDP"
            info["src_port"] = pkt[UDP].sport
            info["dst_port"] = pkt[UDP].dport
        elif ICMP in pkt:
            info["proto"] = "ICMP"
            info["flags"] = f"type={pkt[ICMP].type} code={pkt[ICMP].code}"

    if Raw in pkt:
        info["payload"] = bytes(pkt[Raw].load)

    return info


def print_packet(info, show_payload=True):
    color = PROTO_COLOR.get(info["proto"], C.GREY)
    header = f"[{info['timestamp']}] {color}{C.BOLD}{info['proto']:<5}{C.RESET}"

    src = info["src"]
    dst = info["dst"]
    if info["src_port"] is not None:
        src += f":{port_label(info['src_port'])}"
    if info["dst_port"] is not None:
        dst += f":{port_label(info['dst_port'])}"

    line = f"{header}  {C.CYAN}{src}{C.RESET} -> {C.CYAN}{dst}{C.RESET}  len={info['length']}"
    if info["ttl"] is not None:
        line += f"  ttl={info['ttl']}"
    if info["flags"] is not None:
        line += f"  flags={info['flags']}"
    print(line)

    if show_payload and info["payload"]:
        preview = safe_payload_preview(info["payload"])
        if preview:
            print(f"    {C.GREY}payload> {preview}{C.RESET}")


def make_handler(args):
    def handle(pkt):
        global packet_count
        packet_count += 1
        info = describe_packet(pkt)
        print_packet(info, show_payload=not args.no_payload)
        if args.output:
            captured_packets.append(pkt)
    return handle


def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 - Basic Network Sniffer (educational use only)."
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: scapy's choice)")
    parser.add_argument("-f", "--filter", default="", help="BPF filter, e.g. 'tcp port 80' or 'udp port 53'")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("-o", "--output", help="Save captured packets to a .pcap file")
    parser.add_argument("--no-payload", action="store_true", help="Do not print payload preview")
    args = parser.parse_args()

    print(f"{C.BOLD}=== CodeAlpha Network Sniffer ==={C.RESET}")
    print(f"Interface : {args.interface or 'default'}")
    print(f"Filter    : {args.filter or 'none (all traffic)'}")
    print(f"Count     : {'unlimited' if args.count == 0 else args.count}")
    print("Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter or None,
            prn=make_handler(args),
            store=False,
            count=args.count if args.count > 0 else 0,
        )
    except PermissionError:
        print(f"{C.RED}[!] Permission denied. Run this script with sudo / as Administrator.{C.RESET}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[*] Capture stopped by user.{C.RESET}")
    finally:
        print(f"\n[*] Total packets captured: {packet_count}")
        if args.output and captured_packets:
            wrpcap(args.output, captured_packets)
            print(f"[*] Saved {len(captured_packets)} packets to {args.output}")


if __name__ == "__main__":
    main()
