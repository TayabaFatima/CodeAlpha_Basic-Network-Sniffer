#!/usr/bin/env python3
"""
Basic Network Sniffer — captures and displays live network traffic.

Requires administrator/root privileges and Npcap (Windows) or libpcap (Linux/macOS).
"""

from __future__ import annotations

import argparse
import platform
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.all import (
        ARP,
        DNS,
        ICMP,
        IP,
        TCP,
        UDP,
        Ether,
        conf,
        get_if_list,
        sniff,
        wrpcap,
    )
    from scapy.error import Scapy_Exception
except ImportError:
    print("Error: scapy is not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}


class PacketSniffer:
    """Captures network packets and prints structured summaries."""

    def __init__(
        self,
        interface: str | None = None,
        packet_filter: str | None = None,
        count: int = 0,
        timeout: int | None = None,
        output_file: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.interface = interface
        self.packet_filter = packet_filter
        self.count = count
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        self.captured_packets: list = []
        self.stats: Counter = Counter()

    def _protocol_name(self, packet) -> str:
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(ARP):
            return "ARP"
        if packet.haslayer(IP):
            proto = packet[IP].proto
            return PROTOCOL_NAMES.get(proto, f"IP-{proto}")
        if packet.haslayer(Ether):
            return f"Ether-{packet[Ether].type}"
        return "Unknown"

    def _format_endpoints(self, packet) -> tuple[str, str, str]:
        src = dst = info = "-"

        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst

        if packet.haslayer(TCP):
            src = f"{src}:{packet[TCP].sport}"
            dst = f"{dst}:{packet[TCP].dport}"
            flags = packet[TCP].sprintf("%TCP.flags%")
            info = f"flags={flags} seq={packet[TCP].seq}"
        elif packet.haslayer(UDP):
            src = f"{src}:{packet[UDP].sport}"
            dst = f"{dst}:{packet[UDP].dport}"
            info = f"len={len(packet[UDP].payload)}"
        elif packet.haslayer(ICMP):
            info = f"type={packet[ICMP].type} code={packet[ICMP].code}"
        elif packet.haslayer(ARP):
            src = packet[ARP].psrc
            dst = packet[ARP].pdst
            op = "request" if packet[ARP].op == 1 else "reply"
            info = f"who-has {packet[ARP].pdst} ({op})"
        elif packet.haslayer(DNS) and packet.haslayer(UDP):
            qname = packet[DNS].qd.qname.decode(errors="replace") if packet[DNS].qd else "?"
            info = f"query={qname.rstrip('.')}"

        return src, dst, info

    def _print_packet(self, packet, index: int) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        protocol = self._protocol_name(packet)
        src, dst, info = self._format_endpoints(packet)
        length = len(packet)

        self.stats[protocol] += 1

        line = f"[{index:>5}] {timestamp} | {protocol:<6} | {length:>5} B | {src:<22} -> {dst:<22}"
        if info != "-":
            line += f" | {info}"
        print(line)

        if self.verbose:
            packet.show()

    def _on_packet(self, packet) -> None:
        index = len(self.captured_packets) + 1
        self.captured_packets.append(packet)
        self._print_packet(packet, index)

    def _print_banner(self) -> None:
        iface = self.interface or conf.iface
        print("=" * 72)
        print(" Basic Network Sniffer")
        print("=" * 72)
        print(f" Interface : {iface}")
        print(f" Filter    : {self.packet_filter or '(none)'}")
        print(f" Count     : {self.count if self.count else 'unlimited'}")
        print(f" Timeout   : {self.timeout if self.timeout else 'none'}")
        print("=" * 72)
        print(f" {'#':>5}  {'Time':<12} | {'Proto':<6} | {'Size':>5}   | {'Source':<22} -> {'Destination'}")
        print("-" * 72)

    def _print_summary(self) -> None:
        total = len(self.captured_packets)
        print("-" * 72)
        print(f"Captured {total} packet(s).")
        if self.stats:
            print("Protocol breakdown:")
            for proto, count in self.stats.most_common():
                print(f"  {proto:<8} {count}")

    def start(self) -> None:
        self._print_banner()
        print("Listening... Press Ctrl+C to stop.\n")

        try:
            packets = sniff(
                iface=self.interface,
                filter=self.packet_filter,
                prn=self._on_packet,
                store=True,
                count=self.count or 0,
                timeout=self.timeout,
            )
            if not self.captured_packets and packets:
                self.captured_packets = list(packets)
        except PermissionError:
            print("\nError: Permission denied. Run this program as administrator/root.")
            sys.exit(1)
        except Scapy_Exception as exc:
            print(f"\nError: {exc}")
            if platform.system() == "Windows":
                print("On Windows, install Npcap from https://npcap.com/")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\nCapture stopped by user.")
        finally:
            if self.output_file and self.captured_packets:
                wrpcap(self.output_file, self.captured_packets)
                print(f"Saved {len(self.captured_packets)} packet(s) to {self.output_file}")
            self._print_summary()


def list_interfaces() -> None:
    print("Available network interfaces:")
    for name in get_if_list():
        print(f"  - {name}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture and display live network traffic packets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer.py
  python sniffer.py -i "Ethernet" -c 20
  python sniffer.py -f "tcp port 80" -o capture.pcap
  python sniffer.py --list-interfaces
        """,
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (default: system default)",
    )
    parser.add_argument(
        "-f", "--filter",
        dest="packet_filter",
        help='BPF filter expression (e.g. "tcp", "udp port 53", "host 192.168.1.1")',
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Stop after capturing N packets (0 = unlimited)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=None,
        help="Stop after N seconds",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_file",
        help="Save captured packets to a .pcap file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show full packet layer details",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available interfaces and exit",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    sniffer = PacketSniffer(
        interface=args.interface,
        packet_filter=args.packet_filter,
        count=args.count,
        timeout=args.timeout,
        output_file=args.output_file,
        verbose=args.verbose,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
