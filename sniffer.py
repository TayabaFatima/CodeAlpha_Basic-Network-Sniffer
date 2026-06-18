#!/usr/bin/env python3
"""
Basic Network Sniffer — captures and displays live network traffic.

Uses scapy or the standard-library socket module for packet capture.
Requires administrator/root privileges. On Windows, install Npcap for full Layer 2
capture, or use the built-in Layer 3 / socket fallbacks when Npcap is missing.
"""

from __future__ import annotations

import argparse
import platform
import sys
from collections import Counter
from datetime import datetime

try:
    from scapy.error import Scapy_Exception
except ImportError:
    print("Error: scapy is not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

from capture import create_backend, list_interfaces, npcap_install_hint, save_capture
from packet_analyzer import PacketAnalyzer


class PacketSniffer:
    """Captures network packets and prints structured summaries."""

    def __init__(
        self,
        backend: str = "scapy",
        interface: str | None = None,
        packet_filter: str | None = None,
        count: int = 0,
        timeout: int | None = None,
        output_file: str | None = None,
        verbose: bool = False,
        analyze: bool = False,
        show_payload: bool = True,
        show_hex: bool = False,
        max_payload: int = 128,
    ) -> None:
        self.backend_name = backend
        self.interface = interface
        self.packet_filter = packet_filter
        self.count = count
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        self.analyze = analyze
        self.show_payload = show_payload
        self.show_hex = show_hex
        self.captured_packets: list = []
        self.stats: Counter = Counter()
        self.analyzer = PacketAnalyzer(max_payload_bytes=max_payload)
        self.capture = create_backend(
            backend,
            interface=interface,
            packet_filter=packet_filter,
            count=count,
            timeout=timeout,
        )

    def _print_packet(self, packet, index: int) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        protocol = self.analyzer.protocol_name(packet)
        self.stats[protocol] += 1

        if self.analyze:
            print(self.analyzer.format_capture_block(
                packet, index, timestamp, self.show_payload, self.show_hex,
            ))
            print()
            self.analyzer.print_analysis(packet, index)
        elif self.verbose:
            print(self.analyzer.format_capture_block(
                packet, index, timestamp, self.show_payload, self.show_hex,
            ))
            packet.show()
        else:
            print(self.analyzer.format_capture_block(
                packet, index, timestamp, self.show_payload, self.show_hex,
            ))

        print()

    def _on_packet(self, packet) -> None:
        index = len(self.captured_packets) + 1
        self.captured_packets.append(packet)
        self._print_packet(packet, index)

    def _print_banner(self) -> None:
        print("=" * 78)
        print(" Basic Network Sniffer")
        print("=" * 78)
        print(f" Backend   : {self.backend_name}")
        print(f" Mode      : {self.capture.capture_mode}")
        print(f" Interface : {self.capture.interface_label}")
        print(f" Filter    : {self.packet_filter or '(none)'}")
        print(f" Count     : {self.count if self.count else 'unlimited'}")
        print(f" Timeout   : {self.timeout if self.timeout else 'none'}")
        print(f" Payloads  : {'on' if self.show_payload else 'off'}")
        if self.backend_name == "socket" and self.packet_filter:
            print(" Note      : socket backend supports basic filters (ip/tcp/udp/icmp)")
        print("=" * 78)
        print(" Fields shown: source/destination IP, protocol, ports, and payload preview")
        print("-" * 78)

    def _print_summary(self) -> None:
        total = len(self.captured_packets)
        print("-" * 78)
        print(f"Captured {total} packet(s).")
        if self.stats:
            print("Protocol breakdown:")
            for proto, count in self.stats.most_common():
                print(f"  {proto:<8} {count}")
        if self.captured_packets:
            print(self.analyzer.summary(self.captured_packets))

    def start(self) -> None:
        self._print_banner()
        print("Listening... Press Ctrl+C to stop.\n")

        try:
            packets = self.capture.capture(self._on_packet)
            if not self.captured_packets and packets:
                self.captured_packets = list(packets)
        except PermissionError:
            print("\nError: Permission denied. Run this program as administrator/root.")
            sys.exit(1)
        except OSError as exc:
            print(f"\nError: {exc}")
            sys.exit(1)
        except RuntimeError as exc:
            print(f"\nError: {exc}")
            if platform.system() == "Windows":
                print(npcap_install_hint())
            sys.exit(1)
        except Scapy_Exception as exc:
            print(f"\nError: {exc}")
            if platform.system() == "Windows":
                print(npcap_install_hint())
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n\nCapture stopped by user.")
        finally:
            if self.output_file and self.captured_packets:
                save_capture(self.output_file, self.captured_packets)
                print(f"Saved {len(self.captured_packets)} packet(s) to {self.output_file}")
            self._print_summary()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture and display live network traffic packets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer.py
  python sniffer.py --backend scapy -i "Ethernet" -c 20
  python sniffer.py --backend socket -c 10
  python sniffer.py -f "tcp port 80" -o capture.pcap
  python sniffer.py -c 5 --analyze
  python sniffer.py --no-payload
  python sniffer.py --list-interfaces
  python packet_analyzer.py capture.pcap
        """,
    )
    parser.add_argument(
        "-b", "--backend",
        choices=["scapy", "socket"],
        default="scapy",
        help="Capture library: scapy (default) or socket (stdlib raw sockets)",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (default: system default)",
    )
    parser.add_argument(
        "-f", "--filter",
        dest="packet_filter",
        help='BPF filter (scapy) or basic filter ip/tcp/udp/icmp (socket)',
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
        help="Show scapy layer breakdown in addition to packet summary",
    )
    parser.add_argument(
        "-a", "--analyze",
        action="store_true",
        help="Show full structure analysis with hex dump for each packet",
    )
    parser.add_argument(
        "--no-payload",
        action="store_true",
        help="Hide payload preview in output",
    )
    parser.add_argument(
        "--payload-hex",
        action="store_true",
        help="Include a short hex preview of each payload",
    )
    parser.add_argument(
        "--max-payload",
        type=int,
        default=128,
        help="Max payload bytes used for previews and analysis (default: 128)",
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
        backend=args.backend,
        interface=args.interface,
        packet_filter=args.packet_filter,
        count=args.count,
        timeout=args.timeout,
        output_file=args.output_file,
        verbose=args.verbose,
        analyze=args.analyze,
        show_payload=not args.no_payload,
        show_hex=args.payload_hex,
        max_payload=args.max_payload,
    )
    sniffer.start()


if __name__ == "__main__":
    main()
