#!/usr/bin/env python3
"""
Packet Analyzer — inspect captured packets to understand structure and content.

Works with in-memory packets from the sniffer or saved .pcap files.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from typing import Any

try:
    from scapy.all import ARP, DNS, ICMP, IP, Raw, TCP, UDP, Ether, rdpcap
    from scapy.layers.dns import DNSRR
except ImportError:
    print("Error: scapy is not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


TCP_FLAG_BITS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT",
}


class PacketAnalyzer:
    """Breaks packets into layers, fields, and readable payload content."""

    def __init__(self, max_payload_bytes: int = 128) -> None:
        self.max_payload_bytes = max_payload_bytes

    def layer_names(self, packet) -> list[str]:
        return [layer.name for layer in packet.layers()]

    def protocol_name(self, packet) -> str:
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

    def _service_name(self, port: int | None) -> str | None:
        if port is None:
            return None
        return WELL_KNOWN_PORTS.get(port)

    def extract_info(self, packet) -> dict[str, Any]:
        """Extract source/destination, protocol, and payload details for display."""
        info: dict[str, Any] = {
            "protocol": self.protocol_name(packet),
            "src_ip": "-",
            "dst_ip": "-",
            "src_port": None,
            "dst_port": None,
            "src_mac": "-",
            "dst_mac": "-",
            "details": "",
            "payload_size": 0,
            "payload_summary": "(empty)",
            "payload_hex": "",
        }

        if packet.haslayer(Ether):
            info["src_mac"] = packet[Ether].src
            info["dst_mac"] = packet[Ether].dst

        if packet.haslayer(IP):
            info["src_ip"] = packet[IP].src
            info["dst_ip"] = packet[IP].dst

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info["src_port"] = tcp.sport
            info["dst_port"] = tcp.dport
            flags = [TCP_FLAG_BITS[c] for c in tcp.sprintf("%TCP.flags%") if c in TCP_FLAG_BITS]
            service = self._service_name(tcp.dport) or self._service_name(tcp.sport)
            info["details"] = f"flags=[{', '.join(flags) or 'none'}]"
            if service:
                info["details"] += f", service={service}"
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            info["src_port"] = udp.sport
            info["dst_port"] = udp.dport
            service = self._service_name(udp.dport) or self._service_name(udp.sport)
            info["details"] = f"length={udp.len}"
            if service:
                info["details"] += f", service={service}"
        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info["details"] = f"type={icmp.type}, code={icmp.code}"
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            info["src_ip"] = arp.psrc
            info["dst_ip"] = arp.pdst
            op = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
            info["details"] = f"who-has {arp.pdst} ({op})"

        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qd and dns.qd.qname:
                qname = dns.qd.qname.decode(errors="replace").rstrip(".")
                direction = "response" if dns.qr else "query"
                info["details"] = f"DNS {direction}: {qname}"
            if dns.an:
                answers = []
                for rr in dns.an:
                    if isinstance(rr, DNSRR):
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors="replace")
                        name = rr.rrname.decode(errors="replace").rstrip(".")
                        answers.append(f"{name} -> {rdata}")
                if answers:
                    info["details"] += f" | answers: {', '.join(answers[:2])}"

        payload = self.payload_bytes(packet)
        info["payload_size"] = len(payload)
        info["payload_summary"], info["payload_hex"] = self._summarize_payload(packet, payload)
        return info

    def _summarize_payload(self, packet, payload: bytes, max_text: int = 80) -> tuple[str, str]:
        if not payload:
            return "(empty)", ""

        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qd and dns.qd.qname:
                return f"DNS query: {dns.qd.qname.decode(errors='replace').rstrip('.')}", ""

        sample = payload[: self.max_payload_bytes]
        try:
            text = sample.decode("utf-8")
            if text.isprintable() or all(c in "\r\n\t" or c.isprintable() for c in text):
                cleaned = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
                if len(cleaned) > max_text:
                    cleaned = cleaned[:max_text] + "..."
                first_line = cleaned.split("\\n")[0]
                if first_line.startswith(("GET ", "POST ", "PUT ", "HEAD ", "HTTP/")):
                    return first_line, ""
                return cleaned, ""
        except UnicodeDecodeError:
            pass

        hex_preview = " ".join(f"{b:02x}" for b in sample[:16])
        if len(payload) > 16:
            hex_preview += " ..."
        return f"[binary, {len(payload)} bytes]", hex_preview

    def format_capture_block(
        self,
        packet,
        index: int,
        timestamp: str,
        show_payload: bool = True,
        show_hex: bool = False,
    ) -> str:
        """Format one captured packet for live sniffer output."""
        data = self.extract_info(packet)
        lines = [
            f"[{index:>5}] {timestamp} | {data['protocol']:<6} | {len(packet):>5} B",
            f"  Source IP      : {data['src_ip']}"
            + (f":{data['src_port']}" if data["src_port"] is not None else ""),
            f"  Destination IP : {data['dst_ip']}"
            + (f":{data['dst_port']}" if data["dst_port"] is not None else ""),
        ]

        if data["src_mac"] != "-":
            lines.append(f"  Source MAC     : {data['src_mac']}")
            lines.append(f"  Destination MAC: {data['dst_mac']}")

        lines.append(f"  Protocol       : {data['protocol']}")
        if data["details"]:
            lines.append(f"  Details        : {data['details']}")

        if show_payload:
            lines.append(f"  Payload ({data['payload_size']} B): {data['payload_summary']}")
            if show_hex and data["payload_hex"]:
                lines.append(f"  Payload (hex)  : {data['payload_hex']}")

        return "\n".join(lines)

    def layer_stack(self, packet) -> list[tuple[str, dict[str, Any]]]:
        """Return ordered (layer_name, field_dict) pairs for the packet."""
        stack: list[tuple[str, dict[str, Any]]] = []

        if packet.haslayer(Ether):
            eth = packet[Ether]
            stack.append(("Ethernet II", {
                "Destination MAC": eth.dst,
                "Source MAC": eth.src,
                "EtherType": f"0x{eth.type:04x}",
            }))

        if packet.haslayer(ARP):
            arp = packet[ARP]
            stack.append(("ARP", {
                "Operation": "request" if arp.op == 1 else "reply" if arp.op == 2 else arp.op,
                "Sender MAC": arp.hwsrc,
                "Sender IP": arp.psrc,
                "Target MAC": arp.hwdst,
                "Target IP": arp.pdst,
            }))

        if packet.haslayer(IP):
            ip = packet[IP]
            flags = []
            if ip.flags.DF:
                flags.append("DF")
            if ip.flags.MF:
                flags.append("MF")
            stack.append(("IPv4", {
                "Version": ip.version,
                "Header Length": f"{ip.ihl * 4} bytes",
                "Total Length": ip.len,
                "Identification": ip.id,
                "Flags": " ".join(flags) or "none",
                "Fragment Offset": ip.frag,
                "TTL": ip.ttl,
                "Protocol": ip.sprintf("%IP.proto%"),
                "Header Checksum": f"0x{ip.chksum:04x}",
                "Source IP": ip.src,
                "Destination IP": ip.dst,
            }))

        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            stack.append(("ICMP", {
                "Type": icmp.type,
                "Code": icmp.code,
                "Checksum": f"0x{icmp.chksum:04x}",
                "Identifier": getattr(icmp, "id", "-"),
                "Sequence": getattr(icmp, "seq", "-"),
            }))

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flag_str = tcp.sprintf("%TCP.flags%")
            active_flags = [TCP_FLAG_BITS[c] for c in flag_str if c in TCP_FLAG_BITS]
            stack.append(("TCP", {
                "Source Port": tcp.sport,
                "Destination Port": tcp.dport,
                "Sequence Number": tcp.seq,
                "Acknowledgment Number": tcp.ack,
                "Header Length": f"{tcp.dataofs * 4} bytes",
                "Flags": ", ".join(active_flags) or "none",
                "Window Size": tcp.window,
                "Checksum": f"0x{tcp.chksum:04x}",
                "Urgent Pointer": tcp.urgptr,
            }))

        if packet.haslayer(UDP):
            udp = packet[UDP]
            stack.append(("UDP", {
                "Source Port": udp.sport,
                "Destination Port": udp.dport,
                "Length": udp.len,
                "Checksum": f"0x{udp.chksum:04x}",
            }))

        if packet.haslayer(DNS):
            dns = packet[DNS]
            dns_fields: dict[str, Any] = {
                "Transaction ID": dns.id,
                "Query/Response": "response" if dns.qr else "query",
                "Opcode": dns.opcode,
                "Response Code": dns.rcode,
            }
            if dns.qd:
                qd = dns.qd
                qname = qd.qname.decode(errors="replace").rstrip(".") if qd.qname else "?"
                dns_fields["Query Name"] = qname
                dns_fields["Query Type"] = qd.qtype
            answers = []
            if dns.an:
                for rr in dns.an:
                    if isinstance(rr, DNSRR):
                        rdata = rr.rdata
                        if isinstance(rdata, bytes):
                            rdata = rdata.decode(errors="replace")
                        answers.append(f"{rr.rrname.decode(errors='replace').rstrip('.')} -> {rdata}")
            if answers:
                dns_fields["Answers"] = answers
            stack.append(("DNS", dns_fields))

        return stack

    def payload_bytes(self, packet) -> bytes:
        """Return application-layer payload bytes, if any."""
        if packet.haslayer(Raw):
            return bytes(packet[Raw].load)
        if packet.haslayer(TCP):
            return bytes(packet[TCP].payload)
        if packet.haslayer(UDP):
            return bytes(packet[UDP].payload)
        if packet.haslayer(ICMP):
            return bytes(packet[ICMP].payload)
        return b""

    def hex_dump(self, data: bytes, width: int = 16) -> str:
        if not data:
            return "  (no payload)"
        lines = []
        for offset in range(0, len(data), width):
            chunk = data[offset : offset + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            hex_part = hex_part.ljust(width * 3 - 1)
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"  {offset:08x}  {hex_part}  |{ascii_part}|")
        return "\n".join(lines)

    def payload_preview(self, packet) -> dict[str, str]:
        data = self.payload_bytes(packet)
        if not data:
            return {"size": "0 bytes", "preview": "(empty)", "encoding": "n/a"}

        truncated = len(data) > self.max_payload_bytes
        sample = data[: self.max_payload_bytes]
        note = f" (showing first {self.max_payload_bytes} of {len(data)} bytes)" if truncated else ""

        text_preview = sample.decode("utf-8", errors="replace").replace("\r", "\\r").replace("\n", "\\n")
        if len(text_preview) > 80:
            text_preview = text_preview[:80] + "..."

        return {
            "size": f"{len(data)} bytes{note}",
            "preview": text_preview or "(non-text data)",
            "encoding": "utf-8 (best effort)",
            "hex_dump": self.hex_dump(sample) + ("\n  ... truncated ..." if truncated else ""),
        }

    def analyze(self, packet, index: int | None = None) -> str:
        """Return a formatted analysis report for one packet."""
        header = f"Packet #{index}" if index is not None else "Packet"
        lines = [
            "=" * 72,
            f" {header} — Structure & Content Analysis",
            "=" * 72,
            f" Total size : {len(packet)} bytes",
            f" Layer stack: {' → '.join(self.layer_names(packet))}",
            "",
        ]

        for layer_name, fields in self.layer_stack(packet):
            lines.append(f"[{layer_name}]")
            for key, value in fields.items():
                if isinstance(value, list):
                    lines.append(f"  {key}:")
                    for item in value:
                        lines.append(f"    - {item}")
                else:
                    lines.append(f"  {key:<22}: {value}")
            lines.append("")

        payload = self.payload_preview(packet)
        lines.extend([
            "[Payload / Application Data]",
            f"  Size     : {payload['size']}",
            f"  Preview  : {payload['preview']}",
            f"  Encoding : {payload['encoding']}",
            "",
            "[Hex Dump]",
            payload["hex_dump"],
            "=" * 72,
        ])
        return "\n".join(lines)

    def print_analysis(self, packet, index: int | None = None) -> None:
        print(self.analyze(packet, index))

    def summary(self, packets: list) -> str:
        if not packets:
            return "No packets to summarize."

        proto_counts: Counter = Counter()
        size_total = 0
        endpoints: Counter = Counter()

        for pkt in packets:
            size_total += len(pkt)
            if pkt.haslayer(TCP):
                proto_counts["TCP"] += 1
                endpoints[f"{pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}"] += 1
            elif pkt.haslayer(UDP):
                proto_counts["UDP"] += 1
                endpoints[f"{pkt[IP].src}:{pkt[UDP].sport} -> {pkt[IP].dst}:{pkt[UDP].dport}"] += 1
            elif pkt.haslayer(ICMP):
                proto_counts["ICMP"] += 1
            elif pkt.haslayer(ARP):
                proto_counts["ARP"] += 1
            else:
                proto_counts["Other"] += 1

        lines = [
            "",
            "Capture Summary",
            "-" * 40,
            f"Total packets : {len(packets)}",
            f"Total bytes   : {size_total}",
            f"Avg packet    : {size_total // len(packets)} bytes",
            "",
            "Protocols:",
        ]
        for name, count in proto_counts.most_common():
            lines.append(f"  {name:<6} {count}")

        if endpoints:
            lines.extend(["", "Top conversations:"])
            for conv, count in endpoints.most_common(5):
                lines.append(f"  {count:>3}x  {conv}")

        return "\n".join(lines)


def load_packets(path: str) -> list:
    try:
        return list(rdpcap(path))
    except FileNotFoundError:
        print(f"Error: file not found: {path}")
        sys.exit(1)
    except Exception as exc:
        print(f"Error reading {path}: {exc}")
        sys.exit(1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze captured packets to inspect structure and content.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python packet_analyzer.py capture.pcap
  python packet_analyzer.py capture.pcap -n 3
  python packet_analyzer.py capture.pcap --summary-only
        """,
    )
    parser.add_argument("pcap_file", help="Path to a .pcap file to analyze")
    parser.add_argument(
        "-n", "--number",
        type=int,
        default=None,
        help="Analyze a specific packet number (1-based)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print capture summary without per-packet detail",
    )
    parser.add_argument(
        "--max-payload",
        type=int,
        default=128,
        help="Max payload bytes to show in hex dump (default: 128)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    packets = load_packets(args.pcap_file)
    analyzer = PacketAnalyzer(max_payload_bytes=args.max_payload)

    if not packets:
        print("No packets found in file.")
        return

    print(analyzer.summary(packets))

    if args.summary_only:
        return

    if args.number is not None:
        if args.number < 1 or args.number > len(packets):
            print(f"Error: packet number must be between 1 and {len(packets)}")
            sys.exit(1)
        analyzer.print_analysis(packets[args.number - 1], args.number)
        return

    for i, packet in enumerate(packets, start=1):
        analyzer.print_analysis(packet, i)
        if i < len(packets):
            print()


if __name__ == "__main__":
    main()
