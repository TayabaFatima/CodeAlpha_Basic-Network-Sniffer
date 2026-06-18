#!/usr/bin/env python3
"""Packet capture backends using scapy and the standard-library socket module."""

from __future__ import annotations

import platform
import socket
import struct
import sys
import time
from abc import ABC, abstractmethod
from typing import Callable

try:
    from scapy.all import Ether, IP, conf, get_if_list, sniff, wrpcap
    from scapy.error import Scapy_Exception
except ImportError:
    Ether = IP = conf = get_if_list = sniff = wrpcap = None  # type: ignore
    Scapy_Exception = Exception  # type: ignore


PacketCallback = Callable[[object], None]


class CaptureBackend(ABC):
    """Common interface for live packet capture."""

    name: str = "base"
    capture_mode: str = "unknown"

    def __init__(
        self,
        interface: str | None = None,
        packet_filter: str | None = None,
        count: int = 0,
        timeout: int | None = None,
    ) -> None:
        self.interface = interface
        self.packet_filter = packet_filter
        self.count = count
        self.timeout = timeout

    @abstractmethod
    def capture(self, on_packet: PacketCallback) -> list:
        """Capture packets and invoke on_packet for each one."""

    @property
    def interface_label(self) -> str:
        if self.interface:
            return self.interface
        if conf is not None:
            return str(conf.iface)
        return "default"


def npcap_available() -> bool:
    """Return True when Layer 2 capture via Npcap/libpcap is available."""
    if conf is None:
        return False
    if not getattr(conf, "use_pcap", False):
        return False
    if platform.system() == "Windows":
        return bool(getattr(conf, "use_npcap", False))
    return True


def npcap_install_hint() -> str:
    return (
        "Install Npcap (recommended): https://npcap.com/\n"
        "  - Run the installer as Administrator\n"
        "  - Enable 'WinPcap API-compatible Mode'\n"
        "  - Restart your terminal after installing\n"
        "Alternatives without Npcap:\n"
        "  - python sniffer.py --backend scapy   (auto Layer 3 fallback)\n"
        "  - python sniffer.py --backend socket    (Windows raw IP socket)"
    )


class ScapyCapture(CaptureBackend):
    """Capture packets with scapy.sniff() — full protocol parsing and BPF filters."""

    name = "scapy"

    def __init__(self, *args, l3_fallback: bool = True, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.l3_fallback = l3_fallback
        if npcap_available():
            self.capture_mode = "Layer 2 (Ethernet via Npcap/libpcap)"
        else:
            self.capture_mode = "Layer 3 (IP via scapy L3socket)"

    @staticmethod
    def _layer2_unavailable(exc: BaseException) -> bool:
        message = str(exc).lower()
        return "winpcap" in message or "layer 2" in message or "libpcap" in message

    def _sniff_l2(self, on_packet: PacketCallback) -> list:
        self.capture_mode = "Layer 2 (Ethernet via Npcap/libpcap)"
        packets = sniff(
            iface=self.interface,
            filter=self.packet_filter,
            prn=on_packet,
            store=True,
            count=self.count or 0,
            timeout=self.timeout,
        )
        return list(packets) if packets else []

    def _sniff_l3(self, on_packet: PacketCallback) -> list:
        if conf is None or sniff is None:
            raise ImportError("scapy is not installed. Run: pip install -r requirements.txt")

        conf.use_pcap = False
        self.capture_mode = "Layer 3 (IP via scapy L3socket)"

        l3_kwargs: dict = {}
        if self.interface:
            l3_kwargs["iface"] = self.interface
        if self.packet_filter:
            l3_kwargs["filter"] = self.packet_filter

        sock = conf.L3socket(**l3_kwargs)
        try:
            packets = sniff(
                opened_socket=sock,
                prn=on_packet,
                store=True,
                count=self.count or 0,
                timeout=self.timeout,
            )
            return list(packets) if packets else []
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def capture(self, on_packet: PacketCallback) -> list:
        if sniff is None:
            raise ImportError("scapy is not installed. Run: pip install -r requirements.txt")

        if not npcap_available():
            print(
                "Warning: Npcap/WinPcap not detected. Using Layer 3 capture (IP packets only).\n"
                + npcap_install_hint()
                + "\n"
            )
            return self._sniff_l3(on_packet)

        try:
            return self._sniff_l2(on_packet)
        except RuntimeError as exc:
            if self.l3_fallback and self._layer2_unavailable(exc):
                print(
                    "\nWarning: Layer 2 capture failed. Falling back to Layer 3 (IP only).\n"
                    + npcap_install_hint()
                    + "\n"
                )
                return self._sniff_l3(on_packet)
            raise RuntimeError(
                f"{exc}\n\n{npcap_install_hint()}"
            ) from exc


class SocketCapture(CaptureBackend):
    """
    Capture raw frames with socket (stdlib).

    Linux  : AF_PACKET socket (Ethernet frames)
    Windows: raw IP socket with SIO_RCVALL (IP datagrams)
    """

    name = "socket"
    RECV_SIZE = 65535

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._system = platform.system()
        self._ip_only = self._system == "Windows"
        if self._system == "Windows":
            self.capture_mode = "Layer 3 (Windows raw IP socket)"
        elif self._system == "Linux":
            self.capture_mode = "Layer 2 (Linux AF_PACKET)"
        else:
            self.capture_mode = "Layer 3 (raw socket)"

    def _open_socket(self) -> socket.socket:
        if self._system == "Linux":
            return self._open_linux_socket()
        if self._system == "Windows":
            return self._open_windows_socket()
        raise OSError(
            f"Socket capture is not supported on {self._system}. "
            "Use --backend scapy instead."
        )

    def _open_linux_socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if self.interface:
            sock.bind((self.interface, 0))
        return sock

    def _open_windows_socket(self) -> socket.socket:
        host_ip = self._resolve_bind_ip()
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((host_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return sock

    def _resolve_bind_ip(self) -> str:
        if self.interface:
            try:
                return socket.gethostbyname(self.interface)
            except socket.gaierror:
                if self._looks_like_ip(self.interface):
                    return self.interface
        return socket.gethostbyname(socket.gethostname())

    @staticmethod
    def _looks_like_ip(value: str) -> bool:
        parts = value.split(".")
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def _parse_packet(self, raw: bytes):
        if Ether is None:
            raise ImportError("scapy is required to parse raw socket data.")

        if self._ip_only:
            return IP(raw)
        return Ether(raw)

    def _passes_filter(self, packet) -> bool:
        if not self.packet_filter:
            return True

        expr = self.packet_filter.strip().lower()
        if expr in ("ip", "ip6"):
            return packet.haslayer(IP)
        if expr == "tcp" and packet.haslayer(IP):
            return packet[IP].proto == 6
        if expr == "udp" and packet.haslayer(IP):
            return packet[IP].proto == 17
        if expr == "icmp" and packet.haslayer(IP):
            return packet[IP].proto == 1
        return True

    def capture(self, on_packet: PacketCallback) -> list:
        captured: list = []
        deadline = time.time() + self.timeout if self.timeout else None
        sock = self._open_socket()

        print(f"Socket backend: {self._system} ({'IP layer' if self._ip_only else 'Ethernet frames'})")

        try:
            while True:
                if deadline and time.time() >= deadline:
                    break
                if self.count and len(captured) >= self.count:
                    break

                try:
                    sock.settimeout(1.0)
                    raw = sock.recv(self.RECV_SIZE)
                except socket.timeout:
                    continue

                if not raw:
                    continue

                try:
                    packet = self._parse_packet(raw)
                except Exception:
                    continue

                if not self._passes_filter(packet):
                    continue

                captured.append(packet)
                on_packet(packet)
        except PermissionError as exc:
            raise PermissionError(
                "Permission denied for raw socket capture. Run as administrator/root."
            ) from exc
        finally:
            if self._system == "Windows":
                try:
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
            sock.close()

        return captured


def list_interfaces() -> None:
    if get_if_list is None:
        print("Install scapy to list interfaces: pip install -r requirements.txt")
        return
    print("Available network interfaces:")
    for name in get_if_list():
        print(f"  - {name}")


def save_capture(path: str, packets: list) -> None:
    if wrpcap is None:
        raise ImportError("scapy is required to save .pcap files.")
    wrpcap(path, packets)


def create_backend(name: str, **kwargs) -> CaptureBackend:
    backends = {
        "scapy": ScapyCapture,
        "socket": SocketCapture,
    }
    key = name.lower()
    if key not in backends:
        available = ", ".join(backends)
        print(f"Error: unknown backend '{name}'. Choose: {available}")
        sys.exit(1)
    return backends[key](**kwargs)


def describe_ip_header(raw: bytes) -> dict[str, int | str]:
    """Parse an IPv4 header manually with struct (socket-level inspection)."""
    if len(raw) < 20:
        raise ValueError("Packet too short for an IPv4 header.")

    version_ihl, tos, total_len, ident, flags_frag, ttl, proto, checksum, src, dst = struct.unpack(
        "!BBHHHBBH4s4s",
        raw[:20],
    )
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    flags = (flags_frag >> 13) & 0x7
    frag_offset = flags_frag & 0x1FFF

    return {
        "version": version,
        "header_length": ihl,
        "total_length": total_len,
        "ttl": ttl,
        "protocol": proto,
        "flags": flags,
        "fragment_offset": frag_offset,
        "source_ip": socket.inet_ntoa(src),
        "destination_ip": socket.inet_ntoa(dst),
    }
