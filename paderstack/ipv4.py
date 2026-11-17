"""IPv4 according to RFC 791."""

from __future__ import annotations

import struct
from dataclasses import dataclass

PROTO_ICMP = 1  # ICMP protocol number
PROTO_TCP = 6  # TCP protocol number

# The IPv4 header without options, 20 bytes
IPV4_HEADER = struct.Struct(
    "!"  # network byte order (big-endian), no padding
    "B"  # version (upper 4 bits) and IHL (lower 4 bits, in 32-bit words)
    "B"  # DSCP and ECN: 0
    "H"  # total length: header + payload, in bytes
    "H"  # identification: 0 (assume no fragmentation)
    "H"  # flags (DF = 0x4000, MF = 0x2000) and fragment offset (13 bits)
    "B"  # time to live
    "B"  # protocol: 1 ICMP, 6 TCP
    "H"  # header checksum
    "4s"  # source address
    "4s"  # destination address
)


def ip_to_bytes(text: str) -> bytes:
    """Dotted decimal to 4 bytes (helper, provided)."""
    return bytes(int(part) for part in text.split("."))


def ip_to_str(ip: bytes) -> str:
    """4 bytes to dotted decimal (helper, provided)."""
    return ".".join(str(b) for b in ip)


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    raise NotImplementedError("calculate the checksum (apply padding if needed)")


@dataclass(frozen=True)
class Ipv4Packet:
    """One parsed packet: the header fields the stack uses, and the payload."""

    src: bytes  # source IP
    dst: bytes  # destination IP
    proto: int  # protocol: 1 ICMP, 6 TCP
    ttl: int  # time to live as received
    payload: bytes  # the bytes after the header, up to the total length


def parse(data: bytes) -> Ipv4Packet | None:
    """Parse IP packet; any violation returns None (silent drop)."""
    raise NotImplementedError("perform checks and unpack the header")


def build(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    """Build a complete IPv4 packet."""
    raise NotImplementedError("build the header and compute the checksum")
