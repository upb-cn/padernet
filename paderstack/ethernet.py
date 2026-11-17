"""Ethernet II frames.

Layout: destination MAC (6 bytes) + source MAC (6 bytes) + EtherType
(2 bytes, big-endian) + payload. No 802.1Q handling; no minimum-length
padding required (the gateway does not check it).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ETHERTYPE_IPV4 = 0x0800  # IPv4
ETHERTYPE_ARP = 0x0806  # ARP
BROADCAST = b"\xff" * 6  # broadcast MAC

# The Ethernet II header, 14 bytes, followed by the payload
ETHERNET_HEADER = struct.Struct(
    "!"  # network byte order (big-endian), no padding
    "6s"  # destination MAC
    "6s"  # source MAC
    "H"  # EtherType
)


@dataclass(frozen=True)
class EthernetFrame:
    """One parsed frame (the FCS is not part of what the link delivers)."""

    dst: bytes  # destination MAC
    src: bytes  # source MAC
    ethertype: int  # upper-layer protocol
    payload: bytes  # upper-layer data


def parse(frame: bytes) -> EthernetFrame | None:
    """Parse one frame; returns None for invalid frames."""
    raise NotImplementedError("parse the Ethernet header")


def build(dst: bytes, src: bytes, ethertype: int, payload: bytes) -> bytes:
    """Build one frame (without FCS)."""
    raise NotImplementedError("build the frame")
