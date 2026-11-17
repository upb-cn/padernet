"""ARP (an RFC 826 subset): Ethernet + IPv4 only.

- Answer requests targeting my IP; learn sender mappings from both received requests and replies.
- The cache does not expire: the addresses on this network do not change while your stack runs.
- One send queue per unresolved target; an unanswered request is repeated
  every second until the reply arrives. Never more than 1 request per target
  per second.
"""

from __future__ import annotations

import struct
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field

from stackkit.interfaces import Clock, TimerHandle

OP_REQUEST = 1  # request
OP_REPLY = 2  # reply
RETRY_MS = 1_000  # waiting time before retrying a request (ms)

# The ARP message for Ethernet and IPv4, 28 bytes: all header, no payload
ARP_HEADER = struct.Struct(
    "!"  # network byte order (big-endian), no padding
    "H"  # hardware type: 1 (Ethernet)
    "H"  # protocol type: 0x0800 (IPv4)
    "B"  # hardware address length: 6
    "B"  # protocol address length: 4
    "H"  # operation: 1 request, 2 reply
    "6s"  # sender MAC
    "4s"  # sender IP
    "6s"  # target MAC
    "4s"  # target IP
)


@dataclass(frozen=True)
class ArpPacket:
    """One parsed ARP message."""

    op: int  # request or reply
    sender_mac: bytes  # sender MAC
    sender_ip: bytes  # sender IP
    target_mac: bytes  # target MAC
    target_ip: bytes  # target IP


def parse(data: bytes) -> ArpPacket | None:
    """Parse ARP; invalid ARP packets return None."""
    raise NotImplementedError("check and unpack the ARP header")


def build(
    op: int, sender_mac: bytes, sender_ip: bytes, target_mac: bytes, target_ip: bytes
) -> bytes:
    """Build an ARP packet."""
    raise NotImplementedError("pack per the ARP (RFC 826) layout")


@dataclass
class _Pending:
    """A target being resolved."""

    packets: deque[bytes] = field(default_factory=deque)  # queued packets
    timer: TimerHandle | None = None  # retry timer


class ArpTable:
    """The resolution table: cache and resolution logic."""

    def __init__(
        self,
        clock: Clock,
        my_mac: bytes,
        my_ip: bytes,
        send_ip_frame: Callable[[bytes, bytes], None],
        send_arp_frame: Callable[[bytes, bytes], None],
    ) -> None:
        """Bind the clock, my addresses and the host's frame callbacks; the tables start empty."""
        self._clock = clock  # clock for timers
        self._my_mac = my_mac  # my MAC
        self._my_ip = my_ip  # my IP
        self._send_ip_frame = send_ip_frame  # (mac, ip_packet)
        self._send_arp_frame = send_arp_frame  # (mac, arp_packet)
        self._cache: dict[bytes, bytes] = {}  # ARP cache
        self._pending: dict[bytes, _Pending] = {}  # ongoing

    def send_via(self, next_hop_ip: bytes, ip_packet: bytes) -> None:
        """Send an IPv4 packet via next_hop."""
        raise NotImplementedError("check the cache; on a miss enqueue, and start resolving if new")

    def on_packet(self, data: bytes) -> None:
        """Handle a received ARP."""
        raise NotImplementedError("learn the mapping and reply to requests for my IP")

