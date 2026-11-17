"""ICMP Echo: type 8 request / type 0 reply, payload returned verbatim."""

from __future__ import annotations

import struct
from dataclasses import dataclass

from paderstack.ipv4 import checksum

ECHO_REPLY = 0  # ICMP echo reply
ECHO_REQUEST = 8  # ICMP echo request

# The ICMP echo header, 8 bytes, followed by the payload
ICMP_ECHO_HEADER = struct.Struct(
    "!"  # network byte order (big-endian), no padding
    "B"  # type: 8 echo request, 0 echo reply
    "B"  # code: 0
    "H"  # checksum (over the whole message)
    "H"  # identifier
    "H"  # sequence number
)


@dataclass(frozen=True)
class Echo:
    """One parsed echo message, request or reply."""

    type: int  # ECHO_REQUEST or ECHO_REPLY
    ident: int  # identifier for the ping run
    seq: int  # sequence number of the ping
    payload: bytes  # the data


def parse_echo(data: bytes) -> Echo | None:
    """Parse an echo request/reply; invalid ICMP packets return None."""
    raise NotImplementedError("parse and verify the ICMP echo header and checksum")


def build_echo(icmp_type: int, ident: int, seq: int, payload: bytes) -> bytes:
    """Build an echo request/reply with its checksum."""
    raise NotImplementedError("pack an ICMP echo header with checksum filled in")
