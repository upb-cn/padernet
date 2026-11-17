"""TCP segment codec according to RFC 793, checksum, ISN derivation and the course option.

The course uses no MSS option: both sides send at most MSS (1000) payload
bytes per segment. Sequence numbers are 32-bit and wrap around: add, subtract
and compare them with seq_add, seq_sub, seq_lt and seq_le. All multi-byte
fields are big-endian. Course option: kind = course_option_kind
(253), len = 12, content ExID (2 bytes) + MAC (8 bytes). The MAC is the
first 8 bytes of HMAC-SHA256 over b"seg" || src_ip(4) || dst_ip(4) ||
src_port(2) || dst_port(2) || seq(4) || ack(4) || flags(1) || payload_len(2),
where flags is the byte at TCP header offset 13 (0-based).
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass

from paderstack.ipv4 import checksum

FLAG_FIN = 0x01  # FIN
FLAG_SYN = 0x02  # SYN
FLAG_RST = 0x04  # RST
FLAG_PSH = 0x08  # PSH
FLAG_ACK = 0x10  # ACK

MSS = 1000  # maximum segment size, fixed for both directions

OPT_EOL = 0  # option kind: end of the options list
OPT_NOP = 1  # option kind: one byte of padding
COURSE_OPT_LEN = 12  # kind, length, ExID (2 bytes) and MAC (8 bytes)
EPHEMERAL_LO = 49152  # the manager draws client ports from this range
EPHEMERAL_HI = 65535  # up to and including this port

# The fixed TCP header, 20 bytes; options follow up to the data offset
TCP_HEADER = struct.Struct(
    "!"  # network byte order (big-endian), no padding
    "H"  # source port
    "H"  # destination port
    "I"  # sequence number
    "I"  # acknowledgment number
    "B"  # data offset (upper 4 bits, header length in 32-bit words), 4 reserved bits
    "B"  # flags: CWR ECE URG ACK PSH RST SYN FIN
    "H"  # receive window
    "H"  # checksum
    "H"  # urgent pointer
)


@dataclass(frozen=True)
class TcpSegment:
    """One parsed segment: checksum verified, options checked and dropped."""

    src_port: int  # source port
    dst_port: int  # destination port
    seq: int  # sequence number in the segment
    ack: int  # expected next sequence number
    flags: int  # the FLAG_* bits
    window: int  # advertised receive window
    payload: bytes  # the data; empty in a pure ACK


def tcp_checksum(src_ip: bytes, dst_ip: bytes, segment: bytes) -> int:
    """Checksum with the IPv4 pseudo header (src, dst, 0, 6, TCP length)."""
    raise NotImplementedError("Internet checksum over pseudo header + segment")


def parse_options(options: bytes) -> None:
    """Check a TCP options area (provided); raises ValueError if it is malformed."""
    i = 0
    while i < len(options):
        kind = options[i]

        # the list ends here; whatever follows is padding
        if kind == OPT_EOL:
            break

        # a single padding byte, no length
        if kind == OPT_NOP:
            i += 1
            continue

        # invalid option: bad length
        if i + 1 >= len(options):
            raise ValueError("TCP option without its length byte")
        length = options[i + 1]
        if length < 2 or i + length > len(options):
            raise ValueError(f"TCP option of kind {kind} with a bad length {length}")
        i += length


def build_options(course: tuple[int, int, bytes] | None) -> bytes:
    """The options area of a segment (provided), NOP-padded to a multiple of 4 bytes.

    course: (kind, exid, mac8), the course option (length 12), the only option
    this stack sends.
    """
    options = b""

    # compute the course option
    if course is not None:
        kind, exid, mac = course
        options += bytes([kind, COURSE_OPT_LEN]) + exid.to_bytes(2, "big") + mac

    # padding
    while len(options) % 4:
        options += bytes([OPT_NOP])
    return options


def parse(src_ip: bytes, dst_ip: bytes, data: bytes) -> TcpSegment | None:
    """Parse and verify one TCP segment; bad checksum or header returns None.

    The options area goes to the provided parse_options.
    """
    raise NotImplementedError("parse and verify the TCP header")


def build(
    src_ip: bytes,
    dst_ip: bytes,
    *,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    window: int,
    payload: bytes = b"",
    course: tuple[int, int, bytes] | None = None,  # (kind, exid, mac8)
) -> bytes:
    """Build a full TCP segment incl. checksum; the options come from build_options."""
    raise NotImplementedError("pack the fixed header, append options and payload, then insert the checksum")


def seq_add(a: int, n: int) -> int:
    """a + n as a sequence number (modulo 2^32); provided."""
    return (a + n) % (1 << 32)


def seq_sub(a: int, b: int) -> int:
    """How far a lies ahead of b (a - b modulo 2^32); provided."""
    return (a - b) % (1 << 32)


def seq_lt(a: int, b: int) -> bool:
    """a comes before b: b lies ahead of a by less than 2^31; provided."""
    return 0 < seq_sub(b, a) < (1 << 31)


def seq_le(a: int, b: int) -> bool:
    """a comes before b, or is b; provided."""
    return a == b or seq_lt(a, b)


def derive_isn(proto_key: bytes, src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int) -> int:
    """ISN: HMAC-SHA256(proto_key, b"isn" || src_ip || dst_ip || u16 ports)[:4], big-endian."""
    message = b"isn" + src_ip + dst_ip + src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big")
    return int.from_bytes(hmac.new(proto_key, message, hashlib.sha256).digest()[:4], "big")


def segment_mac(
    proto_key: bytes,
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload_len: int,
) -> bytes:
    """The course option MAC (8 bytes): HMAC-SHA256 over the segment identity fields."""
    message = (
        b"seg"
        + src_ip
        + dst_ip
        + src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
        + seq.to_bytes(4, "big")
        + ack.to_bytes(4, "big")
        + bytes([flags])
        + payload_len.to_bytes(2, "big")
    )
    return hmac.new(proto_key, message, hashlib.sha256).digest()[:8]
