"""Tunnel message encoding, HMAC authentication and anti-replay.

Standard library only. Both sides use this module: stackkit.tunnel_client on
the student machine and the gateway on the course server. Decode failures raise
TunnelDecodeError with a stable reason string; callers drop silently and count
by reason.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import Any

MAGIC = 0x504E  # "PN"
VERSION = 1
HEADER_LEN = 20
TAG_LEN = 16
# Every datagram fits a 1200-byte outer IPv4 packet, well inside the university
# VPN's MTU of 1300: 1200 - IP 20 - UDP 8 - header 20 - tag 16.
MAX_PAYLOAD = 1136
REPLAY_WINDOW = 1024
_U32_MAX = 0xFFFFFFFF

# The tunnel header, 20 bytes; the payload and the 16-byte tag follow
_HEADER = struct.Struct(
    "!"  # network byte order (big-endian), no padding
    "H"  # magic 0x504E ("PN")
    "B"  # version
    "B"  # message type
    "I"  # student index
    "I"  # epoch
    "I"  # sequence number
    "H"  # payload length
    "H"  # reserved: 0
)


class MsgType(IntEnum):
    """What a datagram carries, from the type field of its header."""

    FRAME = 0x01  # one Ethernet frame of the student's stack, in either direction
    KEEPALIVE = 0x02  # client to gateway every 15 s, empty: keeps the student online
    CONTROL = 0x03  # client to gateway: a JSON request such as attach or status
    CONTROL_REPLY = 0x04  # gateway to client: the JSON answer to a CONTROL request
    NOTICE = 0x05  # gateway to client, unsolicited: a JSON note, e.g. new drop reasons


@dataclass(frozen=True)
class TunnelMessage:
    """One datagram as the code sees it: the header fields and the payload, tag left out."""

    type: MsgType
    student_index: int  # whose session this is; the gateway looks up the HMAC key by it
    epoch: int  # the session: the Unix second the process started, bumped on recovery
    seq: int  # counts up from 1 within an epoch; 0 is never valid
    payload: bytes = b""  # an Ethernet frame or a UTF-8 JSON document, by type


class TunnelEncodeError(ValueError):
    """Invalid field values on the send path (a local bug, not a network event)."""


class TunnelDecodeError(ValueError):
    """Datagram rejected; .reason is one of the tunnel drop reasons."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason  # the stable name the drop counters use


def _tag(key: bytes, header: bytes, payload: bytes) -> bytes:
    """The 16-byte tag: HMAC-SHA256 over header and payload, truncated."""
    return hmac.new(key, header + payload, hashlib.sha256).digest()[:TAG_LEN]


def encode_message(message: TunnelMessage, key: bytes) -> bytes:
    """Serialize and tag one message with the student's key; TunnelEncodeError on bad fields."""
    if not 1 <= message.student_index <= _U32_MAX:
        raise TunnelEncodeError(f"student_index out of range: {message.student_index}")
    if not 0 <= message.epoch <= _U32_MAX:
        raise TunnelEncodeError(f"epoch out of range: {message.epoch}")
    if not 1 <= message.seq <= _U32_MAX:
        raise TunnelEncodeError(f"seq out of range (must be 1..2^32-1): {message.seq}")
    if len(message.payload) > MAX_PAYLOAD:
        raise TunnelEncodeError(f"payload {len(message.payload)} exceeds {MAX_PAYLOAD} bytes")
    header = _HEADER.pack(
        MAGIC,
        VERSION,
        message.type,
        message.student_index,
        message.epoch,
        message.seq,
        len(message.payload),
        0,
    )
    return header + message.payload + _tag(key, header, message.payload)


def decode_message(datagram: bytes, key_lookup: Callable[[int], bytes | None]) -> TunnelMessage:
    """Parse and authenticate one datagram; key_lookup maps student_index to its key."""
    if len(datagram) < HEADER_LEN + TAG_LEN:
        raise TunnelDecodeError("short")
    header, rest = datagram[:HEADER_LEN], datagram[HEADER_LEN:]
    magic, version, type_raw, index, epoch, seq, payload_len, _reserved = _HEADER.unpack(header)
    if magic != MAGIC:
        raise TunnelDecodeError("magic")
    if version != VERSION:
        raise TunnelDecodeError("version")
    if len(rest) != payload_len + TAG_LEN:
        raise TunnelDecodeError("length")
    # an unknown type is a drop reason like any other, not a crash
    try:
        msg_type = MsgType(type_raw)
    except ValueError:
        raise TunnelDecodeError("type") from None
    key = key_lookup(index)
    if key is None:
        raise TunnelDecodeError("unknown_student")
    payload, tag = rest[:payload_len], rest[payload_len:]
    # the tag covers the header too, so no field can be altered; compared in constant time
    if not hmac.compare_digest(tag, _tag(key, header, payload)):
        raise TunnelDecodeError("bad_tag")
    return TunnelMessage(msg_type, index, epoch, seq, payload)


class ReplayWindow:
    """Per-direction anti-replay over (epoch, seq) with a 1024-entry bitmap."""

    # trims the bitmap to the window's width after a shift
    _MASK = (1 << REPLAY_WINDOW) - 1

    def __init__(self) -> None:
        """Start empty: the first message of any epoch is accepted."""
        self._epoch = -1  # the newest epoch accepted so far; -1 until the first message
        self._highest = 0  # the highest seq accepted in that epoch
        self._bits = 0  # bit i set: seq highest - i was seen; bit 0 is highest itself

    @property
    def epoch(self) -> int:
        """The epoch the window tracks, -1 before any message."""
        return self._epoch

    def check(self, epoch: int, seq: int) -> str | None:
        """Return None and record (epoch, seq) if acceptable, else a drop reason."""
        if seq == 0:
            return "bad_seq"
        if epoch > self._epoch:  # a newer session of the peer: start the window over
            self._epoch = epoch
            self._highest = seq
            self._bits = 1
            return None
        if epoch < self._epoch:  # from a session a newer one replaced
            return "old_epoch"
        if seq > self._highest:  # ahead of the window: slide it forward
            self._bits = ((self._bits << (seq - self._highest)) | 1) & self._MASK
            self._highest = seq
            return None
        offset = self._highest - seq
        if offset >= REPLAY_WINDOW:  # too far behind: out of the window
            return "stale_seq"
        if self._bits >> offset & 1:  # already seen
            return "replay"
        self._bits |= 1 << offset
        return None


def encode_json(obj: dict[str, Any]) -> bytes:
    """Compact UTF-8 JSON for a control request, reply or notice payload."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def decode_json(payload: bytes) -> dict[str, Any]:
    """Parse a CONTROL/CONTROL_REPLY/NOTICE payload; raises TunnelDecodeError("json")."""
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TunnelDecodeError("json") from None
    if not isinstance(obj, dict):
        raise TunnelDecodeError("json")
    return obj
