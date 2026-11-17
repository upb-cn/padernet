"""student.toml loading and validation. Standard library only.

This is the single source of all per-student parameters inside the student
stack (nothing may be hard-coded). Error messages are student-facing and
name the field at fault.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

# the accepted spellings: a lowercase colon-separated MAC, a 64-digit lowercase hex key
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_HEX_KEY_RE = re.compile(r"^[0-9a-f]{64}$")

# a full segment fits: the course MSS (1000 payload bytes) + 52 bytes of IPv4 and TCP
# headers (20 + 20) with the 12-byte course option
_MIN_LINK_MTU = 1052
_MAX_LINK_MTU = 1122  # a frame (link_mtu + 14-byte Ethernet header) fits one tunnel payload

# the TOML value types _get can check for
_T = TypeVar("_T", int, str, list[Any])


class ConfigError(ValueError):
    """student.toml is missing, lacks a field, or holds an invalid value."""


def _get(table: dict[str, Any], path: str, typ: type[_T]) -> _T:
    """The value at a dotted path in the TOML mapping, type-checked; raises ConfigError."""
    node: Any = table
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            raise ConfigError(f"student.toml is missing the field {path}")
        node = node[part]
    # bool is an int subclass; a true/false where a number belongs is a mistake.
    if not isinstance(node, typ) or (typ is int and isinstance(node, bool)):
        raise ConfigError(f"student.toml field {path} must be of type {typ.__name__}, got {node!r}")
    return node


def _get_port(table: dict[str, Any], path: str) -> int:
    """A port field: an integer in 1-65535."""
    value = _get(table, path, int)
    if not 1 <= value <= 65535:
        raise ConfigError(f"student.toml field {path} must be a port in 1-65535, got {value}")
    return value


def _get_ip(table: dict[str, Any], path: str) -> str:
    """An IPv4 address field, returned as its dotted text."""
    value = _get(table, path, str)
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        raise ConfigError(
            f"student.toml field {path} is not a valid IPv4 address: {value!r}"
        ) from None
    return value


def _get_mac(table: dict[str, Any], path: str) -> str:
    """A MAC address field in lowercase colon notation, returned as text."""
    value = _get(table, path, str)
    if not _MAC_RE.match(value):
        raise ConfigError(
            f"student.toml field {path} is not a lowercase aa:bb:cc:dd:ee:ff MAC: {value!r}"
        )
    return value


def _get_key(table: dict[str, Any], path: str) -> bytes:
    """A 32-byte key field written as 64 hex characters, returned as bytes."""
    value = _get(table, path, str)
    if not _HEX_KEY_RE.match(value):
        raise ConfigError(f"student.toml field {path} must be 64 hex characters (a 32-byte key)")
    return bytes.fromhex(value)


@dataclass(frozen=True)
class Keys:
    """The secrets issued to one student with the config."""

    key_version: int  # the key set this config was issued with; bumped when keys are re-issued
    tunnel_key: bytes  # authenticates every tunnel message between you and the gateway
    proto_key: bytes  # authenticates you to the app server and seeds initial sequence numbers


@dataclass(frozen=True)
class Network:
    """The link the stack lives on: addresses, MTU and the gateway's tunnel endpoint."""

    student_ip: str  # the stack's own IPv4 address
    student_mac: str  # the stack's own MAC address; the gateway drops frames from any other
    gateway_ip: str  # the default router: everything off the link goes through it
    gateway_mac: str  # the gateway's MAC address
    neighbor_ip: str  # a simulated host on the link, reached directly rather than via the gateway
    netmask: str  # always 255.255.255.0
    link_mtu: int  # the largest IPv4 packet the link carries
    gateway_host: str  # the course gateway's UDP tunnel endpoint, host part
    gateway_port: int  # the course gateway's UDP tunnel endpoint, port part


@dataclass(frozen=True)
class Protocol:
    """The TCP parameters your stack must use, issued per student; nothing may be hard-coded."""

    initial_cwnd_segments: int  # the initial congestion window, in segments of MSS
    rto_initial_ms: int  # the retransmission timeout a connection starts with; no RTT estimation
    rto_max_ms: int  # the cap on the timeout as it doubles with each loss
    max_retransmissions: int  # retransmissions of one segment before the connection gives up
    dupack_threshold: int  # duplicate ACKs that trigger fast retransmit
    # the receive buffer; the advertised window never exceeds it
    recv_buffer_bytes: int
    msl_ms: int  # maximum segment lifetime; TIME_WAIT lasts twice this
    course_option_kind: int  # kind of the course TCP option, always 253
    course_option_exid: int  # the per-student experiment id carried in the course option


@dataclass(frozen=True)
class StudentConfig:
    """Everything student.toml provides: the only source of per-student parameters in the stack."""

    student_index: int  # your number toward the course server; never your student id
    profile_version: int  # bumped when the course re-issues your profile
    assignment: str  # the assignment this config was issued for
    keys: Keys
    network: Network
    protocol: Protocol
    control_port: int  # TCP port of the app server's control connection


def parse_student_config(raw: dict[str, Any]) -> StudentConfig:
    """Validate a parsed student.toml mapping into a StudentConfig."""
    student_index = _get(raw, "student_index", int)
    if not 1 <= student_index <= 16000:
        raise ConfigError(f"student_index must be in 1-16000, got {student_index}")
    profile_version = _get(raw, "profile_version", int)
    if profile_version < 1:
        raise ConfigError(f"profile_version must be >= 1, got {profile_version}")

    key_version = _get(raw, "keys.key_version", int)
    if key_version < 1:
        raise ConfigError(f"keys.key_version must be >= 1, got {key_version}")
    keys = Keys(
        key_version=key_version,
        tunnel_key=_get_key(raw, "keys.tunnel_key"),
        proto_key=_get_key(raw, "keys.proto_key"),
    )

    netmask = _get(raw, "network.netmask", str)
    if netmask != "255.255.255.0":
        raise ConfigError(f"network.netmask must be 255.255.255.0, got {netmask!r}")
    endpoint = _get(raw, "network.gateway_endpoint", str)
    host, _, port_text = endpoint.rpartition(":")
    if not host or not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ConfigError(f"network.gateway_endpoint must be host:port, got {endpoint!r}")
    link_mtu = _get(raw, "network.link_mtu", int)
    if not _MIN_LINK_MTU <= link_mtu <= _MAX_LINK_MTU:
        raise ConfigError(
            f"network.link_mtu must be in {_MIN_LINK_MTU}-{_MAX_LINK_MTU}, got {link_mtu}"
        )
    network = Network(
        student_ip=_get_ip(raw, "network.student_ip"),
        student_mac=_get_mac(raw, "network.student_mac"),
        gateway_ip=_get_ip(raw, "network.gateway_ip"),
        gateway_mac=_get_mac(raw, "network.gateway_mac"),
        neighbor_ip=_get_ip(raw, "network.neighbor_ip"),
        netmask=netmask,
        link_mtu=link_mtu,
        gateway_host=host,
        gateway_port=int(port_text),
    )
    subnet = ipaddress.ip_network(f"{network.gateway_ip}/24", strict=False)
    for field_name in ("student_ip", "neighbor_ip"):
        if ipaddress.ip_address(getattr(network, field_name)) not in subnet:
            raise ConfigError(f"network.{field_name} is not in the same /24 as network.gateway_ip")

    protocol = Protocol(
        initial_cwnd_segments=_get(raw, "protocol.initial_cwnd_segments", int),
        rto_initial_ms=_get(raw, "protocol.rto_initial_ms", int),
        rto_max_ms=_get(raw, "protocol.rto_max_ms", int),
        max_retransmissions=_get(raw, "protocol.max_retransmissions", int),
        dupack_threshold=_get(raw, "protocol.dupack_threshold", int),
        recv_buffer_bytes=_get(raw, "protocol.recv_buffer_bytes", int),
        msl_ms=_get(raw, "protocol.msl_ms", int),
        course_option_kind=_get(raw, "protocol.course_option_kind", int),
        course_option_exid=_get(raw, "protocol.course_option_exid", int),
    )
    if not protocol.rto_initial_ms <= protocol.rto_max_ms:
        raise ConfigError("protocol RTO values must satisfy rto_initial_ms <= rto_max_ms")
    if protocol.course_option_kind != 253:
        raise ConfigError(
            f"protocol.course_option_kind must be 253, got {protocol.course_option_kind}"
        )
    if not 0 <= protocol.course_option_exid <= 0xFFFF:
        raise ConfigError("protocol.course_option_exid must be a 16-bit unsigned integer")
    if not 2048 <= protocol.recv_buffer_bytes <= 65535:
        raise ConfigError(
            f"protocol.recv_buffer_bytes must be in 2048-65535, got {protocol.recv_buffer_bytes}"
        )
    for field_name in (
        "initial_cwnd_segments",
        "max_retransmissions",
        "dupack_threshold",
        "msl_ms",
    ):
        if getattr(protocol, field_name) < 1:
            raise ConfigError(f"protocol.{field_name} must be >= 1")

    # an older student.toml may still carry [scenarios]; the gateway lists them (scenario --list)
    return StudentConfig(
        student_index=student_index,
        profile_version=profile_version,
        assignment=_get(raw, "assignment", str),
        keys=keys,
        network=network,
        protocol=protocol,
        control_port=_get_port(raw, "app.control_port"),
    )


def load_student_config(path: str | Path) -> StudentConfig:
    """Read and validate student.toml; raises ConfigError with a readable message."""
    file = Path(path)
    if not file.exists():
        raise ConfigError(
            f"config file {file} not found; place the student.toml handed out by the course there"
        )
    try:
        raw = tomllib.loads(file.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{file} is not valid TOML: {exc}") from exc
    return parse_student_config(raw)
