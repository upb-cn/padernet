"""The readable view of the gateway's `status` reply (python -m stackkit.control status).

Counters are grouped by what they mean for the student: problems in their own
stack (by layer), and traffic the gateway could not deliver to them. Each
counter carries a one-line explanation. Tunnel and session counters (the
tunnel's replay protection at work) are left out: the framework handles them
and the student can neither cause nor fix them. The scenario and its link
statistics appear only once traffic crossed the scenario's link (only the app
traffic of milestone 3 does; pings and the TCP tests never do). `status --json`
prints the raw reply, with all of it, instead.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

ETHERNET, ARP, IPV4, TCP, RATE = "Ethernet", "ARP", "IPv4 / ICMP", "TCP", "Rate limit"
SESSION, DELIVERY, OTHER = "session", "delivery", "Other"
STACK_GROUPS = (ETHERNET, ARP, IPV4, TCP, RATE, OTHER)


@dataclass(frozen=True)
class Reason:
    """Where a drop counter is listed and the one-line explanation printed beside it."""

    group: str  # a layer group of the student's stack, session, delivery or Other
    text: str  # the explanation


REASONS: dict[str, Reason] = {
    # problems in the student's stack, bottom up
    "short_frame": Reason(ETHERNET, "a frame shorter than the 14-byte Ethernet header"),
    "bad_src_mac": Reason(ETHERNET, "the source MAC is not your student_mac"),
    "bad_dst_mac": Reason(
        ETHERNET, "destination MAC not the gateway, the neighbor or broadcast (broadcast: ARP only)"
    ),
    "bad_ethertype": Reason(ETHERNET, "an EtherType other than IPv4 and ARP"),
    "bad_arp": Reason(ARP, "a malformed ARP packet"),
    "arp_spoof": Reason(ARP, "ARP sender IP or MAC that are not yours"),
    "bad_ip_version": Reason(IPV4, "the IPv4 version field is not 4"),
    "bad_ip_ihl": Reason(IPV4, "an IPv4 header with options (IHL is not 5)"),
    "bad_ip_checksum": Reason(IPV4, "a wrong IPv4 header checksum"),
    "bad_ip_length": Reason(IPV4, "an IPv4 total length larger than the frame"),
    "bad_src_ip": Reason(IPV4, "the source IP is not your student_ip"),
    "fragment": Reason(IPV4, "a fragmented IPv4 packet (MF set or a fragment offset)"),
    "wrong_next_hop": Reason(
        IPV4, "wrong destination MAC: the neighbor .3 directly, everything else via the gateway"
    ),
    "unsupported_proto": Reason(IPV4, "a protocol or ICMP type this network does not carry"),
    "bad_icmp": Reason(IPV4, "a malformed ICMP message"),
    "ttl_exceeded": Reason(IPV4, "the TTL ran out at the gateway"),
    "unreachable": Reason(IPV4, "a destination outside your subnet and 10.0.0.0/24"),
    "bad_tcp": Reason(TCP, "a malformed TCP header"),
    "bad_tcp_checksum": Reason(TCP, "a wrong TCP checksum (check the pseudo-header)"),
    "bad_isn": Reason(TCP, "the SYN's sequence number does not follow the ISN formula"),
    "missing_course_option": Reason(TCP, "a segment without the course option"),
    "bad_course_option": Reason(TCP, "the course option's MAC does not verify"),
    "forbidden_option": Reason(
        TCP, "a TCP option other than the course option, NOP and EOL (no MSS option)"
    ),
    "rate_limited": Reason(RATE, "more traffic than the per-student limit allows"),
    # tunnel and session events: framework internals, left out of the readable view
    "old_epoch": Reason(SESSION, "from an earlier session (a newer one of yours took over)"),
    "replay": Reason(SESSION, "a repeated message, normal when commands start back to back"),
    "stale_seq": Reason(SESSION, "a message far older than the rest of its session"),
    "bad_seq": Reason(SESSION, "a message with sequence number 0"),
    "bad_control": Reason(SESSION, "a malformed control request"),
    "unexpected_type": Reason(SESSION, "a tunnel message type the gateway does not accept"),
    # traffic toward the student that could not be delivered
    "offline_drop": Reason(DELIVERY, "arrived while none of your programs was connected"),
    "arp_timeout": Reason(
        DELIVERY, "the gateway's ARP requests for your IP went unanswered (does your stack reply?)"
    ),
    "arp_queue_overflow": Reason(DELIVERY, "more than 32 packets waited for your ARP reply"),
    "backend_unavailable": Reason(DELIVERY, "no server attached to the gateway (ask the staff)"),
    "too_big": Reason(DELIVERY, "a server packet too large for the tunnel (ask the staff)"),
}

# the link statistics rows: the printed label and the key in the reply's impairment counters
_LINK_ROWS = (
    ("delivered", "delivered"),
    ("lost", "loss"),
    ("reordered", "reorder"),
    ("duplicated", "duplicate"),
    ("queue-dropped", "queue_drop"),
)


def _reason(name: str) -> Reason:
    """The Reason of a counter name; an unknown name lands in the Other group."""
    return REASONS.get(name, Reason(OTHER, "(no description)"))


def _counter_lines(counters: dict[str, int], groups: tuple[str, ...]) -> list[str]:
    """The lines for the non-zero counters of the given groups, one indented block per group."""
    lines: list[str] = []
    for group in groups:
        names = sorted(n for n, v in counters.items() if v and _reason(n).group == group)
        if not names:
            continue
        if group != DELIVERY:  # the delivery group has its own section title
            lines.append(f"  {group}")
        for name in names:
            lines.append(f"    {name:<22}{counters[name]:>6}  {_reason(name).text}")
    return lines


def _when(t_ms: int, now_ms: object, wall_now: float | None) -> str:
    """A drop's moment: local time and age when the gateway clock is known."""
    if not isinstance(now_ms, int):  # an older gateway without its clock in the reply
        return f"t={t_ms} ms"
    seconds = max(0, now_ms - t_ms) / 1000
    age = f"{seconds:.0f} s ago" if seconds >= 100 else f"{round(seconds, 1):g} s ago"
    if wall_now is None:
        return age
    clock = time.strftime("%H:%M:%S", time.localtime(wall_now - seconds))
    return f"{clock} ({age})"


# the readable status text: scenario and link statistics, drop counters by group, recent drops
def format_status(reply: dict[str, Any], *, wall_now: float | None = None) -> str:
    """wall_now: the caller's wall clock when the reply arrived (shows drops as local time)."""
    lines: list[str] = []
    impairment = reply.get("impairment")
    if impairment:  # only app traffic crosses the scenario's link
        scenario = reply.get("scenario", "?")
        conditions = reply.get("conditions")
        lines += [
            f"scenario: {scenario} ({conditions})" if conditions else f"scenario: {scenario}",
            "",
            "Link to the app server since the last scenario switch or reset",
        ]
        up, down = impairment.get("up", {}), impairment.get("down", {})
        lines.append(f"  {'':<16}{'to the servers':>16}{'from the servers':>18}")
        for label, key in _LINK_ROWS:
            lines.append(f"  {label:<16}{up.get(key, 0):>16}{down.get(key, 0):>18}")
        lines.append("")

    # the gateway's drop counters: first the student's own problems, then undeliverable traffic
    counters: dict[str, int] = reply.get("counters", {})
    lines += ["Dropped by the gateway: problems in your stack"]
    stack = _counter_lines(counters, STACK_GROUPS)
    lines += stack or ["  none: everything your stack sent passed the gateway's checks"]

    delivery = _counter_lines(counters, (DELIVERY,))
    if delivery:
        lines += ["", "Traffic the gateway could not deliver to you", *delivery]

    # the gateway's drop ring: t_ms, reason, info of the most recent drops, newest last
    drops = reply.get("drops") or []
    if drops:
        now_ms = reply.get("now_ms")
        lines += ["", "Recent drops (newest last)"]
        for t_ms, reason, info in drops:
            when = _when(t_ms, now_ms, wall_now)
            detail = f"  {info}" if info else ""
            lines.append(f"    {when:>22}  {reason}{detail}")
    return "\n".join(lines)
