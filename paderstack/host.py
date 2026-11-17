"""PaderStack: the stack entry point (the framework's StackHost contract).

The constructor receives config / link / clock / rng / tracer. on_frame is
called by the framework on the event-loop thread; every send ultimately
leaves through link.send_frame.
"""

from __future__ import annotations

import random
from collections.abc import Callable

from paderstack import arp, ethernet, icmp, ipv4
from paderstack.tcp_base import TcpManager
from stackkit.config import StudentConfig
from stackkit.interfaces import Clock, Link, Tracer

EchoCallback = Callable[[str, int, int, bytes], None]


class PaderStack:
    """The whole stack of one student.

    Contract: the constructor, on_frame, send_ipv4, send_echo_request,
    on_echo_reply and tcp (the TCP manager the socket layer uses).
    Set up for you from student.toml: my_mac, my_ip, gateway_ip, netmask,
    arp_table and tcp; _send_ip_frame and _send_arp_frame put a payload into
    an Ethernet frame and onto the link. _on_icmp (provided) handles an ICMP
    packet for my IP: it answers echo requests and passes echo replies to the
    ping tool.
    """

    def __init__(
        self,
        config: StudentConfig,
        link: Link,
        clock: Clock,
        rng: random.Random,
        tracer: Tracer,
    ) -> None:
        self.config = config  # student.toml
        self.link = link  # frames leave through link.send_frame
        self.clock = clock  # timers
        self.rng = rng  # the only source of randomness (ephemeral ports)
        self.tracer = tracer  # structured trace records
        self.my_mac = bytes.fromhex(config.network.student_mac.replace(":", ""))
        self.my_ip = ipv4.ip_to_bytes(config.network.student_ip)
        self.gateway_ip = ipv4.ip_to_bytes(config.network.gateway_ip)  # the next hop off my subnet
        self.netmask = ipv4.ip_to_bytes(config.network.netmask)  # decides what is on my link

        # resolves next hops, then frames and sends the IPv4 packets
        self.arp_table = arp.ArpTable(
            clock, self.my_mac, self.my_ip, self._send_ip_frame, self._send_arp_frame
        )

        # the ping tool registers it via on_echo_reply
        self._echo_cb: EchoCallback | None = None

        # TCP connection; they send through send_ipv4
        self.tcp = TcpManager(config, clock, rng, tracer, self.my_ip, self.send_ipv4)

    # -- send path -------------------------------------------------------------

    def _send_ip_frame(self, dst_mac: bytes, ip_packet: bytes) -> None:
        """Put an IPv4 packet into a frame to dst_mac and onto the link."""
        self.link.send_frame(
            ethernet.build(dst_mac, self.my_mac, ethernet.ETHERTYPE_IPV4, ip_packet)
        )

    def _send_arp_frame(self, dst_mac: bytes, payload: bytes) -> None:
        """Put an ARP packet into a frame to dst_mac and onto the link."""
        self.link.send_frame(ethernet.build(dst_mac, self.my_mac, ethernet.ETHERTYPE_ARP, payload))

    def send_ipv4(self, dst_ip: bytes, proto: int, payload: bytes) -> None:
        """Build the IPv4 packet and route."""
        raise NotImplementedError("build the packet, pick the next hop by netmask, and then hand to ARP")

    # -- receive path ----------------------------------------------------------

    def on_frame(self, frame: bytes) -> None:
        """Called once per received frame (event-loop thread): the whole receive path.

        Filter the destination MAC (mine or broadcast), dispatch by EtherType:
        ARP goes to self.arp_table.on_packet; IPv4 is validated via ipv4.parse,
        only packets for my IP are accepted, and they are dispatched by protocol:
        ICMP to the provided self._on_icmp, TCP to self.tcp.on_packet. How you
        split this into helpers is up to you.
        """
        raise NotImplementedError("filter and dispatch by EtherType, then by protocol")


    def _on_icmp(self, packet: ipv4.Ipv4Packet) -> None:
        """An ICMP packet for my IP (provided): reply.

        An echo request is answered with an echo reply that returns its
        identifier, sequence number and data unchanged. An echo reply goes to
        the callback the ping tool registered with on_echo_reply, called as
        (source IP text, identifier, sequence number, data).
        """
        echo = icmp.parse_echo(packet.payload)
        if echo is None:
            return

        # reply to a request
        if echo.type == icmp.ECHO_REQUEST:
            reply = icmp.build_echo(icmp.ECHO_REPLY, echo.ident, echo.seq, echo.payload)
            self.send_ipv4(packet.src, ipv4.PROTO_ICMP, reply)

        # a reply to a request we sent, call the ping's callback
        elif echo.type == icmp.ECHO_REPLY and self._echo_cb is not None:
            self._echo_cb(ipv4.ip_to_str(packet.src), echo.ident, echo.seq, echo.payload)

    def send_echo_request(self, dst_ip: str, ident: int, seq: int, payload: bytes) -> None:
        """Send one ICMP echo request (provided; the framework's ping tool calls it)."""
        request = icmp.build_echo(icmp.ECHO_REQUEST, ident, seq, payload)
        self.send_ipv4(ipv4.ip_to_bytes(dst_ip), ipv4.PROTO_ICMP, request)

    def on_echo_reply(self, cb: EchoCallback) -> None:
        """Register the callback that receives echo replies (the ping tool calls this)."""
        self._echo_cb = cb
