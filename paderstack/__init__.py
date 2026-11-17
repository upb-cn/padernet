"""The student-implemented TCP/IP stack and course application client.

The framework's ``stackkit.runtime.Runtime`` creates
``paderstack.host.PaderStack`` with the student configuration, link, clock,
random-number generator, and tracer. The runtime delivers incoming Ethernet
frames to the stack on its event-loop thread; outgoing frames use the
injected link. ``PaderStack`` combines the protocol layers:

- ``ethernet`` builds and parses Ethernet II frames.
- ``arp`` resolves next-hop addresses and queues packets while resolution is
  pending.
- ``ipv4`` builds and validates IPv4 packets and selects the next hop.
- ``icmp`` handles ICMP Echo requests and replies.
- ``tcp_wire`` encodes and parses TCP segments and their checksums.
- ``tcp_base`` provides TCP connection management and shared machinery;
  ``tcp_conn`` implements connection behavior and reliable data transfer.
- ``tcp_reno`` implements Reno congestion control.

``paderstack.socket`` exposes an IPv4/TCP socket API with stdlib-style
semantics, and ``paderstack.appclient`` runs the course application protocol
over either that API or Python's standard-library sockets.
"""

from paderstack.host import PaderStack

__all__ = ["PaderStack"]
