"""Your TCP connection: one stub per concept.

Read the provided on_segment first: it looks at every arriving segment, decides
what it is (a new acknowledgment, a duplicate one, data, a FIN) and calls one
of your stubs for each of those. Everything else is provided in tcp_base.py
(you need not read it): the fields, _set_state, _enter_closed, _own_isn,
_reset, RST, and the application's send, recv, close and
abort.

Sequence numbers are 32-bit and wrap around: add, subtract and compare them
with seq_add, seq_sub, seq_lt and seq_le from tcp_wire.
"""

from __future__ import annotations

from paderstack.tcp_base import State, TcpConnectionBase, TcpManager
from paderstack.tcp_wire import (
    FLAG_ACK,
    FLAG_FIN,
    FLAG_PSH,
    FLAG_SYN,
    MSS,
    TcpSegment,
    seq_add,
    seq_le,
    seq_lt,
    seq_sub,
)


class TcpConnection(TcpConnectionBase):
    """One TCP connection."""

    def __init__(self, manager: TcpManager, local_port: int, peer_ip: bytes, peer_port: int):
        """The provided fields first, then your own."""

        # the provided fields
        super().__init__(manager, local_port, peer_ip, peer_port)


    # -- receiving (provided): dispatches the segment to a stub ----------------

    def on_segment(self, segment: TcpSegment) -> None:
        """An arriving segment of this connection (a RST never comes here)."""

        # SYN_SENT state
        if self.state is State.SYN_SENT:
            syn_ack = segment.flags & FLAG_SYN and segment.flags & FLAG_ACK

            # it acknowledges your SYN
            if syn_ack and segment.ack == seq_add(self.iss, 1):
                self.snd_wnd = segment.window
                self._on_syn_ack(segment)
                self._send_data()
                self._send_fin()

            # ignores everything else
            return

        # SYN_RCVD state
        if self.state is State.SYN_RCVD:
            # the peer's SYN again: your SYN-ACK got lost
            if segment.flags & FLAG_SYN:
                self._send_segment(FLAG_SYN | FLAG_ACK, self.iss, self.rcv_nxt)
                return
            # only the ACK that completes the handshake counts here
            if not segment.flags & FLAG_ACK or segment.ack != self.snd_nxt:
                return

        # TIME_WAIT state
        if self.state is State.TIME_WAIT:
            new_ack = segment.flags & FLAG_ACK and seq_lt(self.snd_una, segment.ack)

            # the ACK of your FIN: the peer's FIN came first
            if new_ack and seq_le(segment.ack, self.snd_nxt):
                self._on_new_ack(segment)
                return

            # the peer's FIN again
            self._send_segment(FLAG_ACK, self.snd_nxt, self.rcv_nxt)
            return

        # the peer's SYN-ACK again: our ACK got lost
        if segment.flags & FLAG_SYN:
            self._send_segment(FLAG_ACK, self.snd_nxt, self.rcv_nxt)
            return

        # past the handshake every segment must carry an ACK
        if not segment.flags & FLAG_ACK:
            return

        # a bad ACK
        if seq_lt(self.snd_nxt, segment.ack):
            self._send_segment(FLAG_ACK, self.snd_nxt, self.rcv_nxt)
            return

        # not an old acknowledgment
        if seq_le(self.snd_una, segment.ack):
            # a duplicate ACK (RFC 5681): the same ack again, nothing else in it
            duplicate = (
                segment.ack == self.snd_una
                and not segment.payload
                and not segment.flags & FLAG_FIN
                and segment.window == self.snd_wnd
                and self.snd_una != self.snd_nxt
            )

            # record the peer's receive window
            self.snd_wnd = segment.window

            # acknowledging new bytes or not
            if segment.ack != self.snd_una:
                self._on_new_ack(segment)
            elif duplicate:
                self._on_dup_ack(segment)

        # CLOSE state

        # the ACK of your FIN in LAST_ACK
        if self.state is State.CLOSED:
            return
        if segment.payload:
            self._on_data(segment)

        # the FIN is in order: right behind the data you accepted
        if segment.flags & FLAG_FIN and seq_add(segment.seq, len(segment.payload)) == self.rcv_nxt:
            self._on_fin(segment)

        # whatever took sequence space, or arrived out of order, is acknowledged right away
        if segment.payload or segment.flags & FLAG_FIN or segment.seq != self.rcv_nxt:
            self._send_segment(FLAG_ACK, self.snd_nxt, self.rcv_nxt)
        self._send_data()  # the acknowledgment may have made room for data
        self._send_fin()  # and a FIN may be waiting

    # -- your stubs ------------------------------------------------------------

    def open_active(self) -> None:
        """The application connects: send the SYN and enter SYN_SENT."""
        raise NotImplementedError("build and send SYN out")

    def open_passive(self, segment: TcpSegment) -> None:
        """A SYN reached a listening port: the manager created this connection for it."""
        raise NotImplementedError("react to a SYN")

    def _on_syn_ack(self, segment: TcpSegment) -> None:
        """SYN_SENT: the SYN-ACK that acknowledges your SYN arrived."""
        raise NotImplementedError("react to SYN-ACK")

    def _on_new_ack(self, segment: TcpSegment) -> None:
        """An acknowledgment of new bytes arrived (segment.ack is beyond snd_una)."""
        raise NotImplementedError("react to a new acknowledgement")

    def _on_data(self, segment: TcpSegment) -> None:
        """An arriving segment containing data as payload (the provided code ACKs it afterwards)."""
        raise NotImplementedError("deal with the data segment")

    def _on_fin(self, segment: TcpSegment) -> None:
        """The peer's FIN arrived in order (right behind its data)."""
        raise NotImplementedError("handle the peer's FIN")

    def _send_data(self) -> None:
        """Send the application's data that may go out now
        (after every received segment, and on send)."""
        raise NotImplementedError("send segments of size MSS")

    def _send_fin(self) -> None:
        """Send your FIN if it is due (after every segment, and on close).

        Due means: the application has closed (fin_pending), every byte of
        send_buffer has been sent (only bytes in flight are left in it), and
        the FIN has not gone out yet (remember that in a field of your own).
        """
        raise NotImplementedError("send out a FIN if it is due")

    def _on_dup_ack(self, segment: TcpSegment) -> None:
        """A duplicate ACK arrived."""
        raise NotImplementedError("trigger fast retransmit if Reno says so")

    def _on_rtx_timeout(self) -> None:
        """The retransmission timer fired.

        Resend only the oldest unacknowledged segment, unchanged (its bytes
        are the front of send_buffer), and count its timeouts in a row; once
        it was resent max_retransmissions times, give up with
        self._reset(TimeoutError(...)).
        """
        raise NotImplementedError("handle timeout and retransmit with exponential backoff")
