"""The provided half of TCP: you need not read this file.

Your TcpConnection (tcp_conn.py) extends TcpConnectionBase. From here you use:
- the fields the constructor sets (listed in TcpConnectionBase),
- self._set_state(state): change the state (never assign self.state),
- self._enter_closed(error): the one way into CLOSED,
- self._own_isn(): your initial sequence number,
- self._reset(error): send a RST and close (giving up after max_retransmissions),
- self._send_segment(flags, seq, ack, payload): build a segment with the window
    and the course option and hand it to the IP layer,
- self._rcv_wnd(): the window you advertise, RCV.WND (the free part of the
    receive buffer),
- self.clock.call_later(ms, callback): a timer.
Everything else here runs on its own: the connection manager and its listeners,
RST in both directions, and the application's send, recv, close and abort.
"""

from __future__ import annotations

import enum
import random
from collections.abc import Callable
from typing import TYPE_CHECKING

from paderstack import ipv4, tcp_wire
from paderstack.tcp_reno import Reno
from paderstack.tcp_wire import FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, MSS, TcpSegment
from stackkit.config import StudentConfig
from stackkit.interfaces import Clock, TimerHandle, Tracer

if TYPE_CHECKING:
    from paderstack.tcp_conn import TcpConnection


class State(enum.Enum):
    """The connection states of RFC 9293 (LISTEN belongs to a listener, not a connection)."""

    # a listener waits for a SYN
    LISTEN = "LISTEN"

    # active open: my SYN is out, waiting for the SYN-ACK
    SYN_SENT = "SYN_SENT"

    # passive open: a SYN came in, my SYN-ACK is out (provided)
    SYN_RCVD = "SYN_RCVD"

    # data flows both ways
    ESTABLISHED = "ESTABLISHED"

    # I closed first: my FIN is out, not yet acknowledged
    FIN_WAIT_1 = "FIN_WAIT_1"

    # my FIN is acknowledged; waiting for the peer's FIN
    FIN_WAIT_2 = "FIN_WAIT_2"

    # all done; lingering 2 x MSL for late segments
    TIME_WAIT = "TIME_WAIT"

    # the peer closed first; waiting for my application to close
    CLOSE_WAIT = "CLOSE_WAIT"

    # my FIN went out after the peer's; waiting for its ACK
    LAST_ACK = "LAST_ACK"

    # no connection
    CLOSED = "CLOSED"


class TcpConnectionBase:
    """The provided part of a connection; your TcpConnection adds the rest.

    The fields below are read or written by the provided code, the socket
    layer or the course tools; keep their names and meanings:
    state           the current state (change it with _set_state)
    error           the exception the application sees (set by _enter_closed)
    on_update       set by the socket layer; _set_state calls it
    iss, irs        your initial sequence number and the peer's
    snd_una         the oldest sequence number you sent that is not yet acknowledged
    snd_nxt         the next sequence number you will send
    snd_wnd         the peer's window
    rcv_nxt         the next sequence number you expect from the peer
    send_buffer     the send buffer: the application's data that is not yet
                    acknowledged, the sent part first (resend from there),
                    then the part you have not sent yet
    fin_pending     the application has called close (stays set)
    recv_buffer     the receive buffer: in-order data the application has not
                    read yet; its size is recv_buffer_bytes of student.toml
    fin_received    the peer's FIN has arrived in order
    rto_initial_ms, rto_max_ms, max_retransmissions, msl_ms
                    the timing parameters of your student.toml
    rto_ms          the retransmission timeout in use: rto_initial_ms, doubled on a
                    timeout (at most rto_max_ms), reset by a new acknowledgment
    cc              the Reno object (tcp_reno.py), created on ESTABLISHED
    rtx_timer, time_wait_timer   your timers; _enter_closed cancels them
    """

    def __init__(
        self,
        manager: TcpManager,
        local_port: int,
        peer_ip: bytes,
        peer_port: int,
    ) -> None:
        """The identity and the contract fields: CLOSED, nothing sent, nothing received."""
        self.manager = manager
        self.config = manager.config  # student.toml
        self.clock: Clock = manager.clock  # clock for timers

        # the connection's identity
        self.local_port = local_port
        self.peer_ip = peer_ip
        self.peer_port = peer_port
        proto = self.config.protocol

        # the contract fields, described in the class docstring
        self.state = State.CLOSED
        self.error: Exception | None = None
        self.on_update: Callable[[], None] = lambda: None
        self.iss = 0
        self.irs = 0
        self.snd_una = 0
        self.snd_nxt = 0
        self.snd_wnd = 0
        self.rcv_nxt = 0
        self.send_buffer = bytearray()
        self.fin_pending = False
        self.recv_buffer = bytearray()
        self.fin_received = False

        # the timing parameters from student.toml
        self.rto_initial_ms = proto.rto_initial_ms
        self.rto_max_ms = proto.rto_max_ms
        self.max_retransmissions = proto.max_retransmissions
        self.msl_ms = proto.msl_ms
        self.rto_ms = proto.rto_initial_ms
        self.cc: Reno | None = None
        self.rtx_timer: TimerHandle | None = None
        self.time_wait_timer: TimerHandle | None = None

    # -- defined by your TcpConnection (tcp_conn.py) ---------------------------
    # Declared here only so that the provided code can call them

    def on_segment(self, segment: TcpSegment) -> None:
        """Every arriving segment except a RST."""
        raise NotImplementedError("defined in tcp_conn.py")

    def open_active(self) -> None:
        """The application connects: start the handshake."""
        raise NotImplementedError("defined in tcp_conn.py")

    def open_passive(self, segment: TcpSegment) -> None:
        """A SYN reached a listening port: answer it."""
        raise NotImplementedError("defined in tcp_conn.py")

    def _send_data(self) -> None:
        """Transmit the buffered data that both windows allow."""
        raise NotImplementedError("defined in tcp_conn.py")

    def _send_fin(self) -> None:
        """Transmit the FIN once the application has finished writing and the data is out."""
        raise NotImplementedError("defined in tcp_conn.py")

    # -- state -----------------------------------------------------------------

    def _set_state(self, new: State) -> None:
        """Change the state; never assign `state` directly.

        On reaching ESTABLISHED it creates the congestion control (cc, with the
        segment size MSS) and hands a passively opened connection to the
        listener's accept queue. It always wakes the socket layer (on_update).
        """
        old = self.state
        self.state = new
        if new is State.ESTABLISHED and self.cc is None:
            proto = self.config.protocol
            self.cc = Reno(
                MSS, proto.initial_cwnd_segments, proto.dupack_threshold, self.manager.tracer
            )
        # a passive open completed: the listener's accept may now hand the connection out
        if new is State.ESTABLISHED and old is State.SYN_RCVD:
            self.manager.deliver_accept(self)
        self.on_update()

    def _enter_closed(self, error: Exception | None) -> None:
        """The one way into CLOSED (refusal, reset, giving up, the end of a close, abort).

        Cancels rtx_timer and time_wait_timer, records `error` unless an earlier
        one is set (the application sees it), enters CLOSED and removes the
        connection from the manager.
        """
        for timer in (self.rtx_timer, self.time_wait_timer):
            if timer is not None:
                timer.cancel()
        self.rtx_timer = self.time_wait_timer = None

        # the first error is the one the application sees
        if error is not None and self.error is None:
            self.error = error
        self._set_state(State.CLOSED)
        self.manager.forget(self)

    def _own_isn(self) -> int:
        """Your initial sequence number for this connection.

        The course derives it from the course key and the four-tuple
        (tcp_wire.derive_isn), so the gateway can check every SYN; any other ISN
        is dropped as bad_isn.
        """
        return tcp_wire.derive_isn(
            self.config.keys.proto_key,
            self.manager.my_ip,
            self.peer_ip,
            self.local_port,
            self.peer_port,
        )

    # -- sending (provided) ----------------------------------------------------

    def _rcv_wnd(self) -> int:
        """The window you advertise (RCV.WND): the free part of recv_buffer, at most 65535."""

        # the fixed size of recv_buffer
        size = self.config.protocol.recv_buffer_bytes
        # what is in it: received, not yet read
        unread = len(self.recv_buffer)
        return max(0, min(size - unread, 65535))

    def _send_segment(self, flags: int, seq: int, ack: int, payload: bytes = b"") -> None:
        """Build one segment of this connection and hand it to the IP layer.

        You choose the flags, seq, the acknowledgment number (rcv_nxt when the
        ACK flag is set, 0 in a SYN) and the payload. The window is _rcv_wnd(),
        the course option is computed from exactly these fields, the segment is
        built with tcp_wire.build and leaves through the stack's send_ipv4.
        """
        course = self.manager.course_option(
            self.peer_ip, self.local_port, self.peer_port, seq, ack, flags, len(payload)
        )
        segment = tcp_wire.build(
            self.manager.my_ip,
            self.peer_ip,
            src_port=self.local_port,
            dst_port=self.peer_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=self._rcv_wnd(),
            payload=payload,
            course=course,
        )
        self.manager.send_ipv4(self.peer_ip, ipv4.PROTO_TCP, segment)

    # -- the application's calls -----------------------------------------------

    def send(self, data: bytes) -> None:
        """App write: into send_buffer, then your _send_data sends what it may."""
        # the application has shut its write side already
        if self.fin_pending:
            raise OSError("the write side is closed; no more sends")

        # CLOSED with an error: the application gets that error, refused, reset or timed out
        if self.state is State.CLOSED:
            raise self.error if self.error is not None else OSError("the connection is closed")

        # also before ESTABLISHED: sent once connected
        self.send_buffer += data
        self._send_data()

    def recv(self, nbytes: int) -> bytes:
        """App read: in-order bytes; a window update goes out when the window reopens.

        The update (a pure ACK) is sent when the read
        lifts the window from below min(MSS, half the buffer) to at least that
        (receiver-side silly window avoidance).
        """
        before = self._rcv_wnd()  # the window before the read
        data = bytes(self.recv_buffer[:nbytes])
        del self.recv_buffer[:nbytes]
        after = self._rcv_wnd()  # and after it

        # silly window avoidance: announce the window again only once it is worth a full segment
        threshold = min(MSS, self.config.protocol.recv_buffer_bytes // 2)
        if before < threshold <= after and self.state is not State.CLOSED:
            self._send_segment(FLAG_ACK, self.snd_nxt, self.rcv_nxt)
        return data

    def close(self) -> None:
        """App closes the write side: your _send_fin sends the FIN once the data is out."""

        # the FIN went out already, or the connection is gone
        if self.state in (State.CLOSED, State.TIME_WAIT, State.LAST_ACK):
            return

        # the write side is shut already: nothing to do
        if self.fin_pending:
            return
        self.fin_pending = True
        self._send_fin()

    def abort(self) -> None:
        """Immediate RST and close (no TIME_WAIT)."""
        self._reset(None)

    # -- RST -------------------------------------------------------------------

    def _reset(self, error: Exception | None) -> None:
        """Send a RST (with ACK, at snd_nxt) and close at once with `error`.

        For abort and for giving up (your _on_rtx_timeout once the
        retransmission limit is reached: self._reset(TimeoutError(...))). No RST
        goes out from CLOSED or TIME_WAIT.
        """
        if self.state not in (State.CLOSED, State.TIME_WAIT):
            self._send_segment(FLAG_RST | FLAG_ACK, self.snd_nxt, self.rcv_nxt)
        self._enter_closed(error)

    def _on_rst(self, segment: TcpSegment) -> None:
        """An arriving RST: check it, then close with the error it means.

        SYN_SENT: valid only with ACK = iss + 1 (the peer refused the SYN):
        ConnectionRefusedError. SYN_RCVD: valid with seq = rcv_nxt:
        ConnectionRefusedError. The other states: valid with seq = rcv_nxt:
        ConnectionResetError. TIME_WAIT and CLOSED ignore it. A RST is never
        answered.
        """
        if self.state is State.SYN_SENT:
            # in SYN_SENT a RST is credible only if it acknowledges my SYN
            if segment.flags & FLAG_ACK and segment.ack == (self.iss + 1) % (1 << 32):
                self._enter_closed(ConnectionRefusedError("connection refused by the peer"))
        elif self.state in (State.CLOSED, State.TIME_WAIT):
            return

        # elsewhere a RST must sit exactly at rcv_nxt
        elif segment.seq == self.rcv_nxt:
            # refused during the handshake, reset after it
            if self.state is State.SYN_RCVD:
                self._enter_closed(ConnectionRefusedError("connection refused by the peer"))
            else:
                self._enter_closed(ConnectionResetError("connection reset by the peer"))

    # -- the manager's entry ---------------------------------------------------

    def _dispatch(self, segment: TcpSegment) -> None:
        """An arriving segment: a RST is handled here, everything else by your on_segment."""
        if segment.flags & FLAG_RST:
            self._on_rst(segment)
        else:
            self.on_segment(segment)


class TcpListener:
    """The passive-open accept queue (the socket layer wraps it into blocking accept)."""

    def __init__(self, port: int) -> None:
        """An empty accept queue for one port."""
        self.port = port  # the listening port

        # completed handshakes, oldest first
        self.accept_queue: list[TcpConnectionBase] = []

        # set by the socket layer: wakes accept
        self.on_update: Callable[[], None] = lambda: None


class TcpManager:
    """Demultiplex by 4-tuple; allocate ephemeral ports; RST unowned segments (RFC 9293).

    For your connections: my_ip, send_ipv4(dst_ip, proto, segment) (the IP
    layer: PaderStack.send_ipv4), course_option(...) (the course option of one
    segment), and tracer (for Reno).
    """

    def __init__(
        self,
        config: StudentConfig,
        clock: Clock,
        rng: random.Random,
        tracer: Tracer,
        my_ip: bytes,
        send_ipv4: Callable[[bytes, int, bytes], None],
    ) -> None:
        """Bind the framework objects; no connections and no listeners yet."""
        self.config = config  # student.toml
        self.clock = clock  # the connections' timers
        self.rng = rng  # ephemeral ports
        self.tracer = tracer  # handed to every connection's Reno
        self.my_ip = my_ip  # my address, 4 bytes
        self.send_ipv4 = send_ipv4  # the IP layer: (dst_ip, proto, segment)
        # (local port, peer IP, peer port) -> connection
        self.connections: dict[tuple[int, bytes, int], TcpConnectionBase] = {}
        self.listeners: dict[int, TcpListener] = {}  # local port -> listener
        # signs the course option and derives ISNs
        self.proto_key = config.keys.proto_key

    def _new_connection(self, local_port: int, peer_ip: bytes, peer_port: int) -> TcpConnection:
        """Create your TcpConnection for a 4-tuple and register it."""
        from paderstack.tcp_conn import TcpConnection  # yours; it imports this module

        conn = TcpConnection(self, local_port, peer_ip, peer_port)
        self.connections[(local_port, peer_ip, peer_port)] = conn
        return conn

    # -- application entry points ----------------------------------------------

    def connect(self, dst_ip: bytes, dst_port: int) -> TcpConnection:
        """Active open; returns the connection in SYN_SENT."""
        # a random ephemeral port that is neither in use for this peer nor listening; 64 tries
        for _ in range(64):
            port = self.rng.randrange(tcp_wire.EPHEMERAL_LO, tcp_wire.EPHEMERAL_HI + 1)
            if (port, dst_ip, dst_port) not in self.connections and port not in self.listeners:
                break
        else:
            raise OSError("no free ephemeral port")
        conn = self._new_connection(port, dst_ip, dst_port)
        conn.open_active()
        return conn

    def listen(self, port: int) -> TcpListener:
        """Start listening on port (the socket layer's listen)."""
        if port in self.listeners:
            raise OSError(f"port {port} is already listening")
        listener = TcpListener(port)
        self.listeners[port] = listener
        return listener

    def unlisten(self, port: int) -> None:
        """Stop listening on port; accepted connections stay, unaccepted ones are aborted."""
        listener = self.listeners.pop(port, None)
        if listener is None:
            return
        # handshakes nobody will accept any more: RST
        for conn in listener.accept_queue:
            conn.abort()
        listener.accept_queue.clear()

    def forget(self, conn: TcpConnectionBase) -> None:
        """Drop a closed connection from the table (called by _enter_closed)."""
        self.connections.pop((conn.local_port, conn.peer_ip, conn.peer_port), None)

    def deliver_accept(self, conn: TcpConnectionBase) -> None:
        """A passive open completed: queue the connection for accept and wake the listener."""
        listener = self.listeners.get(conn.local_port)
        # unlisten happened during the handshake: nobody accepts it, RST
        if listener is None:
            conn.abort()
            return
        listener.accept_queue.append(conn)
        listener.on_update()

    # -- packet entry (called by the host receive path) ------------------------

    def on_packet(self, packet: ipv4.Ipv4Packet) -> None:
        """Validate, parse and dispatch by (local port, peer IP, peer port)."""
        segment = tcp_wire.parse(packet.src, packet.dst, packet.payload)

        # bad checksum or header: silently dropped
        if segment is None:
            return
        conn = self.connections.get((segment.dst_port, packet.src, segment.src_port))

        # an owned 4-tuple: the connection takes it
        if conn is not None:
            conn._dispatch(segment)
            conn.on_update()  # wake the socket layer
            return
        listener = self.listeners.get(segment.dst_port)
        is_pure_syn = segment.flags & FLAG_SYN and not segment.flags & (FLAG_ACK | FLAG_RST)

        # a new passive open
        if listener is not None and is_pure_syn:
            self._new_connection(segment.dst_port, packet.src, segment.src_port).open_passive(
                segment
            )
            return

        # unowned: answer with a RST, but never RST a RST
        if not segment.flags & FLAG_RST:
            self.send_rst_for(packet.src, segment)

    def send_rst_for(self, peer_ip: bytes, segment: TcpSegment) -> None:
        """Build the RST for unowned/invalid segments (both RFC 9293 shapes)."""
        seg_len = len(segment.payload)
        # a SYN and a FIN each take one sequence number: the RST's ack must cover them
        if segment.flags & FLAG_SYN:
            seg_len += 1
        if segment.flags & FLAG_FIN:
            seg_len += 1
        # the segment carried an ACK: the RST sits at that number and acknowledges nothing
        if segment.flags & FLAG_ACK:
            self._emit_raw(
                peer_ip,
                src_port=segment.dst_port,
                dst_port=segment.src_port,
                seq=segment.ack,
                ack=0,
                flags=FLAG_RST,
                window=0,
            )
        # no ACK in it: the RST sits at 0 and acknowledges everything the segment took
        else:
            self._emit_raw(
                peer_ip,
                src_port=segment.dst_port,
                dst_port=segment.src_port,
                seq=0,
                ack=(segment.seq + seg_len) % (1 << 32),
                flags=FLAG_RST | FLAG_ACK,
                window=0,
            )

    # -- the course option, and segments of no connection ----------------------

    def course_option(
        self,
        peer_ip: bytes,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        payload_len: int,
    ) -> tuple[int, int, bytes]:
        """The course option of one segment to peer_ip: (kind, exid, mac8) for tcp_wire.build.

        The MAC covers the given fields, so pass exactly the values the segment
        carries; the gateway drops a segment whose option does not match
        (bad_course_option).
        """
        mac = tcp_wire.segment_mac(
            self.proto_key, self.my_ip, peer_ip, src_port, dst_port, seq, ack, flags, payload_len
        )
        proto = self.config.protocol
        return (proto.course_option_kind, proto.course_option_exid, mac)

    def _emit_raw(
        self,
        peer_ip: bytes,
        *,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        window: int,
    ) -> None:
        """Build one segment of no connection (send_rst_for) and send it."""
        course = self.course_option(peer_ip, src_port, dst_port, seq, ack, flags, 0)
        raw = tcp_wire.build(
            self.my_ip,
            peer_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq=seq,
            ack=ack,
            flags=flags,
            window=window,
            course=course,
        )
        self.send_ipv4(peer_ip, ipv4.PROTO_TCP, raw)
