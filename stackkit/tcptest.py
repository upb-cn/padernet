"""The client half of a live TCP test (python -m stackkit.control tcp-test NAME).

The gateway's test_start / grade_next reply carries a plan; this client plays the
same generic role for every test: connect to the plan's server (or, when the
plan names a listen_port, listen there and accept the server's connection),
send the plan's bytes, close first if asked, read until EOF, close, and wait
until the connection reaches TIME_WAIT or CLOSED. The outcome goes back to the gateway,
which judges what it saw on the wire. The client never knows what a test
checks.

TcpTestClient.step must run on the stack thread (use Runtime.run_in_stack); it
drives the stack only through the TcpManager / TcpConnection contract.
"""

from __future__ import annotations

import hashlib
from typing import Any

from stackkit.appdata import generate

# states with the handshake done: data may go out, even if the peer's FIN already arrived
_CONNECTED = ("ESTABLISHED", "CLOSE_WAIT")
# states in which the test is over on the client's side
_DONE = ("TIME_WAIT", "CLOSED")


def _ip_bytes(text: str) -> bytes:
    """Dotted-quad text to the four raw bytes the stack's connect takes."""
    return bytes(int(part) for part in text.split("."))


class TcpTestClient:
    """One test's client: polled on the stack thread until it hands over the outcome."""

    def __init__(self, stack: Any, plan: dict[str, Any], now_ms: int) -> None:
        """Take the plan apart; now_ms is the stack clock at the start and sets the deadline."""
        self._tcp = stack.tcp  # the student's TcpManager
        self._plan = plan  # the gateway's plan for this test
        # the test gives up at this stack-clock time and reports client_timeout
        self._deadline = now_ms + int(plan["timeout_ms"])
        # the bytes to transmit, derived from the plan's seed so the gateway can verify them
        self._payload = generate(str(plan["data_seed"]), int(plan["send_bytes"]))
        # whether this side ends the connection first, right after the transmit
        self._close_first = bool(plan["close_first"])
        self._listen_port = int(plan.get("listen_port", 0))  # the accept test: the server connects
        self._listener: Any = None  # the listening socket of the accept test
        self._conn: Any = None  # the TcpConnection, once connected or accepted
        self._phase = "listen" if self._listen_port else "connect"  # then read, then closing
        self._received = bytearray()
        self._error: str | None = None  # client_timeout or the name of the stack's exception

    def step(self, now_ms: int) -> dict[str, Any] | None:
        """Advance the client by one poll; returns the outcome once the test is over."""
        if self._phase == "listen":  # the accept test: wait for the server to connect
            if self._listener is None:  # first poll: open the listener
                self._listener = self._tcp.listen(self._listen_port)
                return None
            if now_ms >= self._deadline:  # nobody connected in time
                self._error = "client_timeout"
                return self._outcome()
            if not self._listener.accept_queue:  # nothing accepted yet
                return None
            self._conn = self._listener.accept_queue.pop(0)
            self._tcp.unlisten(self._listen_port)
            self._phase = "connect"  # established already: the next poll sends and reads
            return None
        if self._conn is None:  # first poll of a connect test: open the connection
            server = _ip_bytes(str(self._plan["server_ip"]))
            self._conn = self._tcp.connect(server, int(self._plan["port"]))
            return None
        conn = self._conn
        state = conn.state.name
        if conn.error is not None:  # refused, reset or retransmissions exhausted
            self._error = type(conn.error).__name__
            return self._outcome()
        if now_ms >= self._deadline:
            self._error = "client_timeout"
            return self._outcome()
        if self._phase == "connect":  # waiting for the handshake
            if state in _CONNECTED:
                if self._payload:  # all at once; the stack's buffer holds it
                    conn.send(self._payload)
                # when this side ends first, our FIN goes out now; the server answers with its own
                if self._close_first:
                    conn.close()
                self._phase = "read"
            elif state == "CLOSED":  # refused or reset before the handshake finished
                return self._outcome()
            return None
        if self._phase == "read":  # drain until the peer's FIN
            chunk = conn.recv(65536)
            self._received += chunk
            if conn.fin_received and not chunk:  # EOF: the peer's FIN arrived, buffer drained
                # the server went first: answer its FIN with ours
                if not self._close_first:
                    conn.close()
                self._phase = "closing"
            elif state == "CLOSED":  # reset while reading
                return self._outcome()
            return None
        if state in _DONE:  # phase closing: wait for TIME_WAIT or CLOSED
            return self._outcome()
        return None

    def _outcome(self) -> dict[str, Any]:
        """The report for the gateway: the error, what was received and the final state."""
        if self._conn is not None:
            state = self._conn.state.name
        else:
            state = "LISTEN" if self._listener is not None else "CLOSED"
        return {
            "error": self._error,
            "received_len": len(self._received),
            "received_sha256": hashlib.sha256(self._received).hexdigest(),
            "final_state": state,
        }
