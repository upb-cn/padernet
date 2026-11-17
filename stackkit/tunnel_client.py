"""Blocking UDP tunnel client: epoch/seq management, keepalive, control requests.

Standard library only. The Runtime drives this from its event loop thread;
the client itself is synchronous. Reading the process start time (for the
epoch and the first control id) is the one permitted wall-clock use;
everything else takes time from the injected monotonic clock. Error messages
are student-facing.

Every session opens with attach(): client commands are short-lived, so two of
them often start in the same second and share an epoch, and the second one's
first messages would be dropped by the gateway as replays. Each unanswered
attach try bumps the epoch, until the gateway answers, before anything else
is sent; earlier sessions may have bumped the gateway several epochs ahead.
"""

from __future__ import annotations

import itertools
import socket
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from stackkit.tunnel_proto import (
    MAX_PAYLOAD,
    MsgType,
    ReplayWindow,
    TunnelDecodeError,
    TunnelMessage,
    decode_json,
    decode_message,
    encode_json,
    encode_message,
)

KEEPALIVE_INTERVAL_S = 15.0  # send a keepalive after this long without any message
CONTROL_TIMEOUT_S = 1.0  # wait this long for a control reply before resending
CONTROL_RETRIES = 3  # sends of one control request before the epoch is bumped and they repeat
ATTACH_TIMEOUT_S = 0.3  # wait per attach try; each unanswered try bumps the epoch
_last_process_id = 0  # the last control id handed out in this process
_process_id_lock = threading.Lock()


def _next_process_id() -> int:
    """One increasing id sequence per process, never behind the clock in milliseconds.

    A new process never reuses an id whose reply the gateway may still cache
    from an earlier one, and the clients of one process (the CLI opens one per
    test) never reuse each other's.
    """
    global _last_process_id
    with _process_id_lock:
        _last_process_id = max(_last_process_id + 1, int(time.time() * 1000) + 1)
        return _last_process_id


ATTACH_TRIES = 8  # each unanswered try bumps the epoch once
_U32_MAX = 0xFFFFFFFF  # the epoch and seq fields are 32-bit


@dataclass(frozen=True)
class FrameEvent:
    """An Ethernet frame the gateway delivered for the stack."""

    data: bytes  # the raw frame, Ethernet header included


@dataclass(frozen=True)
class NoticeEvent:
    """A JSON notice pushed by the gateway, such as a summary of the frames it dropped."""

    body: dict[str, Any]  # the decoded notice


Event = FrameEvent | NoticeEvent  # what receive hands to the caller


class TunnelClientError(OSError):
    """Tunnel client error (student-facing messages)."""


class TunnelClient:
    """One UDP socket to the gateway; owns send seq, receive window and keepalive."""

    def __init__(
        self,
        host: str,
        port: int,
        student_index: int,
        tunnel_key: bytes,
        *,
        clock: Callable[[], float] = time.monotonic,
        epoch: int | None = None,
        id_base: int | None = None,
        sock: socket.socket | None = None,
    ) -> None:
        """Open the UDP socket to the gateway; the keyword arguments inject test doubles."""
        self._student_index = student_index
        self._key = tunnel_key  # authenticates every message, in both directions
        self._clock = clock  # monotonic seconds, for the keepalive and the timeouts
        # The epoch is the process start wall-clock second (the sanctioned wall-clock read).
        self._epoch = int(time.time()) if epoch is None else epoch
        self._address = f"{host}:{port}"  # for error messages
        # outgoing: seq restarts at 1 with every epoch; incoming: the replay window drops repeats
        self._send_seq = 0
        self._window = ReplayWindow()
        # frames and notices that arrived while a control reply was awaited
        self._events: deque[Event] = deque()
        self._replies: dict[int, dict[str, Any]] = {}  # control replies by request id
        # control ids: the process-wide sequence, or base + 1, base + 2, ... when given
        self._next_id: Callable[[], int] = (
            _next_process_id if id_base is None else itertools.count(id_base + 1).__next__
        )
        self._control_id = id_base if id_base is not None else 0  # the id of the last request sent
        # when the last message went out, for the keepalive
        self._last_send: float | None = None
        self.drop_counts: dict[str, int] = {}  # received datagrams discarded, by reason
        self._sock = sock if sock is not None else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._sock.connect((host, port))
        except OSError as exc:
            raise TunnelClientError(f"cannot reach the gateway at {host}:{port}: {exc}") from exc

    @property
    def epoch(self) -> int:
        """The current epoch; it grows with every unanswered attach try and on a seq wrap."""
        return self._epoch

    @property
    def last_request_id(self) -> int:
        """The id of the most recent control request."""
        return self._control_id

    def close(self) -> None:
        """Close the UDP socket."""
        self._sock.close()

    def __enter__(self) -> TunnelClient:
        """Context manager entry: the client is usable as soon as it exists."""
        return self

    def __exit__(self, *exc_info: object) -> None:
        """Context manager exit: close the socket."""
        self.close()

    # -- sending -----------------------------------------------------------

    def _bump_epoch(self) -> None:
        """Move to the next epoch and restart seq: after a seq wrap or an unanswered request."""
        self._epoch = min(self._epoch + 1, _U32_MAX)
        self._send_seq = 0

    def _send(self, msg_type: MsgType, payload: bytes = b"") -> None:
        """Encode and send one tunnel message with the next seq; records the send time."""
        # seq is 32-bit: wrapping inside one epoch would look like replays to the gateway
        if self._send_seq >= _U32_MAX:
            self._bump_epoch()
        self._send_seq += 1
        message = TunnelMessage(msg_type, self._student_index, self._epoch, self._send_seq, payload)
        self._sock.send(encode_message(message, self._key))
        self._last_send = self._clock()

    def send_frame(self, frame: bytes) -> None:
        """Send one Ethernet frame; raises TunnelClientError if it exceeds the tunnel payload."""
        if len(frame) > MAX_PAYLOAD:
            raise TunnelClientError(
                f"Ethernet frame of {len(frame)} bytes exceeds the tunnel limit of {MAX_PAYLOAD}"
            )
        self._send(MsgType.FRAME, frame)

    def send_keepalive(self) -> None:
        """Send a keepalive now, due or not."""
        self._send(MsgType.KEEPALIVE)

    def maintain(self) -> None:
        """Send a keepalive when one is due; call this regularly."""
        now = self._clock()
        if self._last_send is None or now - self._last_send >= KEEPALIVE_INTERVAL_S:
            self.send_keepalive()

    def next_keepalive_in(self) -> float:
        """Seconds until the next keepalive is due; 0 when nothing was sent yet."""
        if self._last_send is None:
            return 0.0
        return max(0.0, KEEPALIVE_INTERVAL_S - (self._clock() - self._last_send))

    # -- receiving ---------------------------------------------------------

    def fileno(self) -> int:
        """The UDP socket's fd, so an event loop can select() on the client."""
        return self._sock.fileno()

    def _count_drop(self, reason: str) -> None:
        """Count a discarded datagram under its reason."""
        self.drop_counts[reason] = self.drop_counts.get(reason, 0) + 1

    def _key_lookup(self, index: int) -> bytes | None:
        """The key for a student index, as decode_message asks: only our own index is known."""
        return self._key if index == self._student_index else None

    def _recv_once(self, timeout: float) -> TunnelMessage | None:
        """Read one datagram, waiting up to timeout; None on timeout or when it was dropped."""
        if timeout <= 0:  # a poll: never block
            self._sock.setblocking(False)
        else:
            self._sock.settimeout(timeout)
        try:
            datagram = self._sock.recv(2048)
        except (BlockingIOError, TimeoutError):
            return None
        try:
            message = decode_message(datagram, self._key_lookup)
        except TunnelDecodeError as exc:
            self._count_drop(exc.reason)
            return None
        # replay protection: a stale epoch or an already seen seq is dropped
        reason = self._window.check(message.epoch, message.seq)
        if reason is not None:
            self._count_drop(reason)
            return None
        return message

    def _dispatch(self, message: TunnelMessage) -> Event | None:
        """File a decoded message; returns it if it is an Event for the caller."""
        if message.type is MsgType.FRAME:
            return FrameEvent(message.payload)
        if message.type is MsgType.NOTICE:
            try:
                return NoticeEvent(decode_json(message.payload))
            except TunnelDecodeError as exc:
                self._count_drop(exc.reason)
                return None
        if message.type is MsgType.CONTROL_REPLY:
            try:
                body = decode_json(message.payload)
            except TunnelDecodeError as exc:
                self._count_drop(exc.reason)
                return None
            reply_id = body.get("id")
            if isinstance(reply_id, int):
                self._replies[reply_id] = body
                # bounded: the oldest reply ids are forgotten
                if len(self._replies) > 16:
                    self._replies.pop(min(self._replies))
            return None
        self._count_drop("unexpected_type")  # KEEPALIVE/CONTROL never go downstream
        return None

    def receive(self, timeout: float = 0.0) -> Event | None:
        """Next frame or notice, waiting up to timeout; None if nothing arrived."""
        if self._events:  # filed while a control reply was awaited
            return self._events.popleft()
        deadline = self._clock() + timeout
        while True:
            remaining = max(0.0, deadline - self._clock())
            drops_before = sum(self.drop_counts.values())
            message = self._recv_once(remaining)
            if message is not None:
                event = self._dispatch(message)
                if event is not None:
                    return event
            elif sum(self.drop_counts.values()) == drops_before:
                return None  # a real timeout: nothing arrived in the remaining time
            if remaining <= 0:  # the final poll took a datagram that was not for the caller
                return None
            # a dropped datagram, or a control reply filed for request: keep waiting

    # -- control requests ---------------------------------------

    def attach(self) -> None:
        """Open the session: a quick handshake that absorbs same-second epoch collisions."""
        request_id, payload = self._new_request("attach", {})
        for _try in range(ATTACH_TRIES):
            if self._await_reply(request_id, payload, ATTACH_TIMEOUT_S, 1) is not None:
                return
            self._bump_epoch()
        raise TunnelClientError(
            f"no reply from the gateway at {self._address}; check gateway_endpoint "
            "in student.toml and your network connection"
        )

    def _new_request(self, op: str, params: dict[str, Any]) -> tuple[int, bytes]:
        """Allocate the next control id and encode the request body with it."""
        self._control_id = self._next_id()
        return self._control_id, encode_json({"op": op, "id": self._control_id, **params})

    def _await_reply(
        self, request_id: int, payload: bytes, timeout: float, retries: int
    ) -> dict[str, Any] | None:
        """Send the request up to `retries` times; the reply, or None if none came."""
        for _attempt in range(retries):
            self._send(MsgType.CONTROL, payload)
            deadline = self._clock() + timeout
            while True:
                reply = self._replies.pop(request_id, None)
                if reply is not None:
                    return reply
                remaining = deadline - self._clock()
                if remaining <= 0:  # this attempt timed out: resend
                    break
                message = self._recv_once(remaining)
                # frames and notices arriving meanwhile are kept for receive
                if message is not None:
                    event = self._dispatch(message)
                    if event is not None:
                        self._events.append(event)
        return None

    def request(
        self,
        op: str,
        *,
        timeout: float = CONTROL_TIMEOUT_S,
        retries: int = CONTROL_RETRIES,
        **params: Any,
    ) -> dict[str, Any]:
        """Send a control request and wait for its reply; retries, then bumps epoch once."""
        request_id, payload = self._new_request(op, params)
        for round_no in range(2):  # second round after an epoch bump (epoch-bump recovery)
            reply = self._await_reply(request_id, payload, timeout, retries)
            if reply is not None:
                return reply
            if round_no == 0:
                self._bump_epoch()
        raise TunnelClientError(f"control request {op} timed out: the gateway did not reply")
