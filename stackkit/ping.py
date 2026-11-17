"""The ping tool: drives the stack's echo interface via the Runtime.

Application-thread code: sends and callback registration are posted to the
stack thread (run_in_stack); waiting uses StackSync. The student stack must
provide the echo interface: send_echo_request / on_echo_reply.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from stackkit.runtime import Runtime
from stackkit.sockets_base import StackSync


class EchoSender(Protocol):
    """The echo interface of the student stack that ping drives."""

    # emit one ICMP echo request to dst_ip with this identifier, sequence number and data
    def send_echo_request(self, dst_ip: str, ident: int, seq: int, payload: bytes) -> None: ...

    # register the function called with src_ip, ident, seq and data for every echo reply
    def on_echo_reply(self, cb: object) -> None: ...


@dataclass(frozen=True)
class PingReply:
    """One answered echo request."""

    seq: int  # the request's sequence number
    rtt_ms: int  # stack-clock milliseconds from request to reply
    src_ip: str  # who answered
    nbytes: int  # length of the echoed data


@dataclass(frozen=True)
class PingStats:
    """The result of one ping run."""

    sent: int  # requests that went out
    replies: list[PingReply]  # the answers that arrived in time, by seq

    @property
    def received(self) -> int:
        """How many requests were answered."""
        return len(self.replies)


def ping(
    runtime: Runtime,
    dst_ip: str,
    *,
    count: int = 3,
    timeout_ms: int = 1000,
    payload: bytes = b"stackkit-ping",
    ident: int = 0x5343,
) -> PingStats:
    """Send count echo requests in sequence, waiting up to timeout_ms for each."""
    stack = runtime.stack
    if stack is None or not hasattr(stack, "send_echo_request"):
        raise OSError("student stack lacks the send_echo_request / on_echo_reply echo interface")
    sender = cast(EchoSender, stack)
    sync = StackSync()
    send_ms: dict[int, int] = {}
    replies: dict[int, PingReply] = {}  # filled on the stack thread, read here under sync

    def on_reply(src_ip: str, reply_ident: int, seq: int, data: bytes) -> None:
        """Runs on the stack thread for every echo reply: keep ours and wake the waiter."""
        # someone else's reply, or one for a request not of this run
        if reply_ident != ident or seq not in send_ms:
            return
        rtt = runtime.clock.now_ms() - send_ms[seq]
        with sync:  # the application thread waits on sync below
            replies[seq] = PingReply(seq, rtt, src_ip, len(data))
            sync.wake_all()

    # the registration and every request run on the stack thread; this thread only waits
    runtime.run_in_stack(lambda: sender.on_echo_reply(on_reply)).result(timeout=5)
    for seq in range(1, count + 1):

        def send(seq: int = seq) -> None:
            """Stamp and emit request seq; the default argument pins this iteration's seq."""
            send_ms[seq] = runtime.clock.now_ms()
            sender.send_echo_request(dst_ip, ident, seq, payload)

        runtime.run_in_stack(send).result(timeout=5)

        def got_reply(seq: int = seq) -> bool:
            """The wait predicate: the reply to this request has arrived."""
            return seq in replies

        # one request at a time: wait for its reply, or give up on it after timeout_ms
        sync.wait_for(got_reply, timeout_s=timeout_ms / 1000)
    return PingStats(sent=count, replies=[replies[s] for s in sorted(replies)])
