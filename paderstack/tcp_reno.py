"""Reno congestion control (RFC 5681 subset as pinned by the course; floor division).

Every cwnd or ssthresh change emits one structured record via
tracer.trace("cc", ...): {t_ms, cwnd, ssthresh, flight, event} with event in
{ack, dupack, fast_retx, recovery_exit, timeout} (t_ms added by the tracer).
"""

from __future__ import annotations

from stackkit.interfaces import Tracer

# as good as infinite: slow start until the first loss
INITIAL_SSTHRESH = 65535


class Reno:
    """The congestion-control state of one connection, in bytes.

    Contract (the tests read them): cwnd, ssthresh, dupacks (duplicate ACKs in
    a row) and in_recovery (inside fast recovery). smss and threshold are the
    segment size and the duplicate-ACK threshold; _trace writes one record on
    the cc trace channel.
    """

    def __init__(
        self,
        smss: int,
        initial_cwnd_segments: int,
        dupack_threshold: int,
        tracer: Tracer,
    ) -> None:
        """Start in slow start."""

        # sender maximum segment size: the unit of every increment
        self.smss = smss

        # duplicate ACKs in a row that trigger a fast retransmit
        self.threshold = dupack_threshold

        # the congestion window, in bytes
        self.cwnd = initial_cwnd_segments * smss

        # slow start below it, congestion avoidance from it on
        self.ssthresh = INITIAL_SSTHRESH

        # duplicate ACKs in a row since the last new ACK
        self.dupacks = 0

        # between a fast retransmit and the new ACK that ends it
        self.in_recovery = False

        # the cc trace channel the tests read
        self._tracer = tracer

    def _trace(self, event: str, flight: int) -> None:
        """One record on the cc channel: the state after a change, and the event that caused it."""
        self._tracer.trace("cc", cwnd=self.cwnd, ssthresh=self.ssthresh, flight=flight, event=event)

    def on_new_ack(self, acked: int, flight: int) -> None:
        """An ACK advancing snd.una: exit recovery, or grow per slow start / CA."""
        raise NotImplementedError("handle new ACK")

    def on_dupack(self, flight: int) -> bool:
        """A duplicate ACK; True tells the caller to fast-retransmit the snd.una segment."""
        raise NotImplementedError("handle duplicate ACK")

    def on_timeout(self, flight: int, *, first_timeout: bool) -> None:
        """Timeout: cwnd back to 1 SMSS."""
        raise NotImplementedError("handle timeout")
