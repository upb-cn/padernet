"""The contracts between the framework and the student stack.

The student's StackHost receives everything it may use through its
constructor: config, link, clock, rng and tracer. It must never touch real
sockets, real time or global randomness itself — that is what makes the stack
testable under the virtual clock and the in-memory links in stackkit.testing.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Protocol

from stackkit.config import StudentConfig


class TimerHandle(Protocol):
    """What call_later hands back: the one way to cancel a pending timer."""

    def cancel(self) -> None:
        """Cancel the timer; calling this on a fired or cancelled timer is harmless."""


class Clock(Protocol):
    """The stack's only source of time: the current moment and one-shot timers."""

    # milliseconds since the clock started; never goes backwards
    def now_ms(self) -> int: ...

    # run cb once, delay_ms from now, on the event-loop thread
    def call_later(self, delay_ms: int, cb: Callable[[], None]) -> TimerHandle: ...


class Link(Protocol):
    """Where outgoing frames go: the tunnel in a real run, an in-memory link in tests."""

    # hand one complete Ethernet frame to the network; fire and forget
    def send_frame(self, frame: bytes) -> None: ...


class Tracer(Protocol):
    """The stack's structured event log, read by tests and by the cc trace of the online tests."""

    def trace(self, channel: str, **fields: object) -> None:
        """Record one structured event; implementations add t_ms from their clock."""


class StackHost(Protocol):
    """The student's stack as the framework sees it: a sink for received frames."""

    def on_frame(self, frame: bytes) -> None:
        """Called by the framework on the event-loop thread for every received frame."""


# The student's entry class is used as a factory with exactly this signature.
StackFactory = Callable[[StudentConfig, Link, Clock, random.Random, Tracer], StackHost]
