"""Virtual clock for deterministic protocol tests.

Timers fire strictly in (deadline, registration order); advance() moves time
to each deadline before running its callback, so a callback reads now_ms() as
its own deadline. Callback exceptions propagate to the advance() caller — in
unit tests that is exactly what you want.
"""

from __future__ import annotations

import heapq
import itertools
from collections.abc import Callable


class VirtualTimer:
    """One scheduled callback of a VirtualClock; the handle call_later hands back."""

    __slots__ = ("cancelled", "cb", "deadline_ms", "seq")

    def __init__(self, deadline_ms: int, seq: int, cb: Callable[[], None]) -> None:
        self.deadline_ms = deadline_ms  # the virtual time it fires at
        self.seq = seq  # registration order: decides among equal deadlines
        self.cb = cb
        self.cancelled = False  # a cancelled timer is skipped when it comes up

    def cancel(self) -> None:
        """Mark the timer so advance skips it; harmless after it fired."""
        self.cancelled = True

    def __lt__(self, other: VirtualTimer) -> bool:
        """Heap order: earlier deadline first, then registration order."""
        return (self.deadline_ms, self.seq) < (other.deadline_ms, other.seq)


class VirtualClock:
    """Clock implementation whose time only moves when advance() is called."""

    def __init__(self, *, start_ms: int = 0, max_events_per_advance: int = 100_000) -> None:
        self._now_ms = start_ms  # the current virtual time
        self._queue: list[VirtualTimer] = []  # a heap: earliest deadline first
        # numbers each timer, so equal deadlines fire in registration order
        self._seq = itertools.count()
        self._max_events = max_events_per_advance  # the runaway-timer guard of advance

    def now_ms(self) -> int:
        """The current virtual time in milliseconds."""
        return self._now_ms

    def call_later(self, delay_ms: int, cb: Callable[[], None]) -> VirtualTimer:
        """Schedule cb delay_ms from now and hand back its cancellable handle; delay_ms >= 0."""
        if delay_ms < 0:
            raise ValueError(f"delay_ms must be >= 0, got {delay_ms}")
        timer = VirtualTimer(self._now_ms + delay_ms, next(self._seq), cb)
        heapq.heappush(self._queue, timer)
        return timer

    def pending(self) -> int:
        """Number of scheduled, not-yet-cancelled timers (diagnostic)."""
        return sum(1 for timer in self._queue if not timer.cancelled)

    def advance(self, delta_ms: int) -> None:
        """Move time forward by delta_ms, firing every timer that becomes due."""
        if delta_ms < 0:
            raise ValueError(f"delta_ms must be >= 0, got {delta_ms}")
        target = self._now_ms + delta_ms
        fired = 0
        while self._queue and self._queue[0].deadline_ms <= target:  # every timer due by target
            timer = heapq.heappop(self._queue)
            if timer.cancelled:
                continue
            fired += 1
            if fired > self._max_events:  # a timer that re-arms itself would never let us finish
                raise RuntimeError(
                    f"more than {self._max_events} timers fired in one advance(); "
                    "almost certainly a timer loop that re-arms itself without progress"
                )
            self._now_ms = timer.deadline_ms  # the callback reads now_ms as its own deadline
            timer.cb()
        self._now_ms = target  # the rest of the step passes with nothing due
