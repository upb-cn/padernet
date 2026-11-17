"""Thread synchronization for the blocking socket API.

The student stack mutates connection state on the event-loop thread; the
application blocks in socket calls on its own threads. StackSync wraps one
threading.Condition for this pattern:

    sync = StackSync()

    # event-loop thread (inside the stack):
    with sync:
        state.recv_buffer += data
        sync.wake_all()

    # application thread (inside socket.recv):
    if not sync.wait_for(lambda: state.recv_buffer or state.closed, timeout_s):
        raise timeout("...")

wait_for acquires the lock itself and evaluates the predicate under it.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from types import TracebackType


class StackSync:
    """One condition variable shared by the stack thread and the blocking socket calls."""

    def __init__(self) -> None:
        self._cond = threading.Condition()

    def __enter__(self) -> StackSync:
        """Take the lock: with sync: around every state change on the stack thread."""
        self._cond.acquire()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Release the lock."""
        self._cond.release()

    def wake_all(self) -> None:
        """Wake every waiter. Must be called while holding the lock (`with sync:`)."""
        self._cond.notify_all()

    def wait_for(self, predicate: Callable[[], bool], timeout_s: float | None = None) -> bool:
        """Block until predicate() is true or the timeout expires; returns predicate()."""
        with self._cond:
            return self._cond.wait_for(predicate, timeout_s)
