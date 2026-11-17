"""The event-loop runtime driving a student stack over the tunnel.

One background thread runs a selectors loop over the tunnel socket, a timer
heap and a thunk queue. The student StackHost is instantiated on that thread
and every callback (on_frame, timers, run_in_stack thunks) executes there.
Callback exceptions are caught, appended to Runtime.errors and reported via
trace("error", ...); the loop keeps running.

This is real-runtime entry code: the one place allowed to seed the injected RNG from
os.urandom and read the monotonic clock; the stack itself only ever sees the
injected Clock and Random.
"""

from __future__ import annotations

import contextlib
import functools
import heapq
import itertools
import json
import logging
import os
import random
import selectors
import socket
import threading
import time
import traceback
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass
from typing import Any

from stackkit import log as stacklog
from stackkit.config import StudentConfig
from stackkit.interfaces import Link, StackFactory, StackHost, Tracer
from stackkit.trace import NullTracer
from stackkit.tunnel_client import FrameEvent, NoticeEvent, TunnelClient, TunnelClientError

_log = logging.getLogger("stackkit.runtime")  # into padernet.log when the CLI opened it


@dataclass(frozen=True)
class RuntimeError_:
    """One captured callback failure (kept, not raised; the loop survives)."""

    where: str  # the callback that failed: on_frame, timer or keepalive
    exception: BaseException
    traceback_text: str  # the formatted traceback, ready to print


class _LoopTimer:
    """A pending call_later entry on the loop's timer heap."""

    __slots__ = ("cancelled", "cb", "deadline_ms", "seq")

    def __init__(self, deadline_ms: int, seq: int, cb: Callable[[], None]) -> None:
        """Create the entry; _add_timer pushes it on the heap."""
        self.deadline_ms = deadline_ms  # in loop-clock milliseconds
        self.seq = seq  # creation order, the tie-breaker for equal deadlines
        self.cb = cb
        self.cancelled = False  # a cancelled timer stays on the heap and is skipped when popped

    def cancel(self) -> None:
        """Revoke the timer; the loop skips it when it reaches it."""
        self.cancelled = True

    def __lt__(self, other: _LoopTimer) -> bool:
        """Heap order: earlier deadline first, then creation order."""
        return (self.deadline_ms, self.seq) < (other.deadline_ms, other.seq)


class _LoopClock:
    """Clock backed by the runtime loop: monotonic ms since start, loop-driven timers."""

    def __init__(self, runtime: Runtime) -> None:
        """Bind to the runtime; the stack's time starts at zero here."""
        self._runtime = runtime
        self._start_ns = time.monotonic_ns()

    def now_ms(self) -> int:
        """Milliseconds since the runtime was created."""
        return (time.monotonic_ns() - self._start_ns) // 1_000_000

    def call_later(self, delay_ms: int, cb: Callable[[], None]) -> _LoopTimer:
        """Schedule cb on the loop thread after delay_ms; cancel the returned timer to revoke it."""
        if delay_ms < 0:
            raise ValueError(f"delay_ms must be >= 0, got {delay_ms}")
        return self._runtime._add_timer(self.now_ms() + delay_ms, cb)


class _ClientLink:
    """The Link handed to the stack: frames go out through the tunnel client."""

    def __init__(self, client: TunnelClient) -> None:
        """Wrap the tunnel client the runtime owns."""
        self._client = client

    def send_frame(self, frame: bytes) -> None:
        """Hand one Ethernet frame to the tunnel; raises TunnelClientError if it is too large."""
        self._client.send_frame(frame)


class Runtime:
    """Owns the loop thread, the tunnel client and the student stack; use as a context manager."""

    def __init__(
        self,
        config: StudentConfig,
        stack_factory: StackFactory,
        *,
        client: TunnelClient | None = None,
        rng: random.Random | None = None,
        tracer: Tracer | None = None,
        attach: bool = True,
    ) -> None:
        """attach=False only where no gateway answers (two runtimes wired tunnel to tunnel)."""
        self._config = config
        self._attach = attach  # whether the loop thread opens the gateway session before the stack
        self._stack_factory = stack_factory  # called on the loop thread to build the stack
        self._client = (
            client
            if client is not None
            else TunnelClient(
                config.network.gateway_host,
                config.network.gateway_port,
                config.student_index,
                config.keys.tunnel_key,
            )
        )
        # entry code seeds the injected RNG from os.urandom (the sanctioned exception).
        self._rng = rng if rng is not None else random.Random(int.from_bytes(os.urandom(8), "big"))
        self._tracer: Tracer = tracer if tracer is not None else NullTracer()
        # what the stack is handed, besides the config, the rng and the tracer
        self.clock = _LoopClock(self)
        self.link: Link = _ClientLink(self._client)
        self.errors: list[RuntimeError_] = []  # callback failures, oldest first; the loop lives on
        self.notices: list[dict[str, Any]] = []  # the gateway's notices, as their JSON bodies
        self.stack: StackHost | None = None  # built on the loop thread by start

        self._timers: list[_LoopTimer] = []  # a heap ordered by deadline, then creation
        self._timer_seq = itertools.count()
        self._thunks: list[tuple[Callable[[], Any], Future[Any]]] = []  # queued run_in_stack calls
        # guards _timers and _thunks, the two structures other threads touch
        self._lock = threading.Lock()
        # the wake-up pipe: a byte written here makes the loop's select return at once
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        # _running is cleared by stop; _ready is set once the stack exists or startup failed
        self._running = threading.Event()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None  # why the loop thread gave up, for start
        self._thread = threading.Thread(target=self._run, name="stackkit-runtime", daemon=True)

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> Runtime:
        """Start the loop thread and block until the stack exists; raises if startup failed."""
        stacklog.set_clock(self.clock)  # stamps the log records, the stack's constructor's too
        self._running.set()
        self._thread.start()
        self._ready.wait()
        # a gateway problem is raised as is; a failing stack factory is wrapped as OSError
        if isinstance(self._startup_error, TunnelClientError):
            self.stop()
            raise self._startup_error
        if self._startup_error is not None:
            self.stop()
            raise OSError(
                f"student stack failed to initialize: {self._startup_error!r}"
            ) from self._startup_error
        return self

    def stop(self) -> None:
        """Stop the loop thread, wait for it and close the tunnel and the wake-up pipe."""
        self._running.clear()
        self._wake()
        if self._thread.is_alive():
            self._thread.join(timeout=5)
        self._client.close()
        self._wake_r.close()
        self._wake_w.close()
        stacklog.clear_clock(self.clock)

    def __enter__(self) -> Runtime:
        """Context manager entry: start the loop."""
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        """Context manager exit: stop the loop, whatever happened in the block."""
        self.stop()

    # -- cross-thread entry points -------------------------------------------

    def control(self, op: str, **params: Any) -> dict[str, Any]:
        """Send a gateway control request (status, set_scenario, reset); blocks for the reply.

        The tunnel client is not thread-safe and the loop thread owns its socket,
        so the request runs on the loop thread. Call this, never client.request,
        while the runtime is running.
        """
        future = self.run_in_stack(lambda: self._client.request(op, **params))
        reply: dict[str, Any] = future.result()
        return reply

    def run_in_stack(self, fn: Callable[[], Any]) -> Future[Any]:
        """Run fn() on the loop thread; returns a Future with its result."""
        future: Future[Any] = Future()
        # called from the loop thread itself: run inline, waiting on the queue would deadlock
        if threading.current_thread() is self._thread:
            try:
                future.set_result(fn())
            except BaseException as exc:  # noqa: BLE001 - delivered through the Future
                future.set_exception(exc)
            return future
        with self._lock:
            self._thunks.append((fn, future))
        self._wake()
        return future

    def _add_timer(self, deadline_ms: int, cb: Callable[[], None]) -> _LoopTimer:
        """Push a timer on the heap; wakes the loop when called from another thread."""
        timer = _LoopTimer(deadline_ms, next(self._timer_seq), cb)
        with self._lock:
            heapq.heappush(self._timers, timer)
        if threading.current_thread() is not self._thread:
            self._wake()
        return timer

    def _wake(self) -> None:
        """Nudge the loop out of select; harmless once stop has closed the pipe."""
        with contextlib.suppress(OSError):
            self._wake_w.send(b"\x00")

    # -- the loop --------------------------------------------------------------

    def _report(self, where: str, exc: BaseException) -> None:
        """Record a callback failure in errors, on the tracer's error channel and in the log."""
        entry = RuntimeError_(where, exc, traceback.format_exc())
        self.errors.append(entry)
        self._tracer.trace("error", where=where, error=repr(exc))
        _log.error("%s failed: %r", where, exc, exc_info=True)

    def _guarded(self, where: str, fn: Callable[[], None]) -> None:
        """Call fn, turning an exception into a recorded error instead of ending the loop."""
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - captured and reported by design
            self._report(where, exc)

    def _run(self) -> None:
        """The loop thread: build the stack, then serve tunnel, timers and thunks until stop."""
        try:
            if self._attach:  # before the stack sends anything (same-second restarts)
                self._client.attach()
            self.stack = self._stack_factory(
                self._config, self.link, self.clock, self._rng, self._tracer
            )
        except Exception as exc:  # noqa: BLE001 - surfaced to start()
            self._startup_error = exc
            self._ready.set()
            return
        self._ready.set()

        selector = selectors.DefaultSelector()
        selector.register(self._client.fileno(), selectors.EVENT_READ, "tunnel")
        selector.register(self._wake_r.fileno(), selectors.EVENT_READ, "wake")
        try:
            while self._running.is_set():
                # sleep until a timer or the keepalive is due, or a datagram or a nudge arrives
                timeout = min(self._timer_timeout_s(), self._client.next_keepalive_in())
                for key, _mask in selector.select(timeout):
                    if key.data == "wake":
                        self._drain_wakeups()
                self._run_thunks()
                self._run_due_timers()
                self._pump_tunnel()
                self._guarded("keepalive", self._client.maintain)
        finally:
            selector.close()

    def _timer_timeout_s(self) -> float:
        """Seconds until the earliest live timer is due; at most 1.0 when none is pending."""
        with self._lock:
            while self._timers and self._timers[0].cancelled:  # drop cancelled timers off the top
                heapq.heappop(self._timers)
            if not self._timers:  # idle: still wake once a second
                return 1.0
            return max(0.0, (self._timers[0].deadline_ms - self.clock.now_ms()) / 1000)

    def _drain_wakeups(self) -> None:
        """Empty the wake-up pipe so stale nudges do not wake the loop again."""
        try:
            while self._wake_r.recv(64):
                pass
        except (BlockingIOError, OSError):
            pass

    def _run_thunks(self) -> None:
        """Run the queued run_in_stack calls, each result or exception going to its Future."""
        with self._lock:
            thunks, self._thunks = self._thunks, []
        for fn, future in thunks:
            # the caller cancelled the future meanwhile
            if not future.set_running_or_notify_cancel():
                continue
            try:
                future.set_result(fn())
            except BaseException as exc:  # noqa: BLE001 - delivered through the Future
                future.set_exception(exc)

    def _run_due_timers(self) -> None:
        """Fire every timer whose deadline has passed, earliest first."""
        while True:
            with self._lock:
                if not self._timers or self._timers[0].deadline_ms > self.clock.now_ms():
                    return
                timer = heapq.heappop(self._timers)
            if not timer.cancelled:  # cancel only marks; the heap entry is dropped here
                self._guarded("timer", timer.cb)

    def _pump_tunnel(self) -> None:
        """Deliver every waiting tunnel datagram: frames to the stack, notices to the list."""
        while True:
            event = self._client.receive(0)
            if event is None:
                return
            if isinstance(event, FrameEvent):
                stack = self.stack
                if stack is not None:
                    self._guarded("on_frame", functools.partial(stack.on_frame, event.data))
            elif isinstance(event, NoticeEvent):
                self.notices.append(event.body)
                self._tracer.trace("notice", **event.body)
                _log.info("gateway notice: %s", json.dumps(event.body, sort_keys=True))
