"""Deterministic test links: MemoryLink, LossyLink and Pair.

Everything runs under a VirtualClock; probabilistic impairments draw from an
explicitly injected random.Random, scripted drops go by frame index, so the
same seed always produces the same run (hard rule 3). Frame construction
helpers deliberately do NOT live here — building protocol frames is the
assignment.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from random import Random

from stackkit.clock import VirtualClock


@dataclass(frozen=True)
class LinkConfig:
    """The impairments of one link direction; by default frames just arrive after delay_ms."""

    delay_ms: int = 1  # every frame waits this long, plus the extras below
    loss_p: float = 0.0  # probability a frame vanishes
    reorder_p: float = 0.0  # probability a frame is held back by reorder_extra_ms
    reorder_extra_ms: int = 10  # the extra delay of a reordered frame
    duplicate_p: float = 0.0  # probability a frame arrives twice
    # Scripted, fully deterministic loss: drop(index, frame) -> True to drop.
    drop: Callable[[int, bytes], bool] | None = None


@dataclass
class LinkStats:
    """What happened to the frames handed to one LossyLink."""

    sent: int = 0  # frames handed to the link; also the index the drop script sees
    delivered: int = 0  # frames that reached the receiver, duplicates included
    dropped: int = 0  # by the drop script or loss_p
    reordered: int = 0  # frames given the extra delay
    duplicated: int = 0  # frames scheduled twice
    in_flight: int = 0  # scheduled, not yet delivered
    # the indices of the dropped frames, in order
    frames_dropped: list[int] = field(default_factory=list)


class LossyLink:
    """A one-direction Link that delivers through the virtual clock with impairments."""

    def __init__(
        self,
        clock: VirtualClock,
        config: LinkConfig | None = None,
        *,
        rng: Random | None = None,
    ) -> None:
        """Probabilistic impairments need an explicit rng; a drop script and plain delay do not."""
        self._clock = clock  # every delivery is one of its timers
        self._config = config if config is not None else LinkConfig()
        probabilistic = self._config.loss_p or self._config.reorder_p or self._config.duplicate_p
        if probabilistic and rng is None:
            raise ValueError("probabilistic impairments need an explicitly injected rng")
        self._rng = rng  # the only source of randomness, so a seed fixes the whole run
        self._receiver: Callable[[bytes], None] | None = None  # set by attach
        self.stats = LinkStats()

    def attach(self, receiver: Callable[[bytes], None]) -> None:
        """Name the function every delivered frame goes to, typically a stack's on_frame."""
        self._receiver = receiver

    def send_frame(self, frame: bytes) -> None:
        """Take one frame from the stack: drop, delay, reorder or duplicate it per the config."""
        if self._receiver is None:
            raise RuntimeError("LossyLink.send_frame before attach(); no receiver to deliver to")
        cfg, rng = self._config, self._rng
        index = self.stats.sent
        self.stats.sent += 1
        # the scripted drop decides first, then the random loss
        if cfg.drop is not None and cfg.drop(index, frame):
            self.stats.dropped += 1
            self.stats.frames_dropped.append(index)
            return
        if cfg.loss_p and rng is not None and rng.random() < cfg.loss_p:
            self.stats.dropped += 1
            self.stats.frames_dropped.append(index)
            return
        delay = cfg.delay_ms
        if cfg.reorder_p and rng is not None and rng.random() < cfg.reorder_p:
            delay += cfg.reorder_extra_ms
            self.stats.reordered += 1
        self._schedule(frame, delay)
        # a duplicate takes the same delay, so it lands right behind the original
        if cfg.duplicate_p and rng is not None and rng.random() < cfg.duplicate_p:
            self.stats.duplicated += 1
            self._schedule(frame, delay)

    def _schedule(self, frame: bytes, delay_ms: int) -> None:
        """Hand the frame over delay_ms later on the virtual clock; in flight until then."""
        self.stats.in_flight += 1

        def deliver() -> None:
            """The timer callback: hand the frame to the receiver."""
            self.stats.in_flight -= 1
            self.stats.delivered += 1
            assert self._receiver is not None
            self._receiver(frame)

        self._clock.call_later(delay_ms, deliver)
