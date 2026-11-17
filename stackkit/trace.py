"""Tracer implementations: structured trace records with automatic t_ms."""

from __future__ import annotations

from dataclasses import dataclass

from stackkit.interfaces import Clock


@dataclass(frozen=True)
class TraceRecord:
    """One trace event: when, on which channel, with which fields."""

    t_ms: int  # the tracer's clock when the event was recorded
    channel: str  # e.g. "cc" for the congestion-control trajectory
    fields: dict[str, object]  # the event's keyword arguments, as given


class NullTracer:
    """Discards everything; the default when nobody is watching."""

    def trace(self, channel: str, **fields: object) -> None:
        """Drop the event."""
        pass


class RecordingTracer:
    """Keeps every record in memory; used by tests and the cc-trace grading."""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock  # stamps every record
        self.records: list[TraceRecord] = []  # in the order recorded

    def trace(self, channel: str, **fields: object) -> None:
        """Store the event with the current time."""
        self.records.append(TraceRecord(self._clock.now_ms(), channel, fields))

    def channel(self, name: str) -> list[TraceRecord]:
        """The records of one channel, in order."""
        return [record for record in self.records if record.channel == name]
