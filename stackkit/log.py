"""The student's debugging log: padernet.log next to student.toml.

Student code logs through the standard library, at any level:

    import logging
    log = logging.getLogger(__name__)
    ...
    log.info("SYN sent seq=%d", seq)

The CLI opens the file before it runs the stack and closes it at the end.
Every record lands there as one line, stamped with the clock of the running
runtime (the clock that stamps trace records and fires timers), never the
wall clock; a traceback follows the record that carries one. Without an open
log nothing is written anywhere: the root logger carries a NullHandler, so
Python's last-resort handler stays silent, and the root stays at level
WARNING, so a log.info in student code costs next to nothing.
"""

from __future__ import annotations

import logging
from pathlib import Path

from stackkit.interfaces import Clock

FILE_NAME = "padernet.log"

_root = logging.getLogger()
_root.addHandler(logging.NullHandler())  # keeps logging.lastResort away from student records

_clock: Clock | None = None  # the running runtime's clock; stamps read 0 without one
_handler: LogFileHandler | None = None  # the open log, if any
_saved_level = logging.WARNING  # the root logger's level before open_log


class _Formatter(logging.Formatter):
    """One line per record: the runtime's clock, the level, the logger and the message."""

    def format(self, record: logging.LogRecord) -> str:
        """`<t_ms> ms <LEVEL> <logger>: <message>`, then the traceback if there is one."""
        t_ms = _clock.now_ms() if _clock is not None else 0
        line = f"{t_ms:6d} ms {record.levelname:<7} {record.name}: {record.getMessage()}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class LogFileHandler(logging.FileHandler):
    """The handler open_log installs; it also writes the header and the separators."""

    def write_line(self, line: str) -> None:
        """Write one line outside the record format, under the handler's lock."""
        self.acquire()
        try:
            if self.stream is not None:  # None once closed
                self.stream.write(line + "\n")
                self.flush()
        finally:
            self.release()


def open_log(path: str | Path, header: str) -> Path:
    """Truncate the log, write the header line and route every record there until close_log."""
    global _handler, _saved_level
    close_log()
    handler = LogFileHandler(path, mode="w", encoding="utf-8")
    handler.setFormatter(_Formatter())
    handler.setLevel(logging.DEBUG)
    _saved_level = _root.level
    _root.setLevel(logging.DEBUG)
    _root.addHandler(handler)
    _handler = handler
    handler.write_line(header)
    return Path(path)


def close_log() -> None:
    """Close the log and restore the root logger; a no-op when no log is open."""
    global _handler
    if _handler is None:
        return
    _root.removeHandler(_handler)
    _root.setLevel(_saved_level)
    _handler.close()
    _handler = None


def section(title: str) -> None:
    """A separator line `--- title`, when a log is open."""
    if _handler is not None:
        _handler.write_line(f"--- {title}")


def set_clock(clock: Clock | None) -> None:
    """The clock that stamps the records from now on; None makes the stamps read 0."""
    global _clock
    _clock = clock


def clear_clock(clock: Clock) -> None:
    """Forget `clock` if it is the registered one (a runtime that stops)."""
    global _clock
    if _clock is clock:
        _clock = None


def current_clock() -> Clock | None:
    """The registered clock, for the tests."""
    return _clock
