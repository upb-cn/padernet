"""Classic pcap writing: little-endian, version 2.4, Ethernet link type.

Timestamps are passed in explicitly as milliseconds so captures made under the
virtual clock are deterministic; PcapWriter never reads real time.
"""

from __future__ import annotations

import struct
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

# The pcap global header, 24 bytes
_GLOBAL = struct.Struct(
    "<"  # little-endian (readers learn the byte order from the magic)
    "I"  # magic 0xA1B2C3D4 (microsecond timestamps)
    "H"  # major version: 2
    "H"  # minor version: 4
    "i"  # time zone offset: 0
    "I"  # timestamp accuracy: 0
    "I"  # snapshot length
    "I"  # link type: 1 (Ethernet)
)

# One pcap record header, 16 bytes; the frame follows
_RECORD = struct.Struct(
    "<"  # little-endian, like the global header
    "I"  # timestamp, seconds
    "I"  # timestamp, microseconds
    "I"  # captured length
    "I"  # original length
)


class PcapWriter:
    """Writes frames to a pcap file or stream; usable as a context manager."""

    def __init__(self, target: BinaryIO | str | Path, *, linktype: int = LINKTYPE_ETHERNET):
        """Write the global header; a path is opened and owned, a stream is used but not owned."""
        if isinstance(target, str | Path):
            self._file: BinaryIO = open(target, "wb")  # noqa: SIM115 - closed by close()
            self._owns_file = True  # shut the file at the end: it is ours
        else:
            self._file = target  # the caller's stream stays open after the writer ends
            self._owns_file = False
        self._file.write(_GLOBAL.pack(PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, linktype))

    def write_frame(self, frame: bytes, *, t_ms: int) -> None:
        """Append one frame with its capture time in milliseconds; t_ms must not be negative."""
        if t_ms < 0:
            raise ValueError(f"t_ms must be >= 0, got {t_ms}")
        seconds, ms = divmod(t_ms, 1000)
        captured = frame[:SNAPLEN]  # the record holds at most the snapshot length
        # the file holds microseconds, so nothing of the millisecond input is lost
        self._file.write(_RECORD.pack(seconds, ms * 1000, len(captured), len(frame)))
        self._file.write(captured)

    def flush(self) -> None:
        """Push buffered records to the OS, for a reader following a live capture."""
        self._file.flush()

    def close(self) -> None:
        """Finish the capture: shut an owned file, flush a borrowed stream."""
        if self._owns_file:
            self._file.close()
        else:
            self._file.flush()

    def __enter__(self) -> PcapWriter:
        """Context manager support: the writer itself."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Finish the capture when the with block ends, exception or not."""
        self.close()
