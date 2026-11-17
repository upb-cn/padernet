"""hexdump(data): the classic 16-bytes-per-line offset/hex/ASCII view."""

from __future__ import annotations


def hexdump(data: bytes) -> str:
    """Format data as offset, two groups of 8 hex bytes and the printable ASCII, 16 per line."""
    lines: list[str] = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        left = " ".join(f"{b:02x}" for b in chunk[:8])
        right = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_part = f"{left}  {right}" if right else left  # a double space splits the halves
        # bytes outside printable ASCII show as a dot
        printable = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{offset:08x}  {hex_part:<48}  |{printable}|")
    return "\n".join(lines)
