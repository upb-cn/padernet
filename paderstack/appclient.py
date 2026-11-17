"""The app client: runs the seven-step app protocol against the application server.

Uses only the socket API (the injected sock_mod: paderstack.socket's
bound_module or the stdlib module itself), so the same code runs on Python's
sockets and on your own stack. Every port, size and rate comes from the
server's replies; nothing is hard-coded here. Run it online with
python -m stackkit.control test app.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections.abc import Callable
from typing import Any


class LineReader:
    """Buffered line / fixed-length reader (server lines end in \\n, ASCII)."""

    def __init__(self, sock: Any) -> None:
        """Wrap a connected socket; the buffer starts empty."""
        self._sock = sock  # anything with recv(n): the stack's socket or Python's
        self._buf = bytearray()  # received, not yet handed out

    def readline(self) -> str:
        """The next line without its newline; reads more until one arrives."""
        while b"\n" not in self._buf:  # read until a whole line is buffered
            chunk = self._sock.recv(4096)
            if not chunk:  # EOF in the middle of a line
                raise OSError("connection closed by the peer while reading a line")
            self._buf += chunk
        raw, _, rest = self._buf.partition(b"\n")
        self._buf = bytearray(rest)
        return raw.decode("ascii").rstrip("\r")

    def read_exact(self, n: int) -> bytes:
        """Exactly n bytes; reads more until they are there."""
        while len(self._buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:  # EOF before the n bytes were there
                raise OSError("connection closed by the peer while reading data")
            self._buf += chunk
        data = bytes(self._buf[:n])
        del self._buf[:n]
        return data

    def read_until_eof(self) -> bytes:
        """Everything until the peer closes: the buffered bytes, then the rest."""
        out = bytearray(self._buf)
        self._buf.clear()
        while True:
            chunk = self._sock.recv(65536)
            if not chunk:  # EOF: the peer has finished
                return bytes(out)
            out += chunk


def _generate(seed: str, size: int) -> bytes:
    """Local appdata.generate: block i = SHA-256(seed || u64_be(i)), concatenated, truncated."""
    blocks = []  # 32-byte SHA-256 digests, in counter order
    seed_bytes = seed.encode("utf-8")
    # enough blocks to cover size; the last one is cut to fit
    for counter in range((size + 31) // 32):
        blocks.append(hashlib.sha256(seed_bytes + counter.to_bytes(8, "big")).digest())
    return b"".join(blocks)[:size]


def auth_proof(proto_key: bytes, nonce_hex: str) -> str:
    """The AUTH proof: HMAC-SHA256(proto_key, b"auth" || nonce bytes), first 16 bytes, hex."""
    message = b"auth" + bytes.fromhex(nonce_hex)
    return hmac.new(proto_key, message, hashlib.sha256).digest()[:16].hex()


def submit_digest(tokens_in_order: list[str]) -> str:
    """The SUBMIT digest: SHA-256 (hex) of the step tokens joined with ':' in step order."""
    return hashlib.sha256(":".join(tokens_in_order).encode("ascii")).hexdigest()


def _expect(line: str, *heads: str) -> list[str]:
    """Split a reply line into words; OSError unless the first word is one of heads."""
    parts = line.split(" ")
    if parts[0] not in heads:
        raise OSError(f"unexpected server reply: {line!r}")
    return parts


def run_app(
    sock_mod: Any,
    *,
    server_ip: str,
    control_port: int,
    student_index: int,
    proto_key: bytes,
    sleep: Callable[[float], None] = time.sleep,
    timeout_s: float = 30.0,
    hello_request: str | None = None,
) -> str:
    """Run every app step in the server-announced order; returns the completion code.

    hello_request: a line sent right after connecting, before the server's HELLO
    (the online tests' `TEST <challenge> <steps>`; the course CLI supplies it).
    """
    control = sock_mod.socket()
    control.settimeout(timeout_s)
    control.connect((server_ip, control_port))
    if hello_request is not None:
        control.sendall(hello_request.encode("ascii") + b"\n")
    reader = LineReader(control)
    try:
        return _run(
            sock_mod, server_ip, control, reader, student_index, proto_key, sleep, timeout_s
        )
    finally:  # the control connection goes down whatever happened
        control.close()


def _run(
    sock_mod: Any,
    server_ip: str,
    control: Any,
    reader: LineReader,
    student_index: int,
    proto_key: bytes,
    sleep: Callable[[float], None],
    timeout_s: float,
) -> str:
    """The steps after connecting; returns the completion code (run_app wraps this)."""
    raise NotImplementedError("HELLO carries the nonce and step order; run steps, collect tokens")
