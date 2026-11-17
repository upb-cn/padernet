"""Deterministic app data: block i = SHA-256(seed || u64_be(i)).

Students generate upload payloads with this; the app server generates
download data and verifies uploads with the identical construction, so the
definition here is normative.
"""

from __future__ import annotations

import hashlib


def generate(seed: bytes | str, size: int) -> bytes:
    """The first size bytes of the block stream of seed; a str seed is taken as UTF-8."""
    if size < 0:
        raise ValueError(f"size must be >= 0, got {size}")
    seed_bytes = seed.encode("utf-8") if isinstance(seed, str) else seed
    blocks: list[bytes] = []
    # 32-byte blocks, as many as cover size; the last one is cut to fit
    for counter in range((size + 31) // 32):
        blocks.append(hashlib.sha256(seed_bytes + counter.to_bytes(8, "big")).digest())
    return b"".join(blocks)[:size]
