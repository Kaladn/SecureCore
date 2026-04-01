"""Write-ahead log for SecureCore Forge."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path


FRAME_PREFIX = struct.Struct("<I32s")


class ForgeWAL:
    """Small write-ahead log for pending forge frames.

    The current Forge slice commits one frame at a time and clears the WAL
    after a successful append. That keeps recovery simple while the binary
    spine is being introduced beside JSONL truth.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> str:
        return str(self._path)

    def append(self, frame: bytes) -> None:
        digest = hashlib.sha256(frame).digest()
        with open(self._path, "ab") as handle:
            handle.write(FRAME_PREFIX.pack(len(frame), digest))
            handle.write(frame)

    def read_all(self) -> list[bytes]:
        if not self._path.exists():
            return []

        frames: list[bytes] = []
        with open(self._path, "rb") as handle:
            while True:
                prefix = handle.read(FRAME_PREFIX.size)
                if not prefix:
                    break
                if len(prefix) != FRAME_PREFIX.size:
                    raise ValueError("truncated WAL frame prefix")

                size, digest = FRAME_PREFIX.unpack(prefix)
                frame = handle.read(size)
                if len(frame) != size:
                    raise ValueError("truncated WAL frame body")
                if hashlib.sha256(frame).digest() != digest:
                    raise ValueError("WAL frame checksum mismatch")
                frames.append(frame)
        return frames

    def clear(self) -> None:
        with open(self._path, "wb"):
            pass
