"""Reader for SecureCore Forge binary stores."""

from __future__ import annotations

import os
import struct
from pathlib import Path
from typing import Iterator

from securecore.forge.index import ForgeIndex
from securecore.forge.record import ForgeRecord, PREFIX


class ForgeReader:
    """Read forge records from a substrate-specific forge directory."""

    def __init__(self, base_dir: str | Path):
        self._base_dir = Path(base_dir)
        self._records_path = self._base_dir / "records.bin"
        self._index = ForgeIndex(self._base_dir / "records.index.jsonl")

    @property
    def records_path(self) -> str:
        return str(self._records_path)

    def exists(self) -> bool:
        return self._records_path.exists()

    def iter_records(self) -> Iterator[ForgeRecord]:
        if not self._records_path.exists():
            return

        with open(self._records_path, "rb") as handle:
            while True:
                prefix = handle.read(PREFIX.size)
                if not prefix:
                    break
                if len(prefix) != PREFIX.size:
                    raise ValueError("truncated forge record prefix")

                _, _, header_len, payload_len, _ = PREFIX.unpack(prefix)
                body = handle.read(header_len + payload_len)
                if len(body) != header_len + payload_len:
                    raise ValueError("truncated forge record body")
                yield ForgeRecord.decode(prefix + body)

    def count(self) -> int:
        index_count = self._index.count()
        if index_count:
            return index_count
        return sum(1 for _ in self.iter_records())

    def last_record(self) -> ForgeRecord | None:
        last = None
        for record in self.iter_records():
            last = record
        return last

    def tail(self, limit: int = 20) -> list[ForgeRecord]:
        if limit <= 0:
            return []

        entries = self._index.tail(limit)
        if not entries or not self._records_path.exists():
            return list(self.iter_records())[-limit:]

        records: list[ForgeRecord] = []
        with open(self._records_path, "rb") as handle:
            for entry in entries:
                handle.seek(int(entry["offset"]), os.SEEK_SET)
                size = int(entry["size"])
                raw = handle.read(size)
                records.append(ForgeRecord.decode(raw))
        return records

    def verify(self) -> dict:
        count = 0
        last_sequence = -1
        last_chain_hash = None
        for record in self.iter_records():
            if record.sequence <= last_sequence:
                return {
                    "intact": False,
                    "error": "sequence regression",
                    "sequence": record.sequence,
                }
            if last_chain_hash is not None and record.previous_hash != last_chain_hash:
                return {
                    "intact": False,
                    "error": "previous_hash mismatch",
                    "sequence": record.sequence,
                }
            last_sequence = record.sequence
            last_chain_hash = record.chain_hash
            count += 1

        return {
            "intact": True,
            "total_records": count,
            "last_sequence": last_sequence,
            "records_path": str(self._records_path),
        }
