"""Writer for SecureCore Forge substrate stores."""

from __future__ import annotations

import os
import threading
from pathlib import Path

from securecore.forge.index import ForgeIndex
from securecore.forge.reader import ForgeReader
from securecore.forge.record import ForgeRecord
from securecore.forge.wal import ForgeWAL


class ForgeWriter:
    """Single-writer binary append store for one truth domain."""

    def __init__(self, base_dir: str | Path):
        self._base_dir = Path(base_dir)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        self._records_path = self._base_dir / "records.bin"
        self._wal = ForgeWAL(self._base_dir / "records.wal")
        self._index = ForgeIndex(self._base_dir / "records.index.jsonl")
        self._lock = threading.Lock()
        self._writes = 0
        self._recover()

    def _recover(self) -> None:
        frames = self._wal.read_all()
        if not frames:
            return

        reader = ForgeReader(self._base_dir)
        last = reader.last_record()
        last_id = last.record_id if last else None

        for frame in frames:
            record = ForgeRecord.decode(frame)
            if record.record_id == last_id:
                continue
            self._append_frame(frame, record)
            last_id = record.record_id

        self._wal.clear()

    def _append_frame(self, frame: bytes, record: ForgeRecord) -> dict:
        offset = self._records_path.stat().st_size if self._records_path.exists() else 0
        with open(self._records_path, "ab") as handle:
            handle.write(frame)

        metadata = {
            "record_id": record.record_id,
            "substrate": record.substrate,
            "sequence": record.sequence,
            "timestamp": record.timestamp,
            "cell_id": record.cell_id,
            "record_type": record.record_type,
            "offset": offset,
            "size": len(frame),
        }
        self._index.append(metadata)
        self._writes += 1
        return metadata

    def append_dict(self, data: dict) -> dict:
        record = ForgeRecord.from_substrate_dict(data)
        frame = record.encode()

        with self._lock:
            self._wal.append(frame)
            metadata = self._append_frame(frame, record)
            self._wal.clear()
        return metadata

    def append_batch_dicts(self, rows: list[dict]) -> list[dict]:
        if not rows:
            return []

        encoded: list[tuple[bytes, ForgeRecord]] = []
        for row in rows:
            record = ForgeRecord.from_substrate_dict(row)
            encoded.append((record.encode(), record))

        with self._lock:
            for frame, _record in encoded:
                self._wal.append(frame)
            metadata = [self._append_frame(frame, record) for frame, record in encoded]
            self._wal.clear()
        return metadata

    def stats(self) -> dict:
        reader = ForgeReader(self._base_dir)
        last = reader.last_record()
        return {
            "records_path": str(self._records_path),
            "wal_path": self._wal.path,
            "index_path": self._index.path,
            "writes": self._writes,
            "count": reader.count(),
            "last_record_id": last.record_id if last else "",
            "last_sequence": last.sequence if last else -1,
        }
