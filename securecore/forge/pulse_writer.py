"""Pulse-style buffered writer for SecureCore Forge."""

from __future__ import annotations

import time
from dataclasses import dataclass

from securecore.forge.writer import ForgeWriter


@dataclass(slots=True)
class PulseConfig:
    max_records_per_pulse: int = 64
    max_bytes_per_pulse: int = 256 * 1024
    max_age_ms_per_pulse: int = 250


class ForgePulseWriter:
    """Buffered append helper modeled after the Forge pulse pattern.

    This sits in front of ForgeWriter and groups records into short-lived pulses.
    It is intentionally small in the pre-Forge phase and is not yet wired into
    the live substrate hot path by default.
    """

    def __init__(self, writer: ForgeWriter, config: PulseConfig | None = None):
        self._writer = writer
        self._config = config or PulseConfig()
        self._buffer: list[dict] = []
        self._buffer_bytes = 0
        self._buffer_started_at: float | None = None
        self._pulse_id = 0

    def _estimate_size(self, record: dict) -> int:
        payload = record.get("payload", {})
        return len(str(payload)) + 256

    def _age_ms(self) -> float:
        if self._buffer_started_at is None:
            return 0.0
        return (time.time() - self._buffer_started_at) * 1000.0

    def _should_flush(self) -> bool:
        if not self._buffer:
            return False
        if len(self._buffer) >= self._config.max_records_per_pulse:
            return True
        if self._buffer_bytes >= self._config.max_bytes_per_pulse:
            return True
        if self._age_ms() >= self._config.max_age_ms_per_pulse:
            return True
        return False

    def submit(self, record: dict) -> list[dict]:
        if not self._buffer:
            self._buffer_started_at = time.time()
        self._buffer.append(record)
        self._buffer_bytes += self._estimate_size(record)

        if self._should_flush():
            return self.flush()
        return []

    def flush(self) -> list[dict]:
        if not self._buffer:
            return []

        self._pulse_id += 1
        pulse_records = []
        for record in self._buffer:
            stamped = dict(record)
            payload = dict(stamped.get("payload", {}))
            payload.setdefault("forge_pulse_id", self._pulse_id)
            stamped["payload"] = payload
            pulse_records.append(stamped)

        self._buffer = []
        self._buffer_bytes = 0
        self._buffer_started_at = None
        self._writer.append_batch_dicts(pulse_records)
        return pulse_records

    def close(self) -> list[dict]:
        return self.flush()

    def stats(self) -> dict:
        return {
            "pulse_id": self._pulse_id,
            "buffered_records": len(self._buffer),
            "buffered_bytes": self._buffer_bytes,
            "buffer_age_ms": round(self._age_ms(), 3),
        }
