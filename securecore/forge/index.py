"""Rebuildable sidecar index for SecureCore Forge."""

from __future__ import annotations

import json
from pathlib import Path


class ForgeIndex:
    """Lightweight offset index.

    This index is support structure only. It is rebuildable from the binary
    forge store and is not authoritative truth.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> str:
        return str(self._path)

    def append(self, entry: dict) -> None:
        with open(self._path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")

    def stream(self) -> list[dict]:
        if not self._path.exists():
            return []

        entries: list[dict] = []
        with open(self._path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries

    def tail(self, limit: int = 20) -> list[dict]:
        if limit <= 0:
            return []
        return self.stream()[-limit:]

    def count(self) -> int:
        return len(self.stream())
