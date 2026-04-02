"""Log stream management.

Each log concern gets its own JSONL file. Streams are append-only.
The LogRouter dispatches entries to the correct stream based on the
'stream' field in each entry.
"""

import json
import threading
from pathlib import Path
from typing import Optional


class LogStream:
    """A single append-only JSONL log stream."""

    def __init__(self, name: str, log_dir: str):
        self.name = name
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._path = self._log_dir / f"{name}.jsonl"
        self._lock = threading.Lock()
        self._count = 0

    def write(self, entry: dict) -> None:
        """Append an entry to this stream."""
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")
            self._count += 1

    def read_all(self, limit: int = 500) -> list[dict]:
        """Read entries from this stream."""
        entries = []
        if not self._path.exists():
            return entries
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
                if len(entries) >= limit:
                    break
        return entries

    def tail(self, n: int = 50) -> list[dict]:
        """Read the last N entries."""
        all_entries = self.read_all(limit=100000)
        return all_entries[-n:]

    @property
    def path(self) -> str:
        return str(self._path)

    @property
    def count(self) -> int:
        return self._count


class LogRouter:
    """Routes log entries to the correct stream based on the 'stream' field.

    One router per SecureCore instance. All logging goes through here.
    """

    STREAM_NAMES = [
        "raw_ingress",
        "normalized",
        "forensic",
        "agent_decision",
        "operator",
        "health",
        "chain_anchor",
        "llm_audit",
    ]

    def __init__(self, log_dir: str):
        self._log_dir = log_dir
        self._streams: dict[str, LogStream] = {}

        for name in self.STREAM_NAMES:
            self._streams[name] = LogStream(name, log_dir)

    def log(self, entry: dict) -> None:
        """Route a log entry to the appropriate stream."""
        stream_name = entry.get("stream", "normalized")
        stream = self._streams.get(stream_name)
        if stream:
            stream.write(entry)

    def get_stream(self, name: str) -> Optional[LogStream]:
        """Get a specific stream by name."""
        return self._streams.get(name)

    def stats(self) -> dict:
        """Get write counts across all streams."""
        return {name: stream.count for name, stream in self._streams.items()}
