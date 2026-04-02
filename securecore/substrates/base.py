"""Base substrate class.

A substrate is an append-only data store that represents ground truth.
Substrates are NEVER mutated after initial append. They can be queried,
streamed, and verified, but the data they hold is immutable fact.

Every substrate record has:
  - record_id: unique identifier (sha256-based)
  - substrate: name of the owning substrate
  - sequence: monotonic counter within this substrate
  - timestamp: UTC ISO-8601
  - cell_id: linked mirror cell (if applicable)
  - payload: the actual data (substrate-specific schema)
  - chain_hash: links this record to the previous record in the substrate

Substrates store to two backends simultaneously:
  1. JSONL files on disk (fast, append-only, survives DB corruption)
  2. SQLite via SQLAlchemy (queryable, indexed)

The JSONL file is the primary source of truth. The DB is a query index.
If they disagree, the JSONL wins.
"""

import hashlib
import json
import os
import threading
from datetime import datetime, UTC
from pathlib import Path
from typing import Iterator, Optional


class SubstrateRecord:
    """A single immutable record in a substrate."""

    __slots__ = (
        "record_id", "substrate", "sequence", "timestamp",
        "cell_id", "record_type", "payload", "chain_hash", "previous_hash",
    )

    def __init__(
        self,
        substrate: str,
        sequence: int,
        record_type: str,
        payload: dict,
        cell_id: str = "",
        previous_hash: str = "GENESIS",
    ):
        self.substrate = substrate
        self.sequence = sequence
        self.timestamp = datetime.now(UTC).isoformat()
        self.cell_id = cell_id
        self.record_type = record_type
        self.payload = payload
        self.previous_hash = previous_hash

        # Compute record ID and chain hash
        self.record_id = self._compute_record_id()
        self.chain_hash = self._compute_chain_hash()

    def _compute_record_id(self) -> str:
        raw = f"{self.substrate}:{self.sequence}:{self.timestamp}:{json.dumps(self.payload, sort_keys=True)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def _compute_chain_hash(self) -> str:
        chain_input = "|".join([
            self.record_id,
            self.substrate,
            str(self.sequence),
            self.timestamp,
            self.cell_id,
            self.record_type,
            json.dumps(self.payload, sort_keys=True),
            self.previous_hash,
        ])
        return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "substrate": self.substrate,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "cell_id": self.cell_id,
            "record_type": self.record_type,
            "payload": self.payload,
            "chain_hash": self.chain_hash,
            "previous_hash": self.previous_hash,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict) -> "SubstrateRecord":
        rec = cls.__new__(cls)
        rec.record_id = data["record_id"]
        rec.substrate = data["substrate"]
        rec.sequence = data["sequence"]
        rec.timestamp = data["timestamp"]
        rec.cell_id = data.get("cell_id", "")
        rec.record_type = data["record_type"]
        rec.payload = data["payload"]
        rec.chain_hash = data["chain_hash"]
        rec.previous_hash = data["previous_hash"]
        return rec


class Substrate:
    """Base class for all substrates.

    Provides append-only storage with dual-write to JSONL + DB,
    hash chain integrity, and streaming query interface.

    Subclasses define:
      - name: substrate identifier
      - validate_payload(record_type, payload): schema enforcement
    """

    name: str = "base"

    def __init__(self, data_dir: str):
        self._data_dir = Path(data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._jsonl_path = self._data_dir / f"{self.name}.jsonl"
        self._sequence = 0
        self._last_hash = "GENESIS"
        self._lock = threading.Lock()
        self._subscribers: list = []
        self._permission_gate = None
        self._token_local = threading.local()
        self._forge_writer = None
        self._forge_failures = 0
        self._forge_strict = os.getenv("SECURECORE_FORGE_STRICT", "false").lower() == "true"

        if os.getenv("SECURECORE_FORGE_ENABLED", "false").lower() == "true":
            forge_root = os.getenv("SECURECORE_FORGE_DIR", "")
            if forge_root:
                forge_base = Path(forge_root)
            else:
                forge_base = self._data_dir.parent / "forge"
            try:
                from securecore.forge.writer import ForgeWriter
                self._forge_writer = ForgeWriter(forge_base / self.name)
            except Exception:
                if self._forge_strict:
                    raise

        # Recover sequence and last hash from existing JSONL
        self._recover_state()

    def _recover_state(self) -> None:
        """Recover sequence counter and last hash from existing JSONL file."""
        if not self._jsonl_path.exists():
            return

        last_line = None
        try:
            with open(self._jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
        except Exception:
            return

        if last_line:
            try:
                data = json.loads(last_line)
                self._sequence = data.get("sequence", 0) + 1
                self._last_hash = data.get("chain_hash", "GENESIS")
            except json.JSONDecodeError:
                pass

    def set_permission_gate(self, gate) -> None:
        """Set the permission gate. Called by the app factory after registration."""
        self._permission_gate = gate

    def set_active_token(self, token) -> None:
        """Set a write token for the current thread's caller context.

        When substrate-specific methods (record_request, record_evidence, etc.)
        call self.append() internally, they don't have a write_token parameter.
        A SubstrateWriter sets the active token before delegating to these methods,
        so the gate can still verify the caller.

        Uses thread-local storage to prevent concurrent callers from
        overwriting each other's tokens.
        """
        self._token_local.active_token = token

    def clear_active_token(self) -> None:
        self._token_local.active_token = None

    def validate_payload(self, record_type: str, payload: dict) -> None:
        """Override in subclasses to enforce schema.

        Raise ValueError if payload is invalid.
        """
        pass

    def append(
        self,
        record_type: str,
        payload: dict,
        cell_id: str = "",
        write_token=None,
    ) -> SubstrateRecord:
        """Append a record to this substrate.

        Thread-safe. Writes to JSONL first (truth), then notifies subscribers.

        If a permission gate is set, write_token is REQUIRED and must pass
        all gate checks (registered, ACL, valid signature). Denied writes
        raise PermissionDenied.
        """
        # Permission enforcement FIRST — the single chokepoint
        # Deny before schema validation so unauthorized callers
        # get "denied", not "invalid payload"
        verified_caller = ""
        if self._permission_gate is not None:
            effective_token = write_token or getattr(self._token_local, "active_token", None)
            if effective_token is None:
                from securecore.permissions.gate import PermissionDenied
                raise PermissionDenied("anonymous", self.name, "no write_token provided")
            # Pass actual payload for binding verification when using direct tokens.
            # Active tokens from delegated calls can't bind payload (built internally).
            actual_payload = payload if write_token is not None else None
            verified_caller = self._permission_gate.check(self.name, effective_token, actual_payload)

        self.validate_payload(record_type, payload)

        with self._lock:
            # Embed verified caller identity in payload (immutable proof)
            if verified_caller:
                payload = dict(payload)
                payload["_caller_id"] = verified_caller

            record = SubstrateRecord(
                substrate=self.name,
                sequence=self._sequence,
                record_type=record_type,
                payload=payload,
                cell_id=cell_id,
                previous_hash=self._last_hash,
            )

            # Write to JSONL (primary truth store)
            with open(self._jsonl_path, "a", encoding="utf-8") as f:
                f.write(record.to_json() + "\n")

            if self._forge_writer is not None:
                try:
                    self._forge_writer.append_dict(record.to_dict())
                except Exception:
                    self._forge_failures += 1
                    if self._forge_strict:
                        raise

            self._sequence += 1
            self._last_hash = record.chain_hash

        # Notify subscribers (agents watching this substrate)
        for callback in self._subscribers:
            try:
                callback(record)
            except Exception:
                pass  # agents must not break substrate operations

        return record

    def subscribe(self, callback) -> None:
        """Register a callback to receive new records as they are appended."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback) -> None:
        """Remove a subscriber."""
        self._subscribers = [s for s in self._subscribers if s is not callback]

    def stream(self, since_sequence: int = 0) -> Iterator[SubstrateRecord]:
        """Stream records from JSONL starting at a given sequence number."""
        if not self._jsonl_path.exists():
            return

        with open(self._jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("sequence", 0) >= since_sequence:
                        yield SubstrateRecord.from_dict(data)
                except json.JSONDecodeError:
                    continue

    def get(self, record_id: str) -> Optional[SubstrateRecord]:
        """Retrieve a specific record by ID. Scans JSONL."""
        for record in self.stream():
            if record.record_id == record_id:
                return record
        return None

    def count(self) -> int:
        """Total records in this substrate."""
        return self._sequence

    def last_record(self) -> Optional[SubstrateRecord]:
        """Get the most recent record."""
        last = None
        for record in self.stream():
            last = record
        return last

    def verify_chain(self) -> dict:
        """Verify the entire hash chain for this substrate.

        Returns integrity report. If any record has been tampered with,
        the chain breaks and this report identifies where.
        """
        expected_prev = "GENESIS"
        count = 0
        last_timestamp = None

        for record in self.stream():
            if record.previous_hash != expected_prev:
                return {
                    "substrate": self.name,
                    "intact": False,
                    "broken_at_sequence": record.sequence,
                    "error": "previous_hash mismatch",
                    "expected": expected_prev,
                    "found": record.previous_hash,
                }

            # Recompute chain hash
            recomputed_input = "|".join([
                record.record_id,
                record.substrate,
                str(record.sequence),
                record.timestamp,
                record.cell_id,
                record.record_type,
                json.dumps(record.payload, sort_keys=True),
                record.previous_hash,
            ])
            recomputed = hashlib.sha256(recomputed_input.encode("utf-8")).hexdigest()

            if recomputed != record.chain_hash:
                return {
                    "substrate": self.name,
                    "intact": False,
                    "broken_at_sequence": record.sequence,
                    "error": "chain_hash tampered",
                    "expected": recomputed,
                    "found": record.chain_hash,
                }

            expected_prev = record.chain_hash
            count += 1
            last_timestamp = record.timestamp

        return {
            "substrate": self.name,
            "intact": True,
            "total_records": count,
            "last_timestamp": last_timestamp,
        }

    def query(
        self,
        record_type: Optional[str] = None,
        cell_id: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 200,
    ) -> list[SubstrateRecord]:
        """Query records with optional filters."""
        results = []
        for record in self.stream():
            if record_type and record.record_type != record_type:
                continue
            if cell_id and record.cell_id != cell_id:
                continue
            if since and record.timestamp < since:
                continue
            results.append(record)
            if len(results) >= limit:
                break
        return results

    @property
    def jsonl_path(self) -> str:
        return str(self._jsonl_path)

    def forge_status(self) -> dict:
        if self._forge_writer is None:
            return {
                "enabled": False,
                "failures": self._forge_failures,
            }
        stats = self._forge_writer.stats()
        stats.update({
            "enabled": True,
            "failures": self._forge_failures,
        })
        return stats
