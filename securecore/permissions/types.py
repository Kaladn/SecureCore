"""Read/write interface separation for substrates.

SubstrateReader — can stream, query, verify. Cannot append.
SubstrateWriter — can append (with permission gate). Also reads.

Components receive the narrowest interface they need:
  - Agents get SubstrateWriter for agent_decisions, SubstrateReader for everything else
  - Reaper gets SubstrateWriter for operator, SubstrateReader for decisions/hid
  - Trap routes get SubstrateWriter for ingress/mirror/evidence/telemetry
"""

from __future__ import annotations

from typing import Iterator, Optional

from securecore.permissions.gate import WriteToken
from securecore.substrates.base import Substrate, SubstrateRecord


class SubstrateReader:
    """Read-only interface to a substrate. Cannot append."""

    def __init__(self, substrate: Substrate):
        self._substrate = substrate

    @property
    def name(self) -> str:
        return self._substrate.name

    def stream(self, since_sequence: int = 0) -> Iterator[SubstrateRecord]:
        return self._substrate.stream(since_sequence)

    def query(self, **kwargs) -> list[SubstrateRecord]:
        return self._substrate.query(**kwargs)

    def count(self) -> int:
        return self._substrate.count()

    def verify_chain(self) -> dict:
        return self._substrate.verify_chain()

    def last_record(self) -> Optional[SubstrateRecord]:
        return self._substrate.last_record()

    def subscribe(self, callback) -> None:
        self._substrate.subscribe(callback)

    def unsubscribe(self, callback) -> None:
        self._substrate.unsubscribe(callback)

    def forge_status(self) -> dict:
        return self._substrate.forge_status()

    @property
    def jsonl_path(self) -> str:
        return self._substrate.jsonl_path


class SubstrateWriter:
    """Write-capable interface to a substrate. Requires WriteToken for every append.

    Also provides full read access (a writer can always read what it writes).
    Delegates substrate-specific methods (record_request, record_cell_created, etc.)
    through an active-token mechanism so the gate verifies every write.
    """

    def __init__(self, substrate: Substrate, caller_id: str, signing_key: bytes):
        self._substrate = substrate
        self._caller_id = caller_id
        self._signing_key = signing_key

    @property
    def name(self) -> str:
        return self._substrate.name

    @property
    def caller_id(self) -> str:
        return self._caller_id

    def append(self, record_type: str, payload: dict, cell_id: str = "") -> SubstrateRecord:
        """Append a record. Automatically creates and signs a WriteToken."""
        token = WriteToken(
            caller_id=self._caller_id,
            record_type=record_type,
            payload=payload,
            signing_key=self._signing_key,
        )
        return self._substrate.append(
            record_type=record_type,
            payload=payload,
            cell_id=cell_id,
            write_token=token,
        )

    # Delegate all reads to the underlying substrate
    def stream(self, since_sequence: int = 0) -> Iterator[SubstrateRecord]:
        return self._substrate.stream(since_sequence)

    def query(self, **kwargs) -> list[SubstrateRecord]:
        return self._substrate.query(**kwargs)

    def count(self) -> int:
        return self._substrate.count()

    def verify_chain(self) -> dict:
        return self._substrate.verify_chain()

    def last_record(self) -> Optional[SubstrateRecord]:
        return self._substrate.last_record()

    def subscribe(self, callback) -> None:
        self._substrate.subscribe(callback)

    def unsubscribe(self, callback) -> None:
        self._substrate.unsubscribe(callback)

    def forge_status(self) -> dict:
        return self._substrate.forge_status()

    @property
    def jsonl_path(self) -> str:
        return self._substrate.jsonl_path

    def __getattr__(self, name: str):
        """Delegate substrate-specific methods (record_request, record_cell_created, etc.)

        These methods internally call self.append() on the substrate. We set an
        active token on the substrate before the call so the gate can verify
        the caller even when append() is called without an explicit write_token.
        """
        attr = getattr(self._substrate, name)
        if not callable(attr):
            return attr

        def _gated_call(*args, **kwargs):
            token = WriteToken(
                caller_id=self._caller_id,
                record_type=name,
                payload={},
                signing_key=self._signing_key,
            )
            self._substrate.set_active_token(token)
            try:
                return attr(*args, **kwargs)
            finally:
                self._substrate.clear_active_token()

        return _gated_call
