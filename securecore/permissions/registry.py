"""Caller registry for SecureCore permission enforcement.

Every autonomous component must be registered here before it can
write to any substrate. Registration happens in the app factory —
components cannot register themselves.

Each registered caller gets:
  - a unique caller_id
  - a list of substrates it may write to
  - a list of substrates it may read
  - an HMAC signing key (generated at registration, not chosen by caller)
  - a denial counter

Unregistered callers are denied at append(). No exceptions.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import Optional


@dataclass
class CallerEntry:
    """A registered caller and its permissions."""

    caller_id: str
    caller_type: str  # agent | control | collector | routes
    module_path: str
    allowed_write: list[str]
    allowed_read: list[str]
    signing_key: bytes
    registered_at: str
    denied_count: int = 0
    last_denied_at: str = ""
    last_denied_target: str = ""
    total_writes: int = 0

    def may_write(self, substrate_name: str) -> bool:
        return substrate_name in self.allowed_write

    def may_read(self, substrate_name: str) -> bool:
        return substrate_name in self.allowed_read

    def record_denial(self, substrate_name: str) -> None:
        self.denied_count += 1
        self.last_denied_at = datetime.now(UTC).isoformat()
        self.last_denied_target = substrate_name

    def record_write(self) -> None:
        self.total_writes += 1

    def to_dict(self) -> dict:
        return {
            "caller_id": self.caller_id,
            "caller_type": self.caller_type,
            "module_path": self.module_path,
            "allowed_write": self.allowed_write,
            "allowed_read": self.allowed_read,
            "registered_at": self.registered_at,
            "denied_count": self.denied_count,
            "last_denied_at": self.last_denied_at,
            "last_denied_target": self.last_denied_target,
            "total_writes": self.total_writes,
        }


class CallerRegistry:
    """Central registry of all authorized callers.

    Created once by the app factory. Components receive writer/reader
    handles that reference back to this registry for enforcement.
    """

    def __init__(self):
        self._callers: dict[str, CallerEntry] = {}
        self._lock = threading.Lock()

    def register(
        self,
        caller_id: str,
        caller_type: str,
        module_path: str,
        allowed_write: list[str],
        allowed_read: list[str] | None = None,
    ) -> CallerEntry:
        """Register a caller with explicit permissions.

        Returns the CallerEntry (which holds the signing key).
        Raises if caller_id is already registered.
        """
        with self._lock:
            if caller_id in self._callers:
                raise ValueError(f"caller already registered: {caller_id}")

            signing_key = os.urandom(32)

            entry = CallerEntry(
                caller_id=caller_id,
                caller_type=caller_type,
                module_path=module_path,
                allowed_write=list(allowed_write),
                allowed_read=list(allowed_read or []),
                signing_key=signing_key,
                registered_at=datetime.now(UTC).isoformat(),
            )

            self._callers[caller_id] = entry
            return entry

    def get(self, caller_id: str) -> Optional[CallerEntry]:
        return self._callers.get(caller_id)

    def is_registered(self, caller_id: str) -> bool:
        return caller_id in self._callers

    def all_callers(self) -> list[CallerEntry]:
        return list(self._callers.values())

    def callers_for_substrate(self, substrate_name: str) -> list[str]:
        """Get all caller_ids authorized to write to a substrate."""
        return [
            entry.caller_id
            for entry in self._callers.values()
            if entry.may_write(substrate_name)
        ]

    def summary(self) -> dict:
        return {
            "total_registered": len(self._callers),
            "callers": {cid: entry.to_dict() for cid, entry in self._callers.items()},
        }


def sign_record(
    signing_key: bytes,
    caller_id: str,
    record_type: str,
    payload_hash: str,
    timestamp: str,
    nonce: str,
) -> str:
    """Generate HMAC signature for a write operation.

    Includes timestamp + nonce to prevent replay attacks.
    """
    message = f"{caller_id}|{record_type}|{payload_hash}|{timestamp}|{nonce}"
    return hmac.new(signing_key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(
    signing_key: bytes,
    caller_id: str,
    record_type: str,
    payload_hash: str,
    timestamp: str,
    nonce: str,
    signature: str,
) -> bool:
    """Verify an HMAC signature for a write operation."""
    expected = sign_record(signing_key, caller_id, record_type, payload_hash, timestamp, nonce)
    return hmac.compare_digest(expected, signature)
