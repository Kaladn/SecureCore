"""Permission gate — the single enforcement point for all substrate writes.

ALL enforcement happens here. Not sprinkled across the codebase.
This module is called by substrate.append() and nowhere else.

The gate checks:
  1. caller_id is registered
  2. caller_id is authorized to write to this substrate
  3. HMAC signature is valid (proves caller_id is not spoofed)

On denial:
  - logs to operator substrate (if available)
  - increments denial counter on caller entry
  - raises PermissionDenied

On success:
  - increments write counter
  - returns the verified caller_id for embedding in the record
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, UTC

from securecore.permissions.registry import (
    CallerRegistry,
    CallerEntry,
    sign_record,
    verify_signature,
)

logger = logging.getLogger("permissions.gate")

DELEGATED_PAYLOAD_HASH = "DELEGATED"


class PermissionDenied(Exception):
    """Raised when a write is denied by the permission gate."""

    def __init__(self, caller_id: str, substrate: str, reason: str):
        self.caller_id = caller_id
        self.substrate = substrate
        self.reason = reason
        super().__init__(f"DENIED: {caller_id} -> {substrate}: {reason}")


class WriteToken:
    """Proof of authorization for a single write operation.

    Components create a WriteToken, sign it, and pass it to append().
    The gate verifies the token before allowing the write.
    """

    __slots__ = ("caller_id", "record_type", "payload_hash", "timestamp", "nonce", "signature")

    def __init__(
        self,
        caller_id: str,
        record_type: str,
        payload: dict | None,
        signing_key: bytes,
        payload_hash: str | None = None,
    ):
        self.caller_id = caller_id
        self.record_type = record_type
        if payload_hash is None:
            if payload is None:
                raise ValueError("payload is required unless payload_hash is provided")
            payload_hash = hashlib.sha256(
                json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
        self.payload_hash = payload_hash
        self.timestamp = datetime.now(UTC).isoformat()
        self.nonce = uuid.uuid4().hex
        self.signature = sign_record(
            signing_key=signing_key,
            caller_id=caller_id,
            record_type=record_type,
            payload_hash=self.payload_hash,
            timestamp=self.timestamp,
            nonce=self.nonce,
        )

    @classmethod
    def delegated(cls, caller_id: str, record_type: str, signing_key: bytes) -> "WriteToken":
        return cls(
            caller_id=caller_id,
            record_type=record_type,
            payload=None,
            signing_key=signing_key,
            payload_hash=DELEGATED_PAYLOAD_HASH,
        )


class PermissionGate:
    """Single enforcement point for all substrate writes.

    Created once. Shared by all substrates. Backed by the CallerRegistry.
    """

    def __init__(self, registry: CallerRegistry):
        self._registry = registry
        self._denial_log: list[dict] = []
        self._denial_log_max = 1000

    def check(self, substrate_name: str, token: WriteToken, actual_payload: dict | None = None) -> str:
        """Verify a write is authorized. Returns caller_id on success.

        If actual_payload is provided, verifies the token's payload_hash
        matches the real payload being written (prevents token reuse with
        different data). For delegated substrate methods where the payload
        is built internally, actual_payload may be None — identity and
        ACL are still verified, but payload binding is not claimed.

        Raises PermissionDenied on failure.
        """
        # 1. Is caller registered?
        entry = self._registry.get(token.caller_id)
        if entry is None:
            self._deny(token.caller_id, substrate_name, "unregistered caller")
            raise PermissionDenied(token.caller_id, substrate_name, "unregistered caller")

        # 2. Is caller authorized for this substrate?
        if not entry.may_write(substrate_name):
            entry.record_denial(substrate_name)
            self._deny(token.caller_id, substrate_name, "not in allowed_write list")
            raise PermissionDenied(token.caller_id, substrate_name, "not in allowed_write list")

        # 3. Is signature valid? (proves caller holds the real HMAC key)
        valid = verify_signature(
            signing_key=entry.signing_key,
            caller_id=token.caller_id,
            record_type=token.record_type,
            payload_hash=token.payload_hash,
            timestamp=token.timestamp,
            nonce=token.nonce,
            signature=token.signature,
        )
        if not valid:
            entry.record_denial(substrate_name)
            self._deny(token.caller_id, substrate_name, "invalid signature")
            raise PermissionDenied(token.caller_id, substrate_name, "invalid signature")

        # 4. Payload binding check (when actual payload is available)
        if actual_payload is not None:
            real_hash = hashlib.sha256(
                json.dumps(actual_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if token.payload_hash != real_hash:
                entry.record_denial(substrate_name)
                self._deny(token.caller_id, substrate_name, "payload hash mismatch")
                raise PermissionDenied(token.caller_id, substrate_name, "payload hash mismatch")

        # Authorized
        entry.record_write()
        return token.caller_id

    def _deny(self, caller_id: str, substrate: str, reason: str) -> None:
        """Log a denial."""
        denial = {
            "caller_id": caller_id,
            "substrate": substrate,
            "reason": reason,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        logger.warning("PERMISSION DENIED: %s -> %s: %s", caller_id, substrate, reason)

        if len(self._denial_log) >= self._denial_log_max:
            self._denial_log = self._denial_log[-500:]
        self._denial_log.append(denial)

    def recent_denials(self, limit: int = 50) -> list[dict]:
        return self._denial_log[-limit:]

    def denial_count(self) -> int:
        return len(self._denial_log)
