"""Append-only JSONL ledger for chat conversations."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
import uuid

from securecore.chat.models import DEFAULT_BRANCH_ID, new_branch_id


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class ChatLedgerRecord:
    record_id: str
    sequence: int
    timestamp: str
    conversation_id: str
    branch_id: str
    entry_type: str
    mode: str
    role: str
    message_id: str
    payload: dict[str, Any]
    previous_hash: str
    chain_hash: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ChatLedgerRecord":
        return cls(
            record_id=str(payload["record_id"]),
            sequence=int(payload["sequence"]),
            timestamp=str(payload["timestamp"]),
            conversation_id=str(payload["conversation_id"]),
            branch_id=str(payload["branch_id"]),
            entry_type=str(payload["entry_type"]),
            mode=str(payload["mode"]),
            role=str(payload["role"]),
            message_id=str(payload.get("message_id", "")),
            payload=dict(payload.get("payload", {})),
            previous_hash=str(payload["previous_hash"]),
            chain_hash=str(payload["chain_hash"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "conversation_id": self.conversation_id,
            "branch_id": self.branch_id,
            "entry_type": self.entry_type,
            "mode": self.mode,
            "role": self.role,
            "message_id": self.message_id,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
            "chain_hash": self.chain_hash,
        }


class ChatLedger:
    """Single append-only chat truth store."""

    def __init__(self, jsonl_path: str | Path):
        self._path = Path(jsonl_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    @property
    def jsonl_path(self) -> Path:
        return self._path

    def conversation_exists(self, conversation_id: str) -> bool:
        with self._lock:
            return any(
                record.conversation_id == conversation_id
                for record in self._records_locked()
            )

    def branch_exists(self, conversation_id: str, branch_id: str) -> bool:
        with self._lock:
            return any(
                record.entry_type == "branch_created"
                and record.conversation_id == conversation_id
                and record.branch_id == branch_id
                for record in self._records_locked()
            )

    def start_conversation(self, conversation_id: str, mode: str) -> ChatLedgerRecord:
        return self._append(
            conversation_id=conversation_id,
            branch_id=DEFAULT_BRANCH_ID,
            entry_type="conversation_started",
            mode=mode,
            role="system",
            message_id="",
            payload={"conversation_id": conversation_id, "root_branch_id": DEFAULT_BRANCH_ID},
        )

    def ensure_branch(
        self,
        conversation_id: str,
        branch_id: str = DEFAULT_BRANCH_ID,
        *,
        mode: str,
        parent_message_id: str = "",
        parent_branch_id: str = "",
        parent_block_id: str = "",
        reason: str = "root",
    ) -> ChatLedgerRecord | None:
        with self._lock:
            if self.branch_exists(conversation_id, branch_id):
                return None
            return self._append_locked(
                conversation_id=conversation_id,
                branch_id=branch_id,
                entry_type="branch_created",
                mode=mode,
                role="system",
                message_id="",
                payload={
                    "branch_id": branch_id,
                    "parent_message_id": parent_message_id,
                    "parent_branch_id": parent_branch_id,
                    "parent_block_id": parent_block_id,
                    "reason": reason,
                },
            )

    def create_branch(
        self,
        *,
        conversation_id: str,
        mode: str,
        parent_message_id: str,
        parent_branch_id: str,
        parent_block_id: str = "",
        reason: str = "continue_chat",
    ) -> ChatLedgerRecord:
        branch_id = new_branch_id()
        return self._append(
            conversation_id=conversation_id,
            branch_id=branch_id,
            entry_type="branch_created",
            mode=mode,
            role="system",
            message_id="",
            payload={
                "branch_id": branch_id,
                "parent_message_id": parent_message_id,
                "parent_branch_id": parent_branch_id,
                "parent_block_id": parent_block_id,
                "reason": reason,
            },
        )

    def append_message(
        self,
        *,
        conversation_id: str,
        branch_id: str,
        mode: str,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
        message_id: str = "",
    ) -> ChatLedgerRecord:
        msg_id = message_id or f"msg_{uuid.uuid4().hex[:16]}"
        return self._append(
            conversation_id=conversation_id,
            branch_id=branch_id,
            entry_type="message",
            mode=mode,
            role=role,
            message_id=msg_id,
            payload={
                "content": content,
                "metadata": dict(metadata or {}),
            },
        )

    def append_note(
        self,
        *,
        conversation_id: str,
        branch_id: str,
        mode: str,
        message_id: str,
        block_id: str,
        block_index: int,
        content: str,
    ) -> ChatLedgerRecord:
        note_id = f"note_{uuid.uuid4().hex[:16]}"
        return self._append(
            conversation_id=conversation_id,
            branch_id=branch_id,
            entry_type="note",
            mode=mode,
            role="operator",
            message_id=message_id,
            payload={
                "note_id": note_id,
                "block_id": block_id,
                "block_index": block_index,
                "content": content,
            },
        )

    def append_citation(
        self,
        *,
        conversation_id: str,
        branch_id: str,
        mode: str,
        message_id: str,
        block_id: str,
        block_index: int,
        source_type: str,
        source_ref: str,
        excerpt: str = "",
    ) -> ChatLedgerRecord:
        citation_id = f"cite_{uuid.uuid4().hex[:16]}"
        return self._append(
            conversation_id=conversation_id,
            branch_id=branch_id,
            entry_type="citation",
            mode=mode,
            role="operator",
            message_id=message_id,
            payload={
                "citation_id": citation_id,
                "block_id": block_id,
                "block_index": block_index,
                "source_type": source_type,
                "source_ref": source_ref,
                "excerpt": excerpt,
            },
        )

    def get_message(self, conversation_id: str, message_id: str) -> ChatLedgerRecord | None:
        with self._lock:
            for record in self._records_locked():
                if (
                    record.entry_type == "message"
                    and record.conversation_id == conversation_id
                    and record.message_id == message_id
                ):
                    return record
        return None

    def records_for_conversation(self, conversation_id: str) -> list[ChatLedgerRecord]:
        with self._lock:
            return [
                record
                for record in self._records_locked()
                if record.conversation_id == conversation_id
            ]

    def conversation_messages(
        self,
        conversation_id: str,
        *,
        branch_id: str = DEFAULT_BRANCH_ID,
    ) -> list[ChatLedgerRecord]:
        with self._lock:
            records = [
                record
                for record in self._records_locked()
                if record.conversation_id == conversation_id
            ]
            return self._conversation_messages_locked(records, branch_id)

    def tail_messages(
        self,
        conversation_id: str,
        *,
        branch_id: str = DEFAULT_BRANCH_ID,
        limit: int = 12,
    ) -> list[ChatLedgerRecord]:
        records = self.conversation_messages(conversation_id, branch_id=branch_id)
        return records[-limit:]

    def verify_chain(self) -> dict[str, Any]:
        with self._lock:
            expected_prev = "GENESIS"
            total = 0
            for record in self._records_locked():
                if record.previous_hash != expected_prev:
                    return {
                        "intact": False,
                        "broken_at_sequence": record.sequence,
                        "error": "previous_hash mismatch",
                    }
                recomputed = self._compute_hash(record)
                if recomputed != record.chain_hash:
                    return {
                        "intact": False,
                        "broken_at_sequence": record.sequence,
                        "error": "chain_hash mismatch",
                    }
                expected_prev = record.chain_hash
                total += 1
            return {"intact": True, "total_records": total}

    def _append(
        self,
        *,
        conversation_id: str,
        branch_id: str,
        entry_type: str,
        mode: str,
        role: str,
        message_id: str,
        payload: dict[str, Any],
    ) -> ChatLedgerRecord:
        with self._lock:
            return self._append_locked(
                conversation_id=conversation_id,
                branch_id=branch_id,
                entry_type=entry_type,
                mode=mode,
                role=role,
                message_id=message_id,
                payload=payload,
            )

    def _append_locked(
        self,
        *,
        conversation_id: str,
        branch_id: str,
        entry_type: str,
        mode: str,
        role: str,
        message_id: str,
        payload: dict[str, Any],
    ) -> ChatLedgerRecord:
        records = self._records_locked()
        previous_hash = records[-1].chain_hash if records else "GENESIS"
        sequence = (records[-1].sequence + 1) if records else 0
        record = ChatLedgerRecord(
            record_id=f"chat_{uuid.uuid4().hex[:16]}",
            sequence=sequence,
            timestamp=_utc_now(),
            conversation_id=conversation_id,
            branch_id=branch_id,
            entry_type=entry_type,
            mode=mode,
            role=role,
            message_id=message_id,
            payload=dict(payload),
            previous_hash=previous_hash,
            chain_hash="",
        )
        chain_hash = self._compute_hash(record)
        record = ChatLedgerRecord(
            record_id=record.record_id,
            sequence=record.sequence,
            timestamp=record.timestamp,
            conversation_id=record.conversation_id,
            branch_id=record.branch_id,
            entry_type=record.entry_type,
            mode=record.mode,
            role=record.role,
            message_id=record.message_id,
            payload=record.payload,
            previous_hash=record.previous_hash,
            chain_hash=chain_hash,
        )
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record.to_dict(), separators=(",", ":"), ensure_ascii=False))
            handle.write("\n")
        return record

    def _records_locked(self) -> list[ChatLedgerRecord]:
        if not self._path.exists():
            return []
        records: list[ChatLedgerRecord] = []
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                records.append(ChatLedgerRecord.from_dict(payload))
        return records

    @staticmethod
    def _conversation_messages_locked(
        records: list[ChatLedgerRecord],
        branch_id: str,
    ) -> list[ChatLedgerRecord]:
        if branch_id == DEFAULT_BRANCH_ID:
            return [record for record in records if record.entry_type == "message" and record.branch_id == DEFAULT_BRANCH_ID]

        branch_meta = {
            DEFAULT_BRANCH_ID: {
                "parent_branch_id": "",
                "parent_message_id": "",
                "parent_block_id": "",
                "reason": "root",
            }
        }
        for record in records:
            if record.entry_type != "branch_created":
                continue
            branch_meta[record.branch_id] = {
                "parent_branch_id": str(record.payload.get("parent_branch_id", "")),
                "parent_message_id": str(record.payload.get("parent_message_id", "")),
                "parent_block_id": str(record.payload.get("parent_block_id", "")),
                "reason": str(record.payload.get("reason", "")),
            }

        if branch_id not in branch_meta:
            return []

        lineage: list[str] = []
        cursor = branch_id
        seen: set[str] = set()
        while cursor and cursor not in seen:
            seen.add(cursor)
            lineage.append(cursor)
            if cursor == DEFAULT_BRANCH_ID:
                break
            parent_branch_id = branch_meta.get(cursor, {}).get("parent_branch_id") or DEFAULT_BRANCH_ID
            cursor = parent_branch_id
        lineage.reverse()

        message_records = [record for record in records if record.entry_type == "message"]
        visible: list[ChatLedgerRecord] = []

        for index, active_branch_id in enumerate(lineage):
            cutoff_message_id = ""
            if index + 1 < len(lineage):
                next_branch = lineage[index + 1]
                cutoff_message_id = branch_meta.get(next_branch, {}).get("parent_message_id", "")

            branch_messages = [
                record for record in message_records if record.branch_id == active_branch_id
            ]
            for record in branch_messages:
                visible.append(record)
                if cutoff_message_id and record.message_id == cutoff_message_id:
                    break

        return visible

    @staticmethod
    def _compute_hash(record: ChatLedgerRecord) -> str:
        canonical = "|".join(
            [
                record.record_id,
                str(record.sequence),
                record.timestamp,
                record.conversation_id,
                record.branch_id,
                record.entry_type,
                record.mode,
                record.role,
                record.message_id,
                json.dumps(record.payload, sort_keys=True, separators=(",", ":")),
                record.previous_hash,
            ]
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
