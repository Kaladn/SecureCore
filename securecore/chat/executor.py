"""Mode-aware chat execution for the SecureCore control center."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from securecore.chat.ledger import ChatLedger
from securecore.chat.models import (
    DEFAULT_BRANCH_ID,
    INFERENCE_PRESETS,
    TRUST_STATE_PLACEHOLDER,
    new_conversation_id,
)
from securecore.chat.projection import get_block, project_blocks
from securecore.chat.router import ChatRouter
from securecore.llm.contexts.analyze_context import build_analyze_context
from securecore.llm.contexts.draft_context import build_draft_context

OPERATIONS_SYSTEM_PROMPT = """You are the SecureCore operations assistant.

You speak to the operator about the live organism.

Rules:
- prioritize current runtime state over abstraction
- be concise and practical
- do not claim to have executed control actions
- recommend the next safe operator step when helpful
- never invent data not present in context
"""

BUILD_SYSTEM_PROMPT = """You are the SecureCore build assistant.

You help design and implement the system inside its current doctrine.

Rules:
- respect localhost-only, trust-gated, append-only design
- prefer small coherent backend slices over sprawling UI work
- do not invent completed subsystems
- when context is thin, state assumptions plainly
- keep answers implementation-oriented
"""


class ChatExecutor:
    """Coordinates ledger writes and mode-specific response generation."""

    def __init__(self, ledger: ChatLedger, help_bot, broker) -> None:
        self._ledger = ledger
        self._help_bot = help_bot
        self._broker = broker
        self._router = ChatRouter()

    def send(
        self,
        *,
        message: str,
        mode: str | None = None,
        conversation_id: str | None = None,
        branch_id: str | None = None,
    ) -> dict[str, Any]:
        normalized_mode = self._router.normalize_mode(mode)
        conversation_id = conversation_id or new_conversation_id()
        branch_id = branch_id or DEFAULT_BRANCH_ID

        if not self._ledger.conversation_exists(conversation_id):
            self._ledger.start_conversation(conversation_id, normalized_mode)
        if branch_id == DEFAULT_BRANCH_ID and not self._ledger.branch_exists(conversation_id, branch_id):
            self._ledger.ensure_branch(conversation_id, branch_id, mode=normalized_mode)
        elif branch_id != DEFAULT_BRANCH_ID and not self._ledger.branch_exists(conversation_id, branch_id):
            raise ValueError(f"unknown branch_id: {branch_id}")

        user_record = self._ledger.append_message(
            conversation_id=conversation_id,
            branch_id=branch_id,
            mode=normalized_mode,
            role="operator",
            content=message,
        )

        recent_messages = self._ledger.tail_messages(conversation_id, branch_id=branch_id, limit=12)

        if normalized_mode == "support":
            result = self._execute_support(message)
        elif normalized_mode == "operations":
            result = self._execute_operations(message, recent_messages)
        else:
            result = self._execute_build(message, recent_messages)

        assistant_record = self._ledger.append_message(
            conversation_id=conversation_id,
            branch_id=branch_id,
            mode=normalized_mode,
            role="assistant",
            content=result["response"],
            metadata=result.get("metadata", {}),
        )

        return {
            "conversation_id": conversation_id,
            "branch_id": branch_id,
            "mode": normalized_mode,
            "response": result["response"],
            "message_ids": {
                "user": user_record.message_id,
                "assistant": assistant_record.message_id,
            },
            "basis": result.get("basis", []),
            "file_refs": result.get("file_refs", []),
            "commands": result.get("commands", []),
            "unknowns": result.get("unknowns", []),
            "metadata": result.get("metadata", {}),
            "inference": result.get("inference", {}),
            "trust": {"state": TRUST_STATE_PLACEHOLDER},
        }

    def history(
        self,
        *,
        conversation_id: str,
        branch_id: str = DEFAULT_BRANCH_ID,
    ) -> dict[str, Any]:
        if not self._ledger.conversation_exists(conversation_id):
            raise ValueError(f"unknown conversation_id: {conversation_id}")
        if branch_id != DEFAULT_BRANCH_ID and not self._ledger.branch_exists(conversation_id, branch_id):
            raise ValueError(f"unknown branch_id: {branch_id}")

        messages = self._ledger.conversation_messages(conversation_id, branch_id=branch_id)
        notes_by_key, citations_by_key = self._annotation_indexes(conversation_id)

        rendered_messages = []
        for record in messages:
            blocks = []
            for block in project_blocks(str(record.payload.get("content", ""))):
                key = (record.message_id, block.block_id)
                notes = notes_by_key.get(key, [])
                citations = citations_by_key.get(key, [])
                blocks.append(
                    {
                        **block.to_dict(),
                        "notes": notes,
                        "citations": citations,
                        "note_count": len(notes),
                        "citation_count": len(citations),
                    }
                )

            rendered_messages.append(
                {
                    "message_id": record.message_id,
                    "role": record.role,
                    "mode": record.mode,
                    "branch_id": record.branch_id,
                    "timestamp": record.timestamp,
                    "content": record.payload.get("content", ""),
                    "metadata": dict(record.payload.get("metadata", {})),
                    "blocks": blocks,
                }
            )

        return {
            "conversation_id": conversation_id,
            "branch_id": branch_id,
            "messages": rendered_messages,
            "trust": {"state": TRUST_STATE_PLACEHOLDER},
        }

    def add_note(
        self,
        *,
        conversation_id: str,
        message_id: str,
        block_id: str,
        content: str,
        branch_id: str | None = None,
    ) -> dict[str, Any]:
        message_record, block = self._resolve_target_block(
            conversation_id=conversation_id,
            message_id=message_id,
            block_id=block_id,
        )
        note_record = self._ledger.append_note(
            conversation_id=conversation_id,
            branch_id=branch_id or message_record.branch_id,
            mode=message_record.mode,
            message_id=message_id,
            block_id=block.block_id,
            block_index=block.block_index,
            content=content,
        )
        return {
            "conversation_id": conversation_id,
            "message_id": message_id,
            "block_id": block.block_id,
            "note": {
                "note_id": note_record.payload["note_id"],
                "content": note_record.payload["content"],
                "timestamp": note_record.timestamp,
            },
        }

    def add_citation(
        self,
        *,
        conversation_id: str,
        message_id: str,
        block_id: str,
        source_type: str,
        source_ref: str,
        excerpt: str = "",
        branch_id: str | None = None,
    ) -> dict[str, Any]:
        message_record, block = self._resolve_target_block(
            conversation_id=conversation_id,
            message_id=message_id,
            block_id=block_id,
        )
        citation_record = self._ledger.append_citation(
            conversation_id=conversation_id,
            branch_id=branch_id or message_record.branch_id,
            mode=message_record.mode,
            message_id=message_id,
            block_id=block.block_id,
            block_index=block.block_index,
            source_type=source_type,
            source_ref=source_ref,
            excerpt=excerpt,
        )
        return {
            "conversation_id": conversation_id,
            "message_id": message_id,
            "block_id": block.block_id,
            "citation": {
                "citation_id": citation_record.payload["citation_id"],
                "source_type": citation_record.payload["source_type"],
                "source_ref": citation_record.payload["source_ref"],
                "excerpt": citation_record.payload.get("excerpt", ""),
                "timestamp": citation_record.timestamp,
            },
        }

    def continue_chat(
        self,
        *,
        conversation_id: str,
        parent_message_id: str,
        parent_block_id: str = "",
        mode: str | None = None,
        reason: str = "continue_chat",
    ) -> dict[str, Any]:
        parent_record = self._ledger.get_message(conversation_id, parent_message_id)
        if parent_record is None:
            raise ValueError(f"unknown message_id: {parent_message_id}")
        if parent_block_id:
            _, _ = self._resolve_target_block(
                conversation_id=conversation_id,
                message_id=parent_message_id,
                block_id=parent_block_id,
            )

        branch_mode = self._router.normalize_mode(mode or parent_record.mode)
        branch_record = self._ledger.create_branch(
            conversation_id=conversation_id,
            mode=branch_mode,
            parent_message_id=parent_message_id,
            parent_branch_id=parent_record.branch_id,
            parent_block_id=parent_block_id,
            reason=reason,
        )
        return {
            "conversation_id": conversation_id,
            "branch_id": branch_record.branch_id,
            "parent_message_id": parent_message_id,
            "parent_block_id": parent_block_id,
            "mode": branch_mode,
            "trust": {"state": TRUST_STATE_PLACEHOLDER},
        }

    def _execute_support(self, message: str) -> dict[str, Any]:
        preset = INFERENCE_PRESETS["support"]
        result = self._help_bot.ask(message, include_runtime=True)
        return {
            "response": result.get("answer", ""),
            "basis": result.get("basis", []),
            "file_refs": result.get("file_refs", []),
            "commands": result.get("commands", []),
            "unknowns": result.get("unknowns", []),
            "metadata": {
                "sources": result.get("sources", {}),
                "structured": result.get("structured", False),
                "context_bundle_hash": result.get("context_bundle_hash", ""),
            },
            "inference": {
                "model": result.get("model", ""),
                "temperature": preset["temperature"],
                "max_tokens": preset["max_tokens"],
            },
        }

    def _execute_operations(self, message: str, recent_messages) -> dict[str, Any]:
        preset = INFERENCE_PRESETS["operations"]
        bundle = build_analyze_context(recent_messages=recent_messages)
        response = self._broker.query(
            role_name="operations",
            prompt=message,
            context_bundle=bundle,
            temperature=preset["temperature"],
            max_tokens=preset["max_tokens"],
        )
        model = ""
        role = self._broker.get_role("operations")
        if role is not None:
            model = role.model
        return {
            "response": response or "Operations mode is unavailable. Local model may not be running.",
            "metadata": {
                "context_bundle_hash": bundle.bundle_hash,
                "sources": [block.source_label for block in bundle.blocks],
            },
            "inference": {
                "model": model,
                "temperature": preset["temperature"],
                "max_tokens": preset["max_tokens"],
            },
        }

    def _execute_build(self, message: str, recent_messages) -> dict[str, Any]:
        preset = INFERENCE_PRESETS["build"]
        bundle = build_draft_context(recent_messages=recent_messages)
        response = self._broker.query(
            role_name="build",
            prompt=message,
            context_bundle=bundle,
            temperature=preset["temperature"],
            max_tokens=preset["max_tokens"],
        )
        model = ""
        role = self._broker.get_role("build")
        if role is not None:
            model = role.model
        return {
            "response": response or "Build mode is unavailable. Local model may not be running.",
            "metadata": {
                "context_bundle_hash": bundle.bundle_hash,
                "sources": [block.source_label for block in bundle.blocks],
            },
            "inference": {
                "model": model,
                "temperature": preset["temperature"],
                "max_tokens": preset["max_tokens"],
            },
        }

    def _annotation_indexes(
        self,
        conversation_id: str,
    ) -> tuple[dict[tuple[str, str], list[dict[str, Any]]], dict[tuple[str, str], list[dict[str, Any]]]]:
        notes_by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        citations_by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

        for record in self._ledger.records_for_conversation(conversation_id):
            key = (record.message_id, str(record.payload.get("block_id", "")))
            if record.entry_type == "note":
                notes_by_key[key].append(
                    {
                        "note_id": record.payload.get("note_id", record.record_id),
                        "content": record.payload.get("content", ""),
                        "timestamp": record.timestamp,
                    }
                )
            elif record.entry_type == "citation":
                citations_by_key[key].append(
                    {
                        "citation_id": record.payload.get("citation_id", record.record_id),
                        "source_type": record.payload.get("source_type", ""),
                        "source_ref": record.payload.get("source_ref", ""),
                        "excerpt": record.payload.get("excerpt", ""),
                        "timestamp": record.timestamp,
                    }
                )

        return notes_by_key, citations_by_key

    def _resolve_target_block(
        self,
        *,
        conversation_id: str,
        message_id: str,
        block_id: str,
    ):
        message_record = self._ledger.get_message(conversation_id, message_id)
        if message_record is None:
            raise ValueError(f"unknown message_id: {message_id}")

        block = get_block(str(message_record.payload.get("content", "")), block_id)
        if block is None:
            raise ValueError(f"unknown block_id: {block_id}")

        return message_record, block
