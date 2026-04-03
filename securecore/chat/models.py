"""Typed chat constants and id helpers."""

from __future__ import annotations

from dataclasses import dataclass
import uuid

VALID_MODES = frozenset({"support", "operations", "build"})
DEFAULT_MODE = "support"
DEFAULT_BRANCH_ID = "main"
MAX_MESSAGE_CHARS = 100_000
TRUST_STATE_PLACEHOLDER = "FULL"

INFERENCE_PRESETS = {
    "support": {"temperature": 0.0, "max_tokens": 2048},
    "operations": {"temperature": 0.1, "max_tokens": 1200},
    "build": {"temperature": 0.2, "max_tokens": 1600},
    # Reserved slot for future retrieval-heavy grounding without adding a fourth visible mode.
    "grounded": {"temperature": 0.0, "max_tokens": 2048},
}


def normalize_mode(mode: str | None) -> str:
    raw = (mode or "").strip().lower()
    return raw if raw in VALID_MODES else DEFAULT_MODE


def new_conversation_id() -> str:
    return f"conv_{uuid.uuid4().hex[:16]}"


def new_message_id() -> str:
    return f"msg_{uuid.uuid4().hex[:16]}"


def new_branch_id() -> str:
    return f"branch_{uuid.uuid4().hex[:12]}"


@dataclass(frozen=True, slots=True)
class ChatTurn:
    conversation_id: str
    branch_id: str
    mode: str
    message: str
