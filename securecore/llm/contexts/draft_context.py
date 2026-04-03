"""Draft-role context builder."""

from __future__ import annotations

from securecore.llm.contexts.types import ContextBlock, ContextBundle


def _history_block(recent_messages: list, max_chars: int = 6000) -> ContextBlock | None:
    if not recent_messages:
        return None
    lines = []
    chars = 0
    for record in recent_messages[-10:]:
        content = str(record.payload.get("content", "")).strip()
        if not content:
            continue
        line = f"{record.role.upper()}: {content}"
        if chars + len(line) > max_chars:
            break
        lines.append(line)
        chars += len(line)
    if not lines:
        return None
    return ContextBlock.build(
        source_label="chat_history",
        source_ref="chat_ledger.tail",
        rank=0,
        content="RECENT CHAT HISTORY:\n" + "\n\n".join(lines),
    )


def build_draft_context(*, recent_messages: list | None = None) -> ContextBundle:
    blocks = []
    history = _history_block(recent_messages or [])
    if history is not None:
        blocks.append(history)
    blocks.append(
        ContextBlock.build(
            source_label="build_workspace",
            source_ref="securecore/",
            rank=1,
            content=(
                "SECURECORE BUILD LANE:\n"
                "- runtime organism lives under securecore/\n"
                "- current stable lanes include agents, control, help, llm, permissions, substrates, routes, forge\n"
                "- preserve localhost-only, trust-gated, append-only design\n"
                "- prefer coherent backend slices before UI work\n"
            ),
        )
    )
    return ContextBundle.build(blocks)
