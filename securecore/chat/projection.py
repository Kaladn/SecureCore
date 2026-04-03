"""Deterministic message-to-block projection for the chat surface."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ChatBlock:
    block_id: str
    block_index: int
    content: str
    block_type: str
    language: str = ""

    def to_dict(self) -> dict:
        return {
            "block_id": self.block_id,
            "block_index": self.block_index,
            "content": self.content,
            "block_type": self.block_type,
            "language": self.language,
        }


def project_blocks(content: str) -> list[ChatBlock]:
    """Split a message into stable paragraph/code blocks.

    Rules:
    - blank lines split text paragraphs
    - fenced code blocks stay intact
    - order is deterministic so block IDs remain stable for immutable messages
    """
    text = (content or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return []

    blocks: list[ChatBlock] = []
    current: list[str] = []
    in_code = False
    code_language = ""
    fence = "```"

    def flush() -> None:
        nonlocal current, code_language
        if not current:
            return
        block_text = "\n".join(current).strip("\n")
        if not block_text.strip():
            current = []
            code_language = ""
            return
        block_index = len(blocks)
        blocks.append(
            ChatBlock(
                block_id=f"b{block_index}",
                block_index=block_index,
                content=block_text,
                block_type="code" if in_code else "text",
                language=code_language if in_code else "",
            )
        )
        current = []
        code_language = ""

    for line in text.split("\n"):
        stripped = line.strip()
        if stripped.startswith(fence):
            if in_code:
                current.append(line)
                flush()
                in_code = False
                continue
            flush()
            in_code = True
            code_language = stripped[len(fence):].strip()
            current.append(line)
            continue

        if in_code:
            current.append(line)
            continue

        if not stripped:
            flush()
            continue

        current.append(line)

    flush()
    return blocks


def get_block(content: str, block_id: str) -> ChatBlock | None:
    for block in project_blocks(content):
        if block.block_id == block_id:
            return block
    return None
