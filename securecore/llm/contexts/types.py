"""Typed context bundles for grounded LLM roles."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ContextBlock:
    source_label: str
    source_ref: str
    rank: int
    content: str
    content_hash: str

    @classmethod
    def build(cls, source_label: str, source_ref: str, rank: int, content: str) -> "ContextBlock":
        normalized = content or ""
        return cls(
            source_label=source_label,
            source_ref=source_ref,
            rank=rank,
            content=normalized,
            content_hash=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
        )


@dataclass(frozen=True, slots=True)
class ContextBundle:
    blocks: tuple[ContextBlock, ...]
    bundle_hash: str
    total_chars: int

    @classmethod
    def build(cls, blocks: list[ContextBlock] | tuple[ContextBlock, ...]) -> "ContextBundle":
        ordered = tuple(
            sorted(
                blocks,
                key=lambda block: (block.rank, block.source_label, block.source_ref, block.content_hash),
            )
        )
        canonical = "\n".join(
            f"{block.rank}|{block.source_label}|{block.source_ref}|{block.content_hash}"
            for block in ordered
        )
        return cls(
            blocks=ordered,
            bundle_hash=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            total_chars=sum(len(block.content) for block in ordered),
        )

    def as_mapping(self) -> dict[str, str]:
        return {block.source_label: block.content for block in self.blocks}
