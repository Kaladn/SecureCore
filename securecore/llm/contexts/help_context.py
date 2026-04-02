"""Typed help-context builder for grounded operator help."""

from __future__ import annotations

import json
from pathlib import Path

from securecore.help.code_index import CodeMirrorIndex
from securecore.help.corpus import HelpCorpus
from securecore.help.runtime_context import build_runtime_context
from securecore.llm.contexts.types import ContextBlock, ContextBundle


def _read_mirrored_source(mirror_path: str, max_file_chars: int = 8000) -> str:
    if not mirror_path:
        return ""
    path = Path(mirror_path)
    if not path.exists() or not path.is_file():
        return ""
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if len(content) > max_file_chars:
        return content[:max_file_chars] + f"\n... (truncated at {max_file_chars} chars)"
    return content


def build_help_context(
    question: str,
    corpus: HelpCorpus | None = None,
    code_index: CodeMirrorIndex | None = None,
    *,
    include_runtime: bool = True,
    max_context_chars: int = 24000,
) -> tuple[ContextBundle, dict]:
    corpus = corpus or HelpCorpus()
    code_index = code_index or CodeMirrorIndex()
    corpus_hits = corpus.search(question)
    code_hits = code_index.search(question, limit=5)

    blocks: list[ContextBlock] = []

    if corpus_hits:
        corpus_text = []
        for hit in corpus_hits[:5]:
            entry = corpus.get(hit["help_id"])
            if entry:
                corpus_text.append(f"HELP [{hit['help_id']}]: {json.dumps(entry, indent=2)}")
        if corpus_text:
            blocks.append(
                ContextBlock.build(
                    source_label="help_corpus",
                    source_ref="help_content.json",
                    rank=0,
                    content="HELP CORPUS MATCHES:\n" + "\n\n".join(corpus_text),
                )
            )

    if code_hits:
        code_text = []
        budget = max_context_chars // 2
        chars_used = 0
        refs: list[str] = []
        for hit in code_hits[:5]:
            symbols = ", ".join(s["name"] for s in hit.get("symbols", [])[:10])
            header = f"FILE: {hit['relative_path']}  symbols: {symbols}"
            refs.append(hit["relative_path"])
            source_content = _read_mirrored_source(hit.get("mirror_path", ""))
            if source_content and chars_used + len(source_content) <= budget:
                code_text.append(f"{header}\n```\n{source_content}\n```")
                chars_used += len(source_content)
            else:
                code_text.append(header)
        if code_text:
            blocks.append(
                ContextBlock.build(
                    source_label="code_index",
                    source_ref=", ".join(refs),
                    rank=1,
                    content="CODE MATCHES (with source):\n" + "\n\n".join(code_text),
                )
            )

    runtime_included = False
    if include_runtime:
        try:
            runtime = build_runtime_context()
        except Exception as exc:
            runtime = f"RUNTIME STATE: unavailable ({exc})"
        blocks.append(
            ContextBlock.build(
                source_label="runtime_snapshot",
                source_ref="control_bus.status_snapshot",
                rank=2,
                content="RUNTIME STATE:\n" + runtime,
            )
        )
        runtime_included = True

    bundle = ContextBundle.build(blocks)
    metadata = {
        "corpus_hits": len(corpus_hits),
        "code_hits": len(code_hits),
        "runtime_included": runtime_included,
    }
    return bundle, metadata
