"""Help bot — tier 4 grounded chat powered by local LLM.

The bot:
  - searches help corpus for matching entries
  - searches code mirror for relevant symbols/files
  - pulls runtime context from the control bus
  - packs everything into a grounded prompt
  - queries the local LLM through the broker
  - returns a grounded answer

The bot is read-only. It has no write authority. It cannot
pause the Reaper, shun IPs, or modify substrates.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from securecore.help.config import load_help_config
from securecore.help.corpus import HelpCorpus
from securecore.help.code_index import CodeMirrorIndex
from securecore.help.runtime_context import build_runtime_context
from securecore.llm.broker import LLMBroker

logger = logging.getLogger("help.bot")

SYSTEM_PROMPT = """You are the SecureCore help assistant.

You answer questions about the SecureCore defensive security system.
You are grounded — you only answer from the provided context.

Rules:
- Answer from the help corpus, code index, and runtime context provided
- Say "I don't have information about that" when context is missing
- Use SecureCore terminology (substrates, agents, Reaper, Forge, cells)
- Give operator-safe guidance — never suggest bypassing security controls
- Suggest the exact CLI command when useful
- Never claim you executed anything
- Be concise and direct

Doctrine:
- Substrates append. Forge stores. Loggers log. Agents infer.
- No write without identity. No identity without registration.
- Read commands read. Control commands hit the live organism.
"""


def _load_system_prompt(config: dict) -> str:
    """Load system prompt from file if present, fall back to built-in constant."""
    prompt_path = config.get("system_prompt_path")
    if prompt_path:
        from pathlib import Path
        p = Path(prompt_path)
        if p.exists() and p.is_file():
            try:
                return p.read_text(encoding="utf-8").strip()
            except Exception:
                pass
    return SYSTEM_PROMPT


class HelpBot:
    """Grounded help chat backed by local LLM."""

    def __init__(self, broker: LLMBroker, role_name: str = "help"):
        self._broker = broker
        self._role_name = role_name
        self._corpus = HelpCorpus()
        self._code_index = CodeMirrorIndex()
        self._config = load_help_config()
        self._system_prompt = _load_system_prompt(self._config)

    def ask(self, question: str, include_runtime: bool = True) -> dict:
        """Ask the help bot a question.

        Returns a dict with the answer, sources used, and metadata.
        """
        # Search help corpus
        corpus_hits = self._corpus.search(question)

        # Search code index
        code_hits = self._code_index.search(question, limit=5)

        # Build context
        context_parts = []

        if corpus_hits:
            corpus_text = []
            for hit in corpus_hits[:5]:
                entry = self._corpus.get(hit["help_id"])
                if entry:
                    corpus_text.append(f"HELP [{hit['help_id']}]: {json.dumps(entry, indent=2)}")
            context_parts.append("HELP CORPUS MATCHES:\n" + "\n\n".join(corpus_text))

        if code_hits:
            code_text = []
            budget = self._config["max_context_chars"] // 2  # reserve half for code
            chars_used = 0
            for hit in code_hits[:5]:
                symbols = ", ".join(s["name"] for s in hit.get("symbols", [])[:10])
                header = f"FILE: {hit['relative_path']}  symbols: {symbols}"

                # Hydrate actual source content from mirror
                source_content = self._read_mirrored_source(hit.get("mirror_path", ""))
                if source_content and chars_used + len(source_content) <= budget:
                    code_text.append(f"{header}\n```\n{source_content}\n```")
                    chars_used += len(source_content)
                else:
                    code_text.append(header)

            context_parts.append("CODE MATCHES (with source):\n" + "\n\n".join(code_text))

        if include_runtime:
            try:
                runtime = build_runtime_context()
                context_parts.append("RUNTIME STATE:\n" + runtime)
            except Exception as exc:
                context_parts.append(f"RUNTIME STATE: unavailable ({exc})")

        # Build tagged context sources for enforcement
        context_sources = {}
        if corpus_hits:
            context_sources["help_corpus"] = "\n\n".join(context_parts[:1]) if context_parts else ""
        if code_hits and len(context_parts) > (1 if corpus_hits else 0):
            idx = 1 if corpus_hits else 0
            context_sources["code_index"] = context_parts[idx] if idx < len(context_parts) else ""
        if include_runtime and "RUNTIME STATE" in (context_parts[-1] if context_parts else ""):
            context_sources["runtime_snapshot"] = context_parts[-1]

        # Query LLM with tagged sources (broker enforces allowed_reads)
        response = self._broker.query(
            role_name=self._role_name,
            prompt=question,
            context_sources=context_sources,
        )

        return {
            "question": question,
            "answer": response or "Help bot is unavailable. Ollama may not be running.",
            "sources": {
                "corpus_hits": len(corpus_hits),
                "code_hits": len(code_hits),
                "runtime_included": include_runtime,
            },
            "model": self._broker.get_role(self._role_name).model if self._broker.get_role(self._role_name) else "unknown",
        }

    def _read_mirrored_source(self, mirror_path: str) -> str:
        """Read actual source content from the code mirror.

        Returns the file content, or empty string if unavailable.
        The mirror is a detached copy — never reads live source directly.
        """
        if not mirror_path:
            return ""
        from pathlib import Path
        p = Path(mirror_path)
        if not p.exists() or not p.is_file():
            return ""
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
            # Cap individual file size to prevent one huge file from starving others
            max_file = 8000
            if len(content) > max_file:
                content = content[:max_file] + f"\n... (truncated at {max_file} chars)"
            return content
        except Exception:
            return ""

    def status(self) -> dict:
        role = self._broker.get_role(self._role_name)
        return {
            "role": role.to_dict() if role else None,
            "corpus": self._corpus.stats(),
            "code_index_path": str(self._code_index.index_path),
        }
