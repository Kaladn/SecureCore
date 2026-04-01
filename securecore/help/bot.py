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

from securecore.help.config import load_help_config
from securecore.help.corpus import HelpCorpus
from securecore.help.code_index import CodeMirrorIndex
from securecore.llm.broker import LLMBroker
from securecore.llm.contexts.help_context import build_help_context

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
        context_bundle, metadata = build_help_context(
            question=question,
            corpus=self._corpus,
            code_index=self._code_index,
            include_runtime=include_runtime,
            max_context_chars=self._config["max_context_chars"],
        )

        try:
            response = self._broker.query(
                role_name=self._role_name,
                prompt=question,
                context_bundle=context_bundle,
            )
        except ValueError as exc:
            response = str(exc)

        return {
            "question": question,
            "answer": response or "Help bot is unavailable. Ollama may not be running.",
            "sources": {
                "corpus_hits": metadata["corpus_hits"],
                "code_hits": metadata["code_hits"],
                "runtime_included": metadata["runtime_included"],
            },
            "context_bundle_hash": context_bundle.bundle_hash,
            "model": self._broker.get_role(self._role_name).model if self._broker.get_role(self._role_name) else "unknown",
        }

    def status(self) -> dict:
        role = self._broker.get_role(self._role_name)
        return {
            "role": role.to_dict() if role else None,
            "corpus": self._corpus.stats(),
            "code_index_path": str(self._code_index.index_path),
        }
