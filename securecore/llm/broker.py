"""LLM Broker — single managed interface for all LLM roles.

Every LLM role gets:
  - a registered caller_id in the permission system
  - explicit allowed_reads (what context it can see)
  - empty allowed_writes (LLMs don't write to substrates by default)
  - empty allowed_controls (LLMs don't control the organism by default)
  - logged prompt/response hashes for audit

Roles:
  help    — answers operator questions, grounded on corpus + code mirror + runtime
  draft   — generates agent drafts, tests, help stubs (writes to draft workspace only)
  analyze — reads mirrored truth, produces advisory findings

One broker, many roles. Each role is a managed citizen.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, UTC
from typing import Optional

from securecore.llm.adapters.ollama import OllamaAdapter

logger = logging.getLogger("llm.broker")


class LLMRole:
    """A managed LLM role with explicit permissions."""

    def __init__(
        self,
        role_name: str,
        caller_id: str,
        model: str,
        system_prompt: str = "",
        allowed_reads: list[str] | None = None,
        max_context_chars: int = 24000,
    ):
        self.role_name = role_name
        self.caller_id = caller_id
        self.model = model
        self.system_prompt = system_prompt
        self.allowed_reads = allowed_reads or []
        self.max_context_chars = max_context_chars
        self.total_queries = 0
        self.total_tokens_est = 0

    def to_dict(self) -> dict:
        return {
            "role_name": self.role_name,
            "caller_id": self.caller_id,
            "model": self.model,
            "allowed_reads": self.allowed_reads,
            "max_context_chars": self.max_context_chars,
            "total_queries": self.total_queries,
            "total_tokens_est": self.total_tokens_est,
        }


class LLMBroker:
    """Central broker for all LLM interactions.

    Manages roles, enforces read permissions, logs interactions.
    """

    def __init__(self, ollama_host: str = "http://127.0.0.1:11434"):
        self._ollama_host = ollama_host
        self._roles: dict[str, LLMRole] = {}
        self._adapters: dict[str, OllamaAdapter] = {}
        self._interaction_log: list[dict] = []
        self._log_max = 500

    def register_role(
        self,
        role_name: str,
        caller_id: str,
        model: str,
        system_prompt: str = "",
        allowed_reads: list[str] | None = None,
        max_context_chars: int = 24000,
    ) -> LLMRole:
        """Register an LLM role. Caller_id should match the permission registry."""
        if role_name in self._roles:
            raise ValueError(f"LLM role already registered: {role_name}")

        role = LLMRole(
            role_name=role_name,
            caller_id=caller_id,
            model=model,
            system_prompt=system_prompt,
            allowed_reads=allowed_reads,
            max_context_chars=max_context_chars,
        )
        self._roles[role_name] = role

        if model not in self._adapters:
            self._adapters[model] = OllamaAdapter(host=self._ollama_host, model=model)

        logger.info("LLM role registered: %s (model=%s, caller=%s)", role_name, model, caller_id)
        return role

    def query(
        self,
        role_name: str,
        prompt: str,
        context: str = "",
        context_sources: dict[str, str] | None = None,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> Optional[str]:
        """Send a query through a registered role.

        context_sources is the preferred way to pass context: a dict of
        {source_label: content}. The broker verifies all source labels
        are in the role's allowed_reads before assembling the prompt.
        Disallowed sources are dropped and logged.

        The legacy context parameter is accepted but bypasses source
        enforcement (for backward compatibility during transition).

        Returns the response text, or None if unavailable.
        """
        role = self._roles.get(role_name)
        if not role:
            logger.warning("LLM query denied: unknown role %s", role_name)
            return None

        adapter = self._adapters.get(role.model)
        if not adapter:
            logger.warning("LLM query denied: no adapter for model %s", role.model)
            return None

        # Build context from tagged sources (enforced) or raw string (legacy)
        if context_sources:
            allowed = set(role.allowed_reads) if role.allowed_reads else set()
            filtered_parts = []
            for source, content in context_sources.items():
                if allowed and source not in allowed:
                    logger.warning(
                        "LLM context source blocked: role=%s source=%s not in allowed_reads",
                        role_name, source,
                    )
                    continue
                filtered_parts.append(f"[{source}]\n{content}")
            context = "\n\n---\n\n".join(filtered_parts)

        full_prompt = prompt
        if context:
            truncated = context[:role.max_context_chars]
            full_prompt = f"CONTEXT:\n{truncated}\n\nQUESTION:\n{prompt}"

        # Query
        response = adapter.generate(
            prompt=full_prompt,
            system=role.system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        # Log interaction (hashes only, not full content)
        role.total_queries += 1
        if response:
            role.total_tokens_est += len(response) // 4

        self._log_interaction(role, prompt, response)

        return response

    def _log_interaction(self, role: LLMRole, prompt: str, response: Optional[str]) -> None:
        """Log prompt/response hashes for audit trail."""
        entry = {
            "role": role.role_name,
            "caller_id": role.caller_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "prompt_hash": hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16],
            "response_hash": hashlib.sha256((response or "").encode("utf-8")).hexdigest()[:16],
            "prompt_len": len(prompt),
            "response_len": len(response) if response else 0,
            "success": response is not None,
        }
        if len(self._interaction_log) >= self._log_max:
            self._interaction_log = self._interaction_log[-250:]
        self._interaction_log.append(entry)

    def get_role(self, role_name: str) -> Optional[LLMRole]:
        return self._roles.get(role_name)

    def list_roles(self) -> list[dict]:
        return [role.to_dict() for role in self._roles.values()]

    def recent_interactions(self, limit: int = 20) -> list[dict]:
        return self._interaction_log[-limit:]

    def status(self) -> dict:
        adapter_status = {}
        for model, adapter in self._adapters.items():
            adapter_status[model] = adapter.status()
        return {
            "roles": self.list_roles(),
            "adapters": adapter_status,
            "total_interactions": len(self._interaction_log),
        }
