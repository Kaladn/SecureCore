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
import logging
from datetime import datetime, UTC
from typing import Optional

from securecore.llm.adapters.ollama import OllamaAdapter
from securecore.llm.contexts.types import ContextBundle

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
        self.sequence = 0

    def to_dict(self) -> dict:
        return {
            "role_name": self.role_name,
            "caller_id": self.caller_id,
            "model": self.model,
            "allowed_reads": self.allowed_reads,
            "max_context_chars": self.max_context_chars,
            "total_queries": self.total_queries,
            "total_tokens_est": self.total_tokens_est,
            "sequence": self.sequence,
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
        caller_entry,
        model: str,
        system_prompt: str = "",
        max_context_chars: int = 24000,
    ) -> LLMRole:
        """Register an LLM role from a registry-backed caller entry."""
        if role_name in self._roles:
            raise ValueError(f"LLM role already registered: {role_name}")

        entry_caller_id = getattr(caller_entry, "caller_id", None)
        entry_allowed_reads = getattr(caller_entry, "allowed_read", None)
        if isinstance(caller_entry, dict):
            entry_caller_id = caller_entry.get("caller_id")
            entry_allowed_reads = caller_entry.get("allowed_read", [])
        if not entry_caller_id:
            raise ValueError("LLM role registration requires a registry-backed caller entry")

        role = LLMRole(
            role_name=role_name,
            caller_id=entry_caller_id,
            model=model,
            system_prompt=system_prompt,
            allowed_reads=list(entry_allowed_reads or []),
            max_context_chars=max_context_chars,
        )
        self._roles[role_name] = role

        if model not in self._adapters:
            self._adapters[model] = OllamaAdapter(host=self._ollama_host, model=model)

        logger.info("LLM role registered: %s (model=%s, caller=%s)", role_name, model, entry_caller_id)
        return role

    def query(
        self,
        role_name: str,
        prompt: str,
        context_bundle: ContextBundle,
        temperature: float = 0.0,
        max_tokens: int = 2048,
    ) -> Optional[str]:
        """Send a query through a registered role.

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

        allowed = set(role.allowed_reads) if role.allowed_reads else set()
        context_parts = []
        source_labels = []
        for block in context_bundle.blocks:
            if allowed and block.source_label not in allowed:
                logger.warning(
                    "LLM context source blocked: role=%s source=%s not in allowed_reads",
                    role_name, block.source_label,
                )
                continue
            context_parts.append(f"[{block.source_label}]\n{block.content}")
            source_labels.append(block.source_label)

        context = "\n\n---\n\n".join(context_parts)
        context_chars = sum(len(part) for part in context_parts)
        if context_chars > role.max_context_chars:
            raise ValueError(
                f"context bundle exceeds max_context_chars for role {role_name}: "
                f"{context_chars} > {role.max_context_chars}"
            )

        full_prompt = prompt
        if context:
            full_prompt = f"CONTEXT:\n{context}\n\nQUESTION:\n{prompt}"

        # Query
        response = adapter.generate(
            prompt=full_prompt,
            system=role.system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        # Log interaction (hashes only, not full content)
        role.sequence += 1
        role.total_queries += 1
        if response:
            role.total_tokens_est += len(response) // 4

        self._log_interaction(role, prompt, response, context_bundle, source_labels)

        return response

    def _log_interaction(
        self,
        role: LLMRole,
        prompt: str,
        response: Optional[str],
        context_bundle: ContextBundle,
        source_labels: list[str],
    ) -> None:
        """Log prompt/response hashes for audit trail."""
        entry = {
            "role": role.role_name,
            "caller_id": role.caller_id,
            "sequence": role.sequence,
            "timestamp": datetime.now(UTC).isoformat(),
            "prompt_hash": hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16],
            "context_bundle_hash": context_bundle.bundle_hash[:16],
            "context_total_chars": context_bundle.total_chars,
            "source_labels": list(source_labels),
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
