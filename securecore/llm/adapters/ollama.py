"""Ollama adapter for local LLM inference.

Talks to ollama at http://127.0.0.1:11434 by default.
No external network access. Local only.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

logger = logging.getLogger("llm.ollama")


class OllamaAdapter:
    """Minimal ollama HTTP adapter using only stdlib."""

    def __init__(self, host: str = "http://127.0.0.1:11434", model: str = "auto"):
        self._host = host.rstrip("/")
        self._model = (model or "auto").strip() or "auto"

    @property
    def model(self) -> str:
        return self._model

    def generate(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
        max_tokens: int = 2048,
        timeout: float = 60.0,
    ) -> Optional[str]:
        """Generate a response from the local model.

        Returns the response text, or None on failure.
        """
        resolved_model = self._resolve_model_name()
        if not resolved_model:
            logger.warning("ollama has no local model available")
            return None

        payload = {
            "model": resolved_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if system:
            payload["system"] = system

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self._host}/api/generate",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body.get("response", "")
        except urllib.error.URLError as exc:
            logger.warning("ollama unreachable: %s", exc)
            return None
        except Exception as exc:
            logger.error("ollama generate failed: %s", exc)
            return None

    def is_available(self) -> bool:
        """Check if ollama is reachable and the model is loaded."""
        try:
            models = self._fetch_models()
            if not models:
                return False
            if self._model == "auto":
                return True
            return any(self._model_matches(m.get("name", "")) for m in models)
        except Exception:
            return False

    def model_digest(self) -> str:
        """Get the SHA-256 digest of the loaded model from ollama.

        Returns the digest string, or empty string if unavailable.
        This proves the exact model weights that produced a response.
        """
        try:
            models = self._fetch_models()
            resolved_model = self._resolve_model_name(models=models)
            if not resolved_model:
                return ""
            for model in models:
                name = model.get("name", "")
                if name == resolved_model:
                    return model.get("digest", "")
            if self._model != "auto":
                for model in models:
                    name = model.get("name", "")
                    if self._model_matches(name):
                        return model.get("digest", "")
        except Exception:
            pass
        return ""

    def status(self) -> dict:
        models = self._fetch_models()
        return {
            "host": self._host,
            "model": self._model,
            "resolved_model": self._resolve_model_name(models=models),
            "available": bool(models) if self._model == "auto" else any(
                self._model_matches(model.get("name", "")) for model in models
            ),
            "digest": self.model_digest(),
        }

    def _fetch_models(self) -> list[dict]:
        req = urllib.request.Request(f"{self._host}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return list(body.get("models", []))

    def _resolve_model_name(self, *, models: list[dict] | None = None) -> str:
        if self._model != "auto":
            return self._model

        models = models if models is not None else self._fetch_models()
        for model in models:
            name = str(model.get("name", "")).strip()
            if name:
                return name
        return ""

    def _model_matches(self, candidate: str) -> bool:
        if candidate == self._model:
            return True
        if self._model == "auto":
            return bool(candidate)
        configured_base = self._model.split(":")[0]
        candidate_base = candidate.split(":")[0]
        return configured_base == candidate_base
