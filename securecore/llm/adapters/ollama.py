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

    def __init__(self, host: str = "http://127.0.0.1:11434", model: str = "gpt-oss:20b"):
        self._host = host.rstrip("/")
        self._model = model

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
        payload = {
            "model": self._model,
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
            req = urllib.request.Request(f"{self._host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in body.get("models", [])]
                return self._model in models or any(self._model.split(":")[0] in m for m in models)
        except Exception:
            return False

    def model_digest(self) -> str:
        """Get the SHA-256 digest of the loaded model from ollama.

        Returns the digest string, or empty string if unavailable.
        This proves the exact model weights that produced a response.
        """
        try:
            req = urllib.request.Request(f"{self._host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                for m in body.get("models", []):
                    name = m.get("name", "")
                    if name == self._model or self._model.split(":")[0] in name:
                        return m.get("digest", "")
        except Exception:
            pass
        return ""

    def status(self) -> dict:
        return {
            "host": self._host,
            "model": self._model,
            "available": self.is_available(),
            "digest": self.model_digest(),
        }
