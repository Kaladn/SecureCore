"""Mode normalization for the SecureCore chat control center."""

from __future__ import annotations

from securecore.chat.models import DEFAULT_MODE, VALID_MODES, normalize_mode


class ChatRouter:
    """Small mode router for the three control-center modes."""

    def normalize_mode(self, mode: str | None) -> str:
        return normalize_mode(mode)

    def supported_modes(self) -> list[str]:
        return sorted(VALID_MODES)

    def default_mode(self) -> str:
        return DEFAULT_MODE
