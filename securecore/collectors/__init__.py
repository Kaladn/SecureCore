"""Collector adapters for SecureCore sensor inputs.

Collectors gather local sensor metadata and write structured records into
substrates through permission-gated writers. They do not interpret signals.
"""

from securecore.collectors.desktop import DesktopCollector, DesktopSnapshot
from securecore.collectors.keyboard_mouse import (
    KeyboardActivitySample,
    KeyboardMouseCollector,
    MouseActivitySample,
)
from securecore.collectors.screen import ScreenCaptureSample, ScreenCollector

__all__ = [
    "DesktopCollector",
    "DesktopSnapshot",
    "KeyboardActivitySample",
    "KeyboardMouseCollector",
    "MouseActivitySample",
    "ScreenCaptureSample",
    "ScreenCollector",
]
