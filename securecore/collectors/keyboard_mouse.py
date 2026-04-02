"""Keyboard and mouse collector adapters for HID."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class KeyboardActivitySample:
    key_event_count: int
    typing_variance: float = 0.0
    active_window: str = ""
    operator: str = "local"
    cell_id: str = ""


@dataclass
class MouseActivitySample:
    movement_detected: bool
    click_count: int = 0
    jitter_score: float = 0.0
    operator: str = "local"
    cell_id: str = ""


class KeyboardMouseCollector:
    """Adapter that turns keyboard/mouse samples into HID records."""

    def __init__(self, hid_writer):
        self._hid_writer = hid_writer

    def emit_keyboard(self, sample: KeyboardActivitySample):
        return self._hid_writer.record_keyboard_activity(
            key_event_count=sample.key_event_count,
            typing_variance=sample.typing_variance,
            active_window=sample.active_window,
            operator=sample.operator,
            cell_id=sample.cell_id,
        )

    def emit_mouse(self, sample: MouseActivitySample):
        return self._hid_writer.record_mouse_activity(
            movement_detected=sample.movement_detected,
            click_count=sample.click_count,
            jitter_score=sample.jitter_score,
            operator=sample.operator,
            cell_id=sample.cell_id,
        )

    def emit_samples(
        self,
        keyboard: KeyboardActivitySample | None = None,
        mouse: MouseActivitySample | None = None,
    ) -> list:
        records = []
        if keyboard is not None:
            records.append(self.emit_keyboard(keyboard))
        if mouse is not None:
            records.append(self.emit_mouse(mouse))
        return records
