"""HID Substrate - human input device activity signals.

This substrate records human-presence indicators without storing invasive
raw content. It is meant to answer one narrow question:

    "Was there recent, local hardware activity consistent with a human?"

It does not store keystroke contents, screen contents, microphone audio,
or camera video. Only activity metadata and device state changes.
"""

from __future__ import annotations

import time
from datetime import datetime, UTC
from typing import Optional

from securecore.substrates.base import Substrate


class HIDSubstrate(Substrate):
    """Human input device activity substrate."""

    name = "hid"

    def validate_payload(self, record_type: str, payload: dict) -> None:
        if record_type in {"keyboard_activity", "mouse_activity", "session_state", "device_state"}:
            if "epoch_ns" not in payload:
                raise ValueError(f"{record_type} requires epoch_ns")

    def record_keyboard_activity(
        self,
        key_event_count: int,
        typing_variance: float = 0.0,
        active_window: str = "",
        operator: str = "local",
        cell_id: str = "",
    ):
        return self.append(
            record_type="keyboard_activity",
            payload={
                "key_event_count": max(0, int(key_event_count)),
                "typing_variance": max(0.0, float(typing_variance)),
                "active_window": active_window,
                "operator": operator,
                "epoch_ns": time.time_ns(),
            },
            cell_id=cell_id,
        )

    def record_mouse_activity(
        self,
        movement_detected: bool,
        click_count: int = 0,
        jitter_score: float = 0.0,
        operator: str = "local",
        cell_id: str = "",
    ):
        return self.append(
            record_type="mouse_activity",
            payload={
                "movement_detected": bool(movement_detected),
                "click_count": max(0, int(click_count)),
                "jitter_score": max(0.0, float(jitter_score)),
                "operator": operator,
                "epoch_ns": time.time_ns(),
            },
            cell_id=cell_id,
        )

    def record_session_state(
        self,
        session_locked: bool,
        idle_seconds: float,
        foreground_app: str = "",
        operator: str = "local",
        cell_id: str = "",
    ):
        return self.append(
            record_type="session_state",
            payload={
                "session_locked": bool(session_locked),
                "idle_seconds": max(0.0, float(idle_seconds)),
                "foreground_app": foreground_app,
                "operator": operator,
                "epoch_ns": time.time_ns(),
            },
            cell_id=cell_id,
        )

    def record_device_state(
        self,
        camera_active: bool = False,
        mic_active: bool = False,
        usb_event: str = "",
        operator: str = "local",
        cell_id: str = "",
    ):
        return self.append(
            record_type="device_state",
            payload={
                "camera_active": bool(camera_active),
                "mic_active": bool(mic_active),
                "usb_event": usb_event,
                "operator": operator,
                "epoch_ns": time.time_ns(),
            },
            cell_id=cell_id,
        )

    def get_recent_attestation(self, window_seconds: float = 120.0) -> dict:
        """Return a best-effort human activity attestation for recent local use."""
        cutoff_ns = time.time_ns() - int(window_seconds * 1_000_000_000)
        recent = []
        for record in self.stream():
            if record.payload.get("epoch_ns", 0) >= cutoff_ns:
                recent.append(record)

        if not recent:
            return {
                "available": False,
                "active_human": False,
                "confidence": 0.0,
                "window_seconds": window_seconds,
                "records_considered": 0,
            }

        keyboard_events = 0
        mouse_clicks = 0
        movement_detected = False
        session_locked = False
        idle_seconds = None
        foreground_app = ""
        camera_active = False
        mic_active = False

        for record in recent:
            payload = record.payload
            if record.record_type == "keyboard_activity":
                keyboard_events += payload.get("key_event_count", 0)
            elif record.record_type == "mouse_activity":
                mouse_clicks += payload.get("click_count", 0)
                movement_detected = movement_detected or payload.get("movement_detected", False)
            elif record.record_type == "session_state":
                session_locked = payload.get("session_locked", session_locked)
                idle_seconds = payload.get("idle_seconds", idle_seconds)
                foreground_app = payload.get("foreground_app", foreground_app)
            elif record.record_type == "device_state":
                camera_active = camera_active or payload.get("camera_active", False)
                mic_active = mic_active or payload.get("mic_active", False)

        recent_activity = keyboard_events > 0 or mouse_clicks > 0 or movement_detected
        session_clear = not session_locked and (idle_seconds is None or idle_seconds <= window_seconds)
        active_human = recent_activity and session_clear

        confidence = 0.0
        if active_human:
            confidence = 0.55
            if keyboard_events > 0:
                confidence += 0.2
            if mouse_clicks > 0 or movement_detected:
                confidence += 0.15
            if foreground_app:
                confidence += 0.05
            if camera_active or mic_active:
                confidence += 0.05

        return {
            "available": True,
            "active_human": active_human,
            "confidence": min(1.0, confidence),
            "window_seconds": window_seconds,
            "records_considered": len(recent),
            "keyboard_events": keyboard_events,
            "mouse_clicks": mouse_clicks,
            "movement_detected": movement_detected,
            "session_locked": session_locked,
            "idle_seconds": idle_seconds,
            "foreground_app": foreground_app,
            "camera_active": camera_active,
            "mic_active": mic_active,
            "checked_at": datetime.now(UTC).isoformat(),
        }
