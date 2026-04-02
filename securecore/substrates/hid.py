"""HID Substrate - human interface detection signals.

This substrate records human-presence indicators without storing invasive
raw content. It is meant to answer one narrow question:

    "Was there recent, local hardware activity consistent with a human?"

It does not store keystroke contents, raw microphone audio, or camera video.
Visual signals are reduced to quantized metadata (ARC-style grids and
attention state), and audio is reduced to level/presence metadata only.
"""

from __future__ import annotations

import time
from datetime import datetime, UTC
from typing import Optional

from securecore.substrates.base import Substrate


class HIDSubstrate(Substrate):
    """Human input device activity substrate."""

    name = "hid"
    _RECORD_TYPES = {
        "keyboard_activity",
        "mouse_activity",
        "session_state",
        "device_state",
        "screen_capture",
        "camera_frame",
        "audio_level",
        "activity_burst",
    }

    def validate_payload(self, record_type: str, payload: dict) -> None:
        if record_type in self._RECORD_TYPES:
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

    def record_screen_capture(
        self,
        grid: list[list[int]],
        frame_id: int = 0,
        capture_region: str = "",
        screen_changed: bool = False,
        change_ratio: float = 0.0,
        operator: str = "local",
        cell_id: str = "",
    ):
        normalized_grid = [
            [max(0, min(9, int(value))) for value in row]
            for row in grid
        ]
        return self.append(
            record_type="screen_capture",
            payload={
                "frame_id": max(0, int(frame_id)),
                "grid": normalized_grid,
                "capture_region": capture_region,
                "screen_changed": bool(screen_changed),
                "change_ratio": max(0.0, float(change_ratio)),
                "grid_rows": len(normalized_grid),
                "grid_cols": len(normalized_grid[0]) if normalized_grid else 0,
                "operator": operator,
                "epoch_ns": time.time_ns(),
            },
            cell_id=cell_id,
        )

    def record_camera_frame(
        self,
        face_detected: bool,
        attention_on_screen: bool,
        attention_direction: str = "",
        distance_estimate: float = 0.0,
        camera_active: bool = True,
        operator: str = "local",
        cell_id: str = "",
    ):
        return self.append(
            record_type="camera_frame",
            payload={
                "face_detected": bool(face_detected),
                "attention_on_screen": bool(attention_on_screen),
                "attention_direction": attention_direction,
                "distance_estimate": max(0.0, float(distance_estimate)),
                "camera_active": bool(camera_active),
                "operator": operator,
                "epoch_ns": time.time_ns(),
            },
            cell_id=cell_id,
        )

    def record_audio_level(
        self,
        mic_active: bool,
        level_db: float,
        voice_detected: bool = False,
        device_id: str = "",
        operator: str = "local",
        cell_id: str = "",
    ):
        return self.append(
            record_type="audio_level",
            payload={
                "mic_active": bool(mic_active),
                "level_db": float(level_db),
                "voice_detected": bool(voice_detected),
                "device_id": device_id,
                "operator": operator,
                "epoch_ns": time.time_ns(),
            },
            cell_id=cell_id,
        )

    def record_activity_burst(
        self,
        keyboard_events: int = 0,
        mouse_clicks: int = 0,
        movement_detected: bool = False,
        screen_changing: bool = False,
        voice_detected: bool = False,
        foreground_app: str = "",
        operator: str = "local",
        cell_id: str = "",
    ):
        return self.append(
            record_type="activity_burst",
            payload={
                "keyboard_events": max(0, int(keyboard_events)),
                "mouse_clicks": max(0, int(mouse_clicks)),
                "movement_detected": bool(movement_detected),
                "screen_changing": bool(screen_changing),
                "voice_detected": bool(voice_detected),
                "foreground_app": foreground_app,
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
        screen_changing = False
        face_detected = False
        attention_on_screen = False
        voice_detected = False
        last_attention_direction = ""
        last_capture_region = ""

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
            elif record.record_type == "screen_capture":
                screen_changing = screen_changing or payload.get("screen_changed", False)
                screen_changing = screen_changing or payload.get("change_ratio", 0.0) > 0.01
                last_capture_region = payload.get("capture_region", last_capture_region)
            elif record.record_type == "camera_frame":
                face_detected = face_detected or payload.get("face_detected", False)
                attention_on_screen = attention_on_screen or payload.get("attention_on_screen", False)
                camera_active = camera_active or payload.get("camera_active", False)
                last_attention_direction = payload.get("attention_direction", last_attention_direction)
            elif record.record_type == "audio_level":
                mic_active = mic_active or payload.get("mic_active", False)
                voice_detected = voice_detected or payload.get("voice_detected", False)
            elif record.record_type == "activity_burst":
                keyboard_events += payload.get("keyboard_events", 0)
                mouse_clicks += payload.get("mouse_clicks", 0)
                movement_detected = movement_detected or payload.get("movement_detected", False)
                screen_changing = screen_changing or payload.get("screen_changing", False)
                voice_detected = voice_detected or payload.get("voice_detected", False)
                foreground_app = payload.get("foreground_app", foreground_app)

        recent_activity = (
            keyboard_events > 0
            or mouse_clicks > 0
            or movement_detected
            or face_detected
            or attention_on_screen
            or voice_detected
        )
        session_clear = not session_locked and (idle_seconds is None or idle_seconds <= window_seconds)
        active_human = recent_activity and session_clear

        confidence = 0.0
        if active_human:
            confidence = 0.45
            if keyboard_events > 0:
                confidence += 0.15
            if mouse_clicks > 0 or movement_detected:
                confidence += 0.10
            if foreground_app:
                confidence += 0.10
            if face_detected:
                confidence += 0.10
            if attention_on_screen:
                confidence += 0.05
            if voice_detected:
                confidence += 0.05
            if screen_changing:
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
            "screen_changing": screen_changing,
            "face_detected": face_detected,
            "attention_on_screen": attention_on_screen,
            "attention_direction": last_attention_direction,
            "voice_detected": voice_detected,
            "camera_active": camera_active,
            "mic_active": mic_active,
            "capture_region": last_capture_region,
            "checked_at": datetime.now(UTC).isoformat(),
        }
