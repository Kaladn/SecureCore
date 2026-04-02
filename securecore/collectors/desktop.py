"""Desktop state collector adapters for HID."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DesktopSnapshot:
    session_locked: bool
    idle_seconds: float
    foreground_app: str = ""
    camera_active: bool = False
    mic_active: bool = False
    usb_event: str = ""
    operator: str = "local"
    cell_id: str = ""


class DesktopCollector:
    """Adapter that turns desktop state snapshots into HID records."""

    def __init__(self, hid_writer):
        self._hid_writer = hid_writer

    def emit_session_state(self, snapshot: DesktopSnapshot):
        return self._hid_writer.record_session_state(
            session_locked=snapshot.session_locked,
            idle_seconds=snapshot.idle_seconds,
            foreground_app=snapshot.foreground_app,
            operator=snapshot.operator,
            cell_id=snapshot.cell_id,
        )

    def emit_device_state(self, snapshot: DesktopSnapshot):
        return self._hid_writer.record_device_state(
            camera_active=snapshot.camera_active,
            mic_active=snapshot.mic_active,
            usb_event=snapshot.usb_event,
            operator=snapshot.operator,
            cell_id=snapshot.cell_id,
        )

    def emit_snapshot(self, snapshot: DesktopSnapshot) -> list:
        return [
            self.emit_session_state(snapshot),
            self.emit_device_state(snapshot),
        ]
