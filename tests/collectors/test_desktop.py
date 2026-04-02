import unittest

from securecore.collectors.desktop import DesktopCollector, DesktopSnapshot


class _FakeHIDWriter:
    def __init__(self):
        self.calls = []

    def record_session_state(self, **kwargs):
        self.calls.append(("session", kwargs))
        return {"kind": "session", "payload": kwargs}

    def record_device_state(self, **kwargs):
        self.calls.append(("device", kwargs))
        return {"kind": "device", "payload": kwargs}


class DesktopCollectorTests(unittest.TestCase):
    def test_emit_snapshot_writes_session_then_device_state(self):
        writer = _FakeHIDWriter()
        collector = DesktopCollector(writer)

        records = collector.emit_snapshot(
            DesktopSnapshot(
                session_locked=False,
                idle_seconds=4.5,
                foreground_app="SecureCore",
                camera_active=True,
                mic_active=False,
                usb_event="usb_inserted",
            )
        )

        self.assertEqual([call[0] for call in writer.calls], ["session", "device"])
        self.assertEqual(records[0]["kind"], "session")
        self.assertEqual(records[1]["kind"], "device")
        self.assertEqual(writer.calls[0][1]["foreground_app"], "SecureCore")
        self.assertTrue(writer.calls[1][1]["camera_active"])
        self.assertEqual(writer.calls[1][1]["usb_event"], "usb_inserted")


if __name__ == "__main__":
    unittest.main()
