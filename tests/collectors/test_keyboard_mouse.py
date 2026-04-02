import unittest

from securecore.collectors.keyboard_mouse import (
    KeyboardActivitySample,
    KeyboardMouseCollector,
    MouseActivitySample,
)


class _FakeHIDWriter:
    def __init__(self):
        self.calls = []

    def record_keyboard_activity(self, **kwargs):
        self.calls.append(("keyboard", kwargs))
        return {"kind": "keyboard", "payload": kwargs}

    def record_mouse_activity(self, **kwargs):
        self.calls.append(("mouse", kwargs))
        return {"kind": "mouse", "payload": kwargs}


class KeyboardMouseCollectorTests(unittest.TestCase):
    def test_emits_keyboard_sample(self):
        writer = _FakeHIDWriter()
        collector = KeyboardMouseCollector(writer)

        result = collector.emit_keyboard(
            KeyboardActivitySample(
                key_event_count=12,
                typing_variance=0.3,
                active_window="SecureCore",
            )
        )

        self.assertEqual(result["kind"], "keyboard")
        self.assertEqual(writer.calls[0][1]["key_event_count"], 12)
        self.assertEqual(writer.calls[0][1]["active_window"], "SecureCore")

    def test_emits_mouse_sample(self):
        writer = _FakeHIDWriter()
        collector = KeyboardMouseCollector(writer)

        result = collector.emit_mouse(
            MouseActivitySample(
                movement_detected=True,
                click_count=4,
                jitter_score=0.2,
            )
        )

        self.assertEqual(result["kind"], "mouse")
        self.assertTrue(writer.calls[0][1]["movement_detected"])
        self.assertEqual(writer.calls[0][1]["click_count"], 4)

    def test_emit_samples_keeps_keyboard_then_mouse_order(self):
        writer = _FakeHIDWriter()
        collector = KeyboardMouseCollector(writer)

        records = collector.emit_samples(
            keyboard=KeyboardActivitySample(key_event_count=5),
            mouse=MouseActivitySample(movement_detected=True),
        )

        self.assertEqual([call[0] for call in writer.calls], ["keyboard", "mouse"])
        self.assertEqual(len(records), 2)


if __name__ == "__main__":
    unittest.main()
