"""Tests for substrates.hid - HID substrate and attestation."""

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securecore.substrates.hid import HIDSubstrate


class TestHIDSubstrate(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.hid = HIDSubstrate(self.tmpdir)

    def test_record_keyboard_activity(self):
        record = self.hid.record_keyboard_activity(key_event_count=42, typing_variance=0.15)
        self.assertEqual(record.record_type, "keyboard_activity")
        self.assertEqual(record.payload["key_event_count"], 42)
        self.assertAlmostEqual(record.payload["typing_variance"], 0.15)
        self.assertIn("epoch_ns", record.payload)

    def test_record_mouse_activity(self):
        record = self.hid.record_mouse_activity(movement_detected=True, click_count=5, jitter_score=0.3)
        self.assertEqual(record.record_type, "mouse_activity")
        self.assertTrue(record.payload["movement_detected"])
        self.assertEqual(record.payload["click_count"], 5)

    def test_record_session_state(self):
        record = self.hid.record_session_state(session_locked=False, idle_seconds=10.5, foreground_app="vim")
        self.assertEqual(record.record_type, "session_state")
        self.assertFalse(record.payload["session_locked"])
        self.assertEqual(record.payload["foreground_app"], "vim")

    def test_record_device_state(self):
        record = self.hid.record_device_state(camera_active=True, mic_active=False)
        self.assertEqual(record.record_type, "device_state")
        self.assertTrue(record.payload["camera_active"])
        self.assertFalse(record.payload["mic_active"])

    def test_validation_requires_epoch_ns(self):
        with self.assertRaises(ValueError):
            self.hid.validate_payload("keyboard_activity", {"key_event_count": 1})

    def test_negative_values_clamped(self):
        record = self.hid.record_keyboard_activity(key_event_count=-5, typing_variance=-1.0)
        self.assertEqual(record.payload["key_event_count"], 0)
        self.assertAlmostEqual(record.payload["typing_variance"], 0.0)

    def test_attestation_no_records(self):
        att = self.hid.get_recent_attestation()
        self.assertFalse(att["available"])
        self.assertFalse(att["active_human"])
        self.assertAlmostEqual(att["confidence"], 0.0)

    def test_attestation_with_activity(self):
        self.hid.record_keyboard_activity(key_event_count=20, typing_variance=0.2)
        self.hid.record_mouse_activity(movement_detected=True, click_count=3)
        self.hid.record_session_state(session_locked=False, idle_seconds=5.0, foreground_app="terminal")

        att = self.hid.get_recent_attestation(window_seconds=300.0)
        self.assertTrue(att["available"])
        self.assertTrue(att["active_human"])
        self.assertGreater(att["confidence"], 0.7)
        self.assertEqual(att["keyboard_events"], 20)
        self.assertEqual(att["mouse_clicks"], 3)
        self.assertTrue(att["movement_detected"])

    def test_attestation_locked_session(self):
        self.hid.record_keyboard_activity(key_event_count=10)
        self.hid.record_session_state(session_locked=True, idle_seconds=600.0)

        att = self.hid.get_recent_attestation(window_seconds=300.0)
        self.assertTrue(att["available"])
        self.assertFalse(att["active_human"])
        self.assertAlmostEqual(att["confidence"], 0.0)

    def test_chain_integrity(self):
        self.hid.record_keyboard_activity(key_event_count=1)
        self.hid.record_mouse_activity(movement_detected=True)
        self.hid.record_device_state(camera_active=True)

        result = self.hid.verify_chain()
        self.assertTrue(result["intact"])
        self.assertEqual(result["total_records"], 3)


if __name__ == "__main__":
    unittest.main()
