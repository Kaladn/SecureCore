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

    def test_record_screen_capture(self):
        record = self.hid.record_screen_capture(
            grid=[[0, 1], [2, 11]],
            frame_id=7,
            capture_region="full",
            screen_changed=True,
            change_ratio=0.25,
        )
        self.assertEqual(record.record_type, "screen_capture")
        self.assertEqual(record.payload["frame_id"], 7)
        self.assertEqual(record.payload["grid"], [[0, 1], [2, 9]])
        self.assertTrue(record.payload["screen_changed"])
        self.assertEqual(record.payload["grid_rows"], 2)
        self.assertEqual(record.payload["grid_cols"], 2)

    def test_record_camera_frame(self):
        record = self.hid.record_camera_frame(
            face_detected=True,
            attention_on_screen=True,
            attention_direction="center",
            distance_estimate=42.5,
        )
        self.assertEqual(record.record_type, "camera_frame")
        self.assertTrue(record.payload["face_detected"])
        self.assertTrue(record.payload["attention_on_screen"])
        self.assertEqual(record.payload["attention_direction"], "center")

    def test_record_audio_level(self):
        record = self.hid.record_audio_level(
            mic_active=True,
            level_db=-18.5,
            voice_detected=True,
            device_id="mic-1",
        )
        self.assertEqual(record.record_type, "audio_level")
        self.assertTrue(record.payload["mic_active"])
        self.assertTrue(record.payload["voice_detected"])
        self.assertEqual(record.payload["device_id"], "mic-1")

    def test_record_activity_burst(self):
        record = self.hid.record_activity_burst(
            keyboard_events=8,
            mouse_clicks=2,
            movement_detected=True,
            screen_changing=True,
            voice_detected=False,
            foreground_app="SecureCore",
        )
        self.assertEqual(record.record_type, "activity_burst")
        self.assertEqual(record.payload["keyboard_events"], 8)
        self.assertTrue(record.payload["screen_changing"])

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

    def test_attestation_with_visual_audio_signals(self):
        self.hid.record_session_state(session_locked=False, idle_seconds=3.0, foreground_app="console")
        self.hid.record_screen_capture(
            grid=[[1, 2], [3, 4]],
            capture_region="full",
            screen_changed=True,
            change_ratio=0.4,
        )
        self.hid.record_camera_frame(
            face_detected=True,
            attention_on_screen=True,
            attention_direction="center",
        )
        self.hid.record_audio_level(
            mic_active=True,
            level_db=-12.0,
            voice_detected=True,
        )

        att = self.hid.get_recent_attestation(window_seconds=300.0)
        self.assertTrue(att["available"])
        self.assertTrue(att["active_human"])
        self.assertTrue(att["screen_changing"])
        self.assertTrue(att["face_detected"])
        self.assertTrue(att["attention_on_screen"])
        self.assertTrue(att["voice_detected"])
        self.assertEqual(att["attention_direction"], "center")
        self.assertGreater(att["confidence"], 0.6)

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
