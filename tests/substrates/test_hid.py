import shutil
import unittest
import uuid
from pathlib import Path

from securecore.substrates.hid import HIDSubstrate


def _make_repo_temp_dir() -> str:
    root = Path(__file__).resolve().parents[2] / ".test_tmp"
    root.mkdir(exist_ok=True)
    temp_dir = root / f"hid_{uuid.uuid4().hex}"
    temp_dir.mkdir()
    return str(temp_dir)


class HIDSubstrateTests(unittest.TestCase):
    def test_recent_attestation_detects_local_activity(self):
        temp_dir = _make_repo_temp_dir()
        try:
            hid = HIDSubstrate(temp_dir)
            hid.record_session_state(session_locked=False, idle_seconds=4, foreground_app="SecureCore")
            hid.record_keyboard_activity(key_event_count=8, typing_variance=0.23, active_window="SecureCore")
            hid.record_mouse_activity(movement_detected=True, click_count=2, jitter_score=0.11)

            attestation = hid.get_recent_attestation(window_seconds=60)

            self.assertTrue(attestation["available"])
            self.assertTrue(attestation["active_human"])
            self.assertGreater(attestation["confidence"], 0.5)
            self.assertEqual(attestation["foreground_app"], "SecureCore")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_empty_attestation_reports_unavailable(self):
        temp_dir = _make_repo_temp_dir()
        try:
            hid = HIDSubstrate(temp_dir)
            attestation = hid.get_recent_attestation(window_seconds=10)

            self.assertFalse(attestation["available"])
            self.assertFalse(attestation["active_human"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
