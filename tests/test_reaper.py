"""Tests for control.reaper - consensus gate and cognitive cache."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securecore.substrates.agent_decisions import AgentDecisionsSubstrate
from securecore.substrates.operator import OperatorSubstrate
from securecore.substrates.hid import HIDSubstrate
from securecore.control.reaper import Reaper, ReaperPolicy


class TestReaperConsensus(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.decisions = AgentDecisionsSubstrate(os.path.join(self.tmpdir, "decisions"))
        self.operator = OperatorSubstrate(os.path.join(self.tmpdir, "operator"))
        self.hid = HIDSubstrate(os.path.join(self.tmpdir, "hid"))
        self.reaper = Reaper(
            decisions_substrate=self.decisions,
            operator_writer=self.operator,
            hid_substrate=self.hid,
            policy=ReaperPolicy(min_confidence=0.7, dry_run=True),
        )

    def test_consensus_three_channels(self):
        """Consensus gate should use all three channels."""
        # Populate cognitive cache
        self.reaper._cognitive_cache["cell_abc"] = {
            "confidence": 0.85,
            "threat_score": 0.8,
            "human_likelihood": 0.2,
            "consensus_strength": 0.9,
        }

        # Add HID activity
        self.hid.record_keyboard_activity(key_event_count=10)
        self.hid.record_session_state(session_locked=False, idle_seconds=5.0)

        consensus = self.reaper._build_consensus(
            "cell_abc", {"ip": "10.0.0.5", "escalation_level": 3}, 0.9
        )

        self.assertIn("score", consensus)
        self.assertIn("tier", consensus)
        self.assertIn("actionable", consensus)
        self.assertIn("contributors", consensus)
        # Should have 3 contributors: containment, cognitive, hid
        self.assertEqual(len(consensus["contributors"]), 3)
        contributor_names = {c["name"] for c in consensus["contributors"]}
        self.assertEqual(contributor_names, {"containment", "cognitive", "hid"})

    def test_consensus_without_cognitive(self):
        """Without cognitive data, should still work with 2 channels."""
        consensus = self.reaper._build_consensus(
            "cell_xyz", {"ip": "10.0.0.5", "escalation_level": 3}, 0.9
        )
        contributor_names = {c["name"] for c in consensus["contributors"]}
        self.assertEqual(contributor_names, {"containment", "hid"})

    def test_cognitive_cache_populated_by_on_decision(self):
        """_on_decision should cache cognitive assessments."""
        self.reaper._running = True
        self.reaper._paused = False

        # Simulate a cognitive agent emitting an assessment
        self.decisions.record_decision(
            agent_name="cognitive",
            decision_type="cognitive_assessment",
            confidence=0.85,
            cell_id="cell_test",
            context={"threat_score": 0.75, "human_likelihood": 0.3},
        )

        # The subscription fires synchronously in append, so cache should be populated
        self.reaper.start()  # subscribe
        # Re-emit after subscription
        self.decisions.record_decision(
            agent_name="cognitive",
            decision_type="cognitive_assessment",
            confidence=0.9,
            cell_id="cell_test2",
            context={"threat_score": 0.8, "human_likelihood": 0.2},
        )

        self.assertIn("cell_test2", self.reaper._cognitive_cache)
        cached = self.reaper._cognitive_cache["cell_test2"]
        self.assertAlmostEqual(cached["threat_score"], 0.8)
        self.reaper.stop()

    def test_low_confidence_not_actionable(self):
        """Consensus below min_confidence should not be actionable."""
        consensus = self.reaper._build_consensus(
            "cell_low", {"ip": "10.0.0.5", "escalation_level": 1}, 0.3
        )
        self.assertFalse(consensus["actionable"])

    def test_consensus_weights_sum_to_one(self):
        """Weights in _build_consensus should sum to 1.0."""
        # containment=0.40, cognitive=0.35, hid=0.25 → 1.0
        self.reaper._cognitive_cache["cell_w"] = {"confidence": 0.5, "threat_score": 0.5}
        consensus = self.reaper._build_consensus("cell_w", {"ip": "1.2.3.4"}, 0.8)
        total = sum(c["weight"] for c in consensus["contributors"])
        self.assertAlmostEqual(total, 1.0)

    def test_hid_inversion_logic(self):
        """High human confidence should LOWER the HID threat signal."""
        # Active human at keyboard
        self.hid.record_keyboard_activity(key_event_count=50)
        self.hid.record_mouse_activity(movement_detected=True, click_count=10)
        self.hid.record_session_state(session_locked=False, idle_seconds=2.0, foreground_app="code")

        consensus = self.reaper._build_consensus("cell_h", {"ip": "1.2.3.4"}, 0.9)
        hid_contrib = next(c for c in consensus["contributors"] if c["name"] == "hid")
        # Human active → high HID confidence → inverted → LOW threat signal
        self.assertLess(hid_contrib["score"], 0.5)


if __name__ == "__main__":
    unittest.main()
