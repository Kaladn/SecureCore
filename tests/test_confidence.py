"""Tests for validators.confidence - weighted scoring and tier classification."""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securecore.validators.confidence import ConfidenceSignal, ConfidenceValidator, ConfidenceAssessment


class TestConfidenceSignal(unittest.TestCase):
    def test_normalized_score_clamps(self):
        self.assertEqual(ConfidenceSignal("x", -0.5).normalized_score(), 0.0)
        self.assertEqual(ConfidenceSignal("x", 1.5).normalized_score(), 1.0)
        self.assertAlmostEqual(ConfidenceSignal("x", 0.7).normalized_score(), 0.7)

    def test_normalized_weight_clamps(self):
        self.assertEqual(ConfidenceSignal("x", 0.5, weight=-1.0).normalized_weight(), 0.0)
        self.assertAlmostEqual(ConfidenceSignal("x", 0.5, weight=0.4).normalized_weight(), 0.4)


class TestConfidenceValidator(unittest.TestCase):
    def setUp(self):
        self.validator = ConfidenceValidator()

    def test_single_signal(self):
        signals = [ConfidenceSignal("test", 0.8, weight=1.0)]
        result = self.validator.assess(signals)
        self.assertAlmostEqual(result.score, 0.8)
        self.assertTrue(result.actionable)
        self.assertEqual(result.tier, "review")

    def test_weighted_average(self):
        signals = [
            ConfidenceSignal("a", 1.0, weight=0.4),
            ConfidenceSignal("b", 0.0, weight=0.6),
        ]
        result = self.validator.assess(signals)
        self.assertAlmostEqual(result.score, 0.4)

    def test_empty_signals(self):
        result = self.validator.assess([])
        self.assertAlmostEqual(result.score, 0.0)
        self.assertFalse(result.actionable)
        self.assertEqual(result.tier, "reject")

    def test_absent_signal_ignored(self):
        signals = [
            ConfidenceSignal("real", 0.9, weight=1.0),
            ConfidenceSignal("ghost", 0.1, weight=1.0, present=False),
        ]
        result = self.validator.assess(signals)
        self.assertAlmostEqual(result.score, 0.9)
        self.assertEqual(len(result.contributors), 1)

    def test_tier_classification(self):
        self.assertEqual(self.validator.tier_for(0.96), "auto_act")
        self.assertEqual(self.validator.tier_for(0.90), "high")
        self.assertEqual(self.validator.tier_for(0.75), "review")
        self.assertEqual(self.validator.tier_for(0.55), "cautious")
        self.assertEqual(self.validator.tier_for(0.30), "reject")

    def test_three_channel_consensus(self):
        """Simulates the Reaper's 3-channel consensus gate."""
        signals = [
            ConfidenceSignal("containment", 0.9, weight=0.40),
            ConfidenceSignal("cognitive", 0.85, weight=0.35),
            ConfidenceSignal("hid", 0.7, weight=0.25),
        ]
        result = self.validator.assess(signals)
        # (0.9*0.4 + 0.85*0.35 + 0.7*0.25) / (0.4+0.35+0.25) = (0.36+0.2975+0.175)/1.0 = 0.8325
        self.assertAlmostEqual(result.score, 0.8325, places=3)
        self.assertTrue(result.actionable)
        self.assertEqual(len(result.contributors), 3)


if __name__ == "__main__":
    unittest.main()
