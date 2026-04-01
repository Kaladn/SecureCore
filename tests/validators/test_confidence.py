import unittest

from securecore.validators.confidence import ConfidenceSignal, ConfidenceValidator


class ConfidenceValidatorTests(unittest.TestCase):
    def test_weighted_confidence_and_tier(self):
        validator = ConfidenceValidator()
        assessment = validator.assess(
            [
                ConfidenceSignal("containment", 0.9, weight=0.6),
                ConfidenceSignal("cognitive", 0.8, weight=0.4),
            ]
        )

        self.assertAlmostEqual(assessment.score, 0.86, places=2)
        self.assertEqual(assessment.tier, "high")
        self.assertTrue(assessment.actionable)

    def test_missing_signals_do_not_contribute(self):
        validator = ConfidenceValidator()
        assessment = validator.assess(
            [
                ConfidenceSignal("containment", 0.9, weight=0.6),
                ConfidenceSignal("hid", 1.0, weight=0.4, present=False),
            ]
        )

        self.assertAlmostEqual(assessment.score, 0.9, places=2)
        self.assertEqual(len(assessment.contributors), 1)


if __name__ == "__main__":
    unittest.main()
