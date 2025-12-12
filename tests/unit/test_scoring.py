"""
Unit tests for detection confidence scoring.
"""

import unittest

from reactguard.framework_detection.scoring import (
    STRONG_SIGNAL_WEIGHTS,
    SUPPORTING_SIGNAL_WEIGHTS,
    score_confidence,
)


class TestConfidenceScoring(unittest.TestCase):
    def test_empty_signals_returns_zero(self):
        score, level, breakdown = score_confidence({})
        self.assertEqual(score, 0)
        self.assertEqual(level, "low")
        self.assertEqual(breakdown["strong_hits"], [])
        self.assertEqual(breakdown["supporting_hits"], [])
        self.assertEqual(breakdown["router_bonus"], 0)
        self.assertEqual(breakdown["penalties"], [])

    def test_strong_signal_weights_applied(self):
        score, level, breakdown = score_confidence({"rsc_content_type": True})
        self.assertEqual(score, STRONG_SIGNAL_WEIGHTS["rsc_content_type"])
        self.assertIn("rsc_content_type", breakdown["strong_hits"])
        self.assertEqual(level, "low")

    def test_multiple_strong_signals_add_bonus(self):
        signals = {
            "rsc_content_type": True,
            "nextjs_hydration_array": True,
            "rsc_flight_payload": True,
        }
        score, level, breakdown = score_confidence(signals)
        expected = (
            STRONG_SIGNAL_WEIGHTS["rsc_content_type"]
            + STRONG_SIGNAL_WEIGHTS["nextjs_hydration_array"]
            + STRONG_SIGNAL_WEIGHTS["rsc_flight_payload"]
            + 6  # bonus for three strong hits
        )
        self.assertEqual(score, expected)
        self.assertEqual(level, "high")

    def test_mutable_only_penalty(self):
        score, level, breakdown = score_confidence({"header_powered_by_nextjs": True})
        # 6 - 10 = -4, then capped to 50 because no strong signals (stays negative)
        self.assertEqual(score, -4)
        self.assertIn("mutable_signals_only", breakdown["penalties"])
        self.assertEqual(level, "low")

    def test_router_bonus_applies(self):
        signals = {"react_router_manifest": True, "react_router_confidence": "medium"}
        score, level, breakdown = score_confidence(signals)
        expected = STRONG_SIGNAL_WEIGHTS["react_router_manifest"] + 6
        self.assertEqual(score, expected)
        self.assertEqual(breakdown["router_bonus"], 6)
        self.assertEqual(level, "low")

    def test_supporting_only_scores_capped_without_strong(self):
        score, level, breakdown = score_confidence({"react_spa_structure": True})
        self.assertEqual(score, SUPPORTING_SIGNAL_WEIGHTS["react_spa_structure"])
        self.assertEqual(level, "low")
        self.assertEqual(breakdown["penalties"], [])

    def test_score_clamped_to_100(self):
        signals = {
            "rsc_content_type": True,
            "nextjs_hydration_array": True,
            "rsc_flight_payload": True,
            "waku_root": True,
            "server_actions_enabled": True,
        }
        score, level, breakdown = score_confidence(signals)
        self.assertEqual(score, 100)
        self.assertEqual(level, "high")
        self.assertGreaterEqual(len(breakdown["strong_hits"]), 3)

    def test_breakdown_fields_present(self):
        score, level, breakdown = score_confidence({"vite_assets": True})
        self.assertIn("strong_hits", breakdown)
        self.assertIn("supporting_hits", breakdown)
        self.assertIn("router_bonus", breakdown)
        self.assertIn("penalties", breakdown)
        self.assertIsInstance(breakdown["strong_hits"], list)
        self.assertIsInstance(breakdown["supporting_hits"], list)
        self.assertEqual(level, "low")
        self.assertEqual(score, SUPPORTING_SIGNAL_WEIGHTS["vite_assets"] - 10)  # mutable-only penalty


class TestSignalWeightsConsistency(unittest.TestCase):
    def test_strong_signals_have_positive_weights(self):
        for signal, weight in STRONG_SIGNAL_WEIGHTS.items():
            with self.subTest(signal=signal):
                self.assertIsInstance(weight, int)
                self.assertGreater(weight, 0)

    def test_supporting_signals_have_positive_weights(self):
        for signal, weight in SUPPORTING_SIGNAL_WEIGHTS.items():
            with self.subTest(signal=signal):
                self.assertIsInstance(weight, int)
                self.assertGreater(weight, 0)


if __name__ == "__main__":
    unittest.main()
