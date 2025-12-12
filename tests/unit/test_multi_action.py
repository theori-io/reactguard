#!/usr/bin/env python3
import unittest

from reactguard.models.poc import PocStatus
from reactguard.vulnerability_detection.interpreters import analyze_multi_action_results
from reactguard.vulnerability_detection.journal import PocJournal, journal_context


class TestMultiActionInterpreter(unittest.TestCase):
    def test_control_diverges_proto_digest_marks_vulnerable(self):
        """When control succeeds (200) but proto fails, this is deterministic divergent behavior - VULNERABLE."""
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"deadbeef"}',
                "headers": {"content-type": "text/x-component"},
            },
            {
                "action_id": "40bbbb",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"deadbeef"}',
                "headers": {"content-type": "text/x-component"},
            },
        ]
        control_results = [
            {
                "action_id": "40aaaa",
                "status_code": 200,
                "body_snippet": "ok",
                "headers": {"content-type": "text/x-component"},
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa", "40bbbb"],
            is_rsc_framework=True,
            control_results=control_results,
            react_major=19,
        )

        self.assertEqual(result["status"], PocStatus.VULNERABLE)
        self.assertIn("control succeeded", result["details"]["reason"].lower())

    def test_different_digests_mark_likely_not_vulnerable(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"deadbeef"}',
                "headers": {"content-type": "text/x-component"},
            },
            {
                "action_id": "40bbbb",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"cafebabe"}',
                "headers": {"content-type": "text/x-component"},
            },
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa", "40bbbb"],
            is_rsc_framework=True,
            react_major=19,
        )

        self.assertEqual(result["status"], PocStatus.LIKELY_NOT_VULNERABLE)
        self.assertIn("distinct error digests", result["details"]["reason"].lower())

    def test_action_validation_returns_likely_not_vulnerable(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 404,
                "body_snippet": "Action not found",
                "headers": {"content-type": "text/html"},
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa"],
            is_rsc_framework=True,
        )

        self.assertEqual(result["status"], PocStatus.LIKELY_NOT_VULNERABLE)
        self.assertIn("action validation", result["details"]["reason"].lower())

    def test_prototype_error_pattern_marks_likely_vulnerable(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 400,
                "body_snippet": "Cannot read properties of undefined (reading 'workers')",
                "headers": {"content-type": "text/plain"},
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa"],
            is_rsc_framework=True,
            react_major=19,
        )

        self.assertEqual(result["status"], PocStatus.INCONCLUSIVE)
        self.assertIn("only one probe result", result["details"]["reason"].lower())

    def test_uses_ambient_journal_when_none_provided(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 404,
                "body_snippet": "Action not found",
                "headers": {"content-type": "text/html"},
            }
        ]

        ambient = PocJournal()
        with journal_context(ambient):
            result = analyze_multi_action_results(
                probe_results,
                action_ids=["40aaaa"],
                is_rsc_framework=True,
            )

        self.assertGreater(len(ambient.entries), 0)
        self.assertEqual(result["raw_data"]["journal"], ambient.to_list())


if __name__ == "__main__":
    unittest.main()
