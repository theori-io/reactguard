#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

import unittest

from reactguard.models.poc import PocStatus
from reactguard.vulnerability_detection.interpreters import analyze_multi_action_results
from reactguard.vulnerability_detection.journal import PocJournal, journal_context


class TestMultiActionInterpreter(unittest.TestCase):
    def test_infers_react_major_from_flight_root_shape(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 500,
                "body_snippet": '0:["$@1",["x",null]]\n1:E{"digest":"deadbeef"}\n',
                "headers": {"content-type": "text/x-component"},
            }
        ]
        control_results = [
            {
                "action_id": "40bbbb",
                "status_code": 500,
                "body_snippet": '0:["$@1",["x",null]]\n1:E{"digest":"deadbeef"}\n',
                "headers": {"content-type": "text/x-component"},
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa"],
            is_rsc_framework=True,
            invocation_expected=True,
            control_results=control_results,
            react_major=None,
            react_major_confidence=None,
        )

        self.assertEqual(result["details"]["react_major"], 18)

    def test_content_type_header_is_case_insensitive_for_success_detection(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 200,
                "body_snippet": "ok",
                "headers": {"Content-Type": "text/x-component"},
            }
        ]
        control_results = [
            {
                "action_id": "40aaaa",
                "status_code": 200,
                "body_snippet": "ok",
                "headers": {"Content-Type": "text/x-component"},
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa"],
            is_rsc_framework=True,
            invocation_expected=True,
            control_results=control_results,
            react_major=19,
        )

        self.assertEqual(result["status"], PocStatus.NOT_VULNERABLE)
        self.assertEqual(result["details"]["decision_rule"], "_rule_success_path")

    def test_react_major_conflict_lowers_confidence_without_forcing_inconclusive(self):
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
                "action_id": "40cccc",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"deadbeef"}',
                "headers": {"content-type": "text/x-component"},
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa", "40bbbb"],
            is_rsc_framework=True,
            invocation_expected=True,
            control_results=control_results,
            react_major=18,
            react_major_conflict=True,
            react_major_conflict_confidence="high",
            react_major_conflict_majors=[18, 19],
        )

        self.assertEqual(result["status"], PocStatus.LIKELY_NOT_VULNERABLE)
        self.assertEqual(result["details"]["confidence"], "low")
        self.assertIs(result["details"].get("react_major_conflict"), True)

    def test_safe_args_strategy_match_marks_vulnerable(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"deadbeef"}',
                "headers": {"content-type": "text/x-component"},
                "payload_meta": {"probe_strategy": "safe_args_bigint_length"},
            },
            {
                "action_id": "40bbbb",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"deadbeef"}',
                "headers": {"content-type": "text/x-component"},
                "payload_meta": {"probe_strategy": "safe_args_bigint_length"},
            },
        ]
        control_results = [
            {
                "action_id": "40cccc",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"deadbeef"}',
                "headers": {"content-type": "text/x-component"},
                "payload_meta": {"probe_strategy": "safe_args_bigint_length"},
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa", "40bbbb"],
            is_rsc_framework=True,
            invocation_expected=True,
            control_results=control_results,
            react_major=19,
        )

        self.assertEqual(result["status"], PocStatus.VULNERABLE)
        self.assertEqual(result["details"]["decision_rule"], "_rule_safe_args_no_invoke")

    def test_safe_args_strategy_divergence_marks_likely_not_vulnerable(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"proto1"}',
                "headers": {"content-type": "text/x-component"},
                "payload_meta": {"probe_strategy": "safe_args_bigint_length"},
            },
            {
                "action_id": "40bbbb",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"proto1"}',
                "headers": {"content-type": "text/x-component"},
                "payload_meta": {"probe_strategy": "safe_args_bigint_length"},
            },
        ]
        control_results = [
            {
                "action_id": "40cccc",
                "status_code": 500,
                "body_snippet": '1:E{"digest":"ctrl1"}',
                "headers": {"content-type": "text/x-component"},
                "payload_meta": {"probe_strategy": "safe_args_bigint_length"},
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa", "40bbbb"],
            is_rsc_framework=True,
            invocation_expected=True,
            control_results=control_results,
            react_major=19,
        )

        self.assertEqual(result["status"], PocStatus.LIKELY_NOT_VULNERABLE)
        self.assertEqual(result["details"]["decision_rule"], "_rule_safe_args_no_invoke")

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
        self.assertIs(result["details"].get("decode_surface_reached"), False)
        self.assertEqual(result["details"]["decision_rule"], "_rule_rsc_validation_without_success")

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
        self.assertTrue(any(entry.get("step") == "probe" for entry in ambient.to_list()))
        self.assertTrue(any(entry.get("step") == "decision" for entry in ambient.to_list()))
        self.assertEqual(result["raw_data"]["journal"], ambient.to_list())

    def test_all_failed_includes_raw_results_and_journals_failures(self):
        probe_results = [
            {
                "action_id": "40aaaa",
                "ok": False,
                "status_code": None,
                "body_snippet": "",
                "headers": {},
                "endpoint": "https://example.invalid/_action",
                "error_message": "timed out",
                "error_type": "TimeoutError",
            },
            {
                "action_id": "40bbbb",
                "ok": False,
                "status_code": None,
                "body_snippet": "",
                "headers": {},
                "endpoint": "https://example.invalid/_action",
                "error_message": "timed out",
                "error_type": "TimeoutError",
            },
        ]
        control_results = [
            {
                "action_id": "control_probe",
                "ok": False,
                "status_code": None,
                "body_snippet": "",
                "headers": {},
                "endpoint": "https://example.invalid/_action",
                "error_message": "timed out",
                "error_type": "TimeoutError",
            }
        ]

        result = analyze_multi_action_results(
            probe_results,
            action_ids=["40aaaa", "40bbbb"],
            is_rsc_framework=True,
            control_results=control_results,
        )

        self.assertEqual(result["status"], PocStatus.INCONCLUSIVE)
        self.assertEqual(result["details"]["decision_rule"], "all_probes_failed")
        self.assertEqual(result["raw_data"]["probe_results"], probe_results)
        self.assertEqual(result["raw_data"]["control_results"], control_results)

        journal_entries = result["raw_data"]["journal"]
        probe_entries = [e for e in journal_entries if e.get("step") == "probe"]
        self.assertGreaterEqual(len(probe_entries), len(probe_results) + len(control_results))


if __name__ == "__main__":
    unittest.main()
