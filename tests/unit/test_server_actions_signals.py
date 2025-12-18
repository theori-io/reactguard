# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for server action probe helper."""

import unittest

from reactguard.framework_detection.signals.server_actions import apply_server_actions_probe_results
from reactguard.utils import TagSet


class TestApplyServerActionsProbeResults(unittest.TestCase):
    def test_action_not_found_promotes_supported(self):
        signals = {}
        tags = TagSet()
        probe_result = {
            "supported": False,
            "action_not_found_header": True,
            "action_not_found_body": False,
            "status_code": 404,
        }

        result = apply_server_actions_probe_results(
            probe_result=probe_result,
            tags=tags,
            signals=signals,
            not_found_signal_key="nextjs_action_not_found",
        )

        self.assertFalse(result["supported"])
        self.assertNotIn("invocation_enabled", signals)
        self.assertTrue(signals["nextjs_action_not_found"])

    def test_html_with_markers_and_keywords_counts_as_supported(self):
        signals = {}
        tags = TagSet()
        probe_result = {
            "supported": False,
            "status_code": 404,
            "has_action_keywords": True,
            "has_framework_html_marker": True,
            "is_html": True,
            "has_action_content_type": False,
            "has_flight_marker": False,
            "has_digest": False,
        }

        result = apply_server_actions_probe_results(
            probe_result=probe_result,
            tags=tags,
            signals=signals,
            server_actions_tag="server-actions",
            default_confidence="medium",
        )

        self.assertTrue(result["supported"])
        self.assertIn("server-actions", tags)
        self.assertEqual(signals["invocation_confidence"], "medium")

    def test_html_marker_hint_sets_false_with_low_confidence(self):
        signals = {}
        tags = TagSet()
        probe_result = {
            "supported": False,
            "status_code": 200,
            "has_action_keywords": False,
            "has_framework_html_marker": False,
            "is_html": True,
        }

        result = apply_server_actions_probe_results(
            probe_result=probe_result,
            tags=tags,
            signals=signals,
            html_marker_hint=True,
            fallback_html_signal_key="nextjs_probe_html_with_next_marker",
            set_defaults=False,
        )

        self.assertFalse(result["supported"])
        self.assertIsNone(signals["invocation_enabled"])
        self.assertEqual(signals["invocation_confidence"], "low")
        self.assertTrue(signals["nextjs_probe_html_with_next_marker"])

    def test_sets_react_major_and_rsc_flight_signals(self):
        signals = {}
        tags = TagSet()
        probe_result = {
            "supported": True,
            "status_code": 200,
            "flight_format": "object",
            "react_major_from_flight": 19,
        }

        apply_server_actions_probe_results(
            probe_result=probe_result,
            tags=tags,
            signals=signals,
            react_major_signal_key="detected_react_major",
            rsc_flight_signal_key="rsc_flight_payload",
        )

        self.assertTrue(signals["invocation_enabled"])
        self.assertEqual(signals["detected_react_major"], 19)
        self.assertTrue(signals["rsc_flight_payload"])


if __name__ == "__main__":
    unittest.main()
