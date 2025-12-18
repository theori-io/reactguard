# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for RSC probe helpers."""

import unittest
from unittest.mock import patch

from reactguard.framework_detection.signals.rsc import apply_rsc_probe_results
from reactguard.utils import TagSet


class TestApplyRscProbeResults(unittest.TestCase):
    def test_adds_rsc_tag_when_probe_hits_endpoint(self):
        tags = TagSet()
        signals = {}

        with patch("reactguard.framework_detection.signals.rsc.probe_rsc_and_actions") as mock_probe:
            mock_probe.return_value = {"rsc_endpoint_found": True, "invocation_enabled": False}

            result = apply_rsc_probe_results(
                "http://example.com",
                tags=tags,
                signals=signals,
                rsc_tag="rsc-tag",
            )

        self.assertTrue(result["rsc_endpoint_found"])
        self.assertIn("rsc-tag", tags)
        self.assertTrue(signals["rsc_endpoint_found"])
        self.assertNotIn("invocation_enabled", signals)

    def test_server_actions_can_imply_rsc_and_defaults(self):
        tags = TagSet()
        signals = {}

        with patch("reactguard.framework_detection.signals.rsc.probe_rsc_and_actions") as mock_probe:
            mock_probe.return_value = {"rsc_endpoint_found": False, "invocation_enabled": True}

            result = apply_rsc_probe_results(
                "http://example.com",
                tags=tags,
                signals=signals,
                rsc_tag="expo-rsc",
                server_actions_tag="expo-server-actions",
                server_actions_imply_rsc=True,
                set_defaults=True,
        )

        self.assertFalse(result["rsc_endpoint_found"])
        self.assertTrue(result["invocation_enabled"])
        self.assertIn("expo-rsc", tags)
        self.assertIn("expo-server-actions", tags)
        self.assertTrue(signals["rsc_endpoint_found"])
        self.assertTrue(signals["invocation_enabled"])

    def test_defaults_do_not_override_existing_true(self):
        tags = TagSet()
        signals = {"invocation_enabled": True}

        with patch("reactguard.framework_detection.signals.rsc.probe_rsc_and_actions") as mock_probe:
            mock_probe.return_value = {"rsc_endpoint_found": False, "invocation_enabled": False}

            apply_rsc_probe_results(
                "http://example.com",
                tags=tags,
                signals=signals,
                set_defaults=True,
        )

        self.assertFalse(signals["rsc_endpoint_found"])
        self.assertTrue(signals["invocation_enabled"])


if __name__ == "__main__":
    unittest.main()
