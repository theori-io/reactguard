# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Unit tests for assessor orchestration.
"""

import unittest
from unittest.mock import patch

from reactguard.models.poc import PocStatus
from reactguard.utils import DetectedVersion
from reactguard.rsc.types import RscResponse
from reactguard.vulnerability_detection.assessors.generic_rsc import GenericRSCAssessor
from reactguard.vulnerability_detection.assessors.nextjs import NextJSAssessor
from reactguard.vulnerability_detection.assessors.react_router import ReactRouterAssessor
from reactguard.vulnerability_detection.snapshots import DetectContext


def make_detect_context(
    *,
    react_major=None,
    invocation_enabled=None,
    signals=None,
    tags=None,
):
    return DetectContext(
        react_major=react_major,
        react_major_confidence=None,
        react_major_conflict=None,
        react_major_conflict_confidence=None,
        react_major_conflict_majors=None,
        invocation_enabled=invocation_enabled,
        invocation_confidence=None,
        signals=signals or {},
        tags=tags or [],
        invocation_endpoints=[],
        detected_versions={},
        extra={},
    )


def rsc_response(*, status_code=200, body="", headers=None, ok=True):
    text = str(body or "")
    return RscResponse(
        ok=ok,
        status_code=status_code,
        headers=headers or {},
        text=text,
        content=text.encode(),
        url=None,
    )


class TestNextJSAssessor(unittest.TestCase):
    def test_react_18_still_runs_probes(self):
        assessor = NextJSAssessor()
        fake_actions = ["40aaa", "40bbb", "40ccc"]
        with (
            patch("reactguard.vulnerability_detection.assessors.nextjs.generate_action_ids", return_value=fake_actions),
            patch("reactguard.vulnerability_detection.assessors.nextjs.discover_nextjs_action_entrypoint_cached", return_value=None),
            patch(
                "reactguard.vulnerability_detection.assessors.nextjs.run_rsc_action_probes",
                return_value=(
                    [rsc_response(status_code=500, body="err")] * 3,
                    rsc_response(status_code=200, body="ok"),
                ),
            ) as run_probes,
            patch("reactguard.vulnerability_detection.assessors.nextjs.NextjsInterpreter") as analyzer_cls,
        ):
            analyzer_cls.return_value.analyze.return_value = {
                "status": PocStatus.LIKELY_NOT_VULNERABLE,
                "details": {"confidence": "medium", "reason": "react 18"},
                "raw_data": {},
            }
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": DetectedVersion("18.2.0")},
                detect_context=make_detect_context(react_major=18, signals={"rsc_endpoint_found": True}),
            )
        run_probes.assert_called_once()
        analyzer_cls.return_value.analyze.assert_called_once()
        self.assertEqual(result["status"], PocStatus.LIKELY_NOT_VULNERABLE)
        self.assertEqual(analyzer_cls.call_args.kwargs["react_major"], 18)

    def test_analyzer_called_with_action_ids(self):
        assessor = NextJSAssessor()
        fake_actions = ["40aaa", "40bbb", "40ccc"]
        with (
            patch("reactguard.vulnerability_detection.assessors.nextjs.generate_action_ids", return_value=fake_actions),
            patch(
                "reactguard.vulnerability_detection.assessors.nextjs.discover_nextjs_action_entrypoint_cached",
                return_value=None,
            ),
            patch(
                "reactguard.vulnerability_detection.assessors.nextjs.run_rsc_action_probes",
                return_value=(
                    [rsc_response(status_code=500, body='0:{"a":"$@1"}', headers={"content-type": "text/x-component"})] * 3,
                    rsc_response(status_code=200, body='0:{"a":"$@1"}', headers={"content-type": "text/x-component"}),
                ),
            ) as run_probes,
            patch("reactguard.vulnerability_detection.assessors.nextjs.NextjsInterpreter") as analyzer_cls,
        ):
            analyzer_cls.return_value.analyze.return_value = {"status": PocStatus.NOT_VULNERABLE, "details": {"confidence": "medium"}}
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": DetectedVersion("19.0.0")},
                detect_context=make_detect_context(react_major=19, signals={"rsc_endpoint_found": True}),
            )

        self.assertEqual(result["status"], PocStatus.NOT_VULNERABLE)
        run_probes.assert_called_once()
        analyzer_cls.return_value.analyze.assert_called_once()
        self.assertEqual(analyzer_cls.return_value.analyze.call_args.kwargs["action_ids"], fake_actions)
        self.assertTrue(analyzer_cls.call_args.kwargs["invocation_expected"])
        self.assertEqual(analyzer_cls.call_args.kwargs["react_major"], 19)

    def test_confirmation_round_runs_on_vulnerable(self):
        assessor = NextJSAssessor()
        action_batches = [
            ["40aaa", "40bbb", "40ccc"],
            ["50aaa", "50bbb"],
        ]
        with (
            patch("reactguard.vulnerability_detection.assessors.nextjs.generate_action_ids", side_effect=action_batches),
            patch("reactguard.vulnerability_detection.assessors.nextjs.discover_nextjs_action_entrypoint_cached", return_value=None),
            patch(
                "reactguard.vulnerability_detection.assessors.nextjs.run_rsc_action_probes",
                side_effect=[
                    (
                        [rsc_response(status_code=500, body="err")] * 3,
                        rsc_response(status_code=500, body="err"),
                    ),
                    (
                        [rsc_response(status_code=500, body="err2")] * 2,
                        rsc_response(status_code=500, body="err2"),
                    ),
                ],
            ) as run_probes,
            patch(
                "reactguard.vulnerability_detection.assessors.nextjs.NextjsInterpreter.analyze",
                side_effect=[
                    {"status": PocStatus.VULNERABLE, "details": {"confidence": "medium", "reason": "first"}, "raw_data": {}},
                    {"status": PocStatus.VULNERABLE, "details": {"confidence": "medium", "reason": "confirm"}, "raw_data": {}},
                ],
            ) as analyze,
        ):
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": DetectedVersion("19.0.0")},
                detect_context=make_detect_context(react_major=19, signals={"rsc_endpoint_found": True}),
            )

        self.assertEqual(result["status"], PocStatus.VULNERABLE)
        self.assertTrue(result["details"].get("confirmed"))
        self.assertEqual(result["details"].get("confidence"), "high")
        self.assertIn("confirmation", result["raw_data"])
        self.assertEqual(run_probes.call_count, 2)
        self.assertEqual(analyze.call_count, 2)


class TestGenericRSCAssessor(unittest.TestCase):
    def test_passes_invocation_flag(self):
        assessor = GenericRSCAssessor()
        fake_actions = ["40ddd", "40eee", "40fff"]
        with (
            patch("reactguard.vulnerability_detection.assessors.generic_rsc.generate_action_ids", return_value=fake_actions),
            patch(
                "reactguard.vulnerability_detection.assessors.generic_rsc.run_rsc_action_probes",
                return_value=(
                    [rsc_response(status_code=500, body="err")] * 3,
                    rsc_response(status_code=200, body="ok"),
                ),
            ) as run_probes,
            patch("reactguard.vulnerability_detection.assessors.generic_rsc.GenericRscInterpreter") as analyzer_cls,
        ):
            analyzer_cls.return_value.analyze.return_value = {"status": PocStatus.INCONCLUSIVE, "details": {}}
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": DetectedVersion("19.0.0")},
                detect_context=make_detect_context(react_major=19, invocation_enabled=False),
            )

        self.assertEqual(result["status"], PocStatus.INCONCLUSIVE)
        run_probes.assert_called_once()
        analyzer_cls.return_value.analyze.assert_called_once()
        self.assertEqual(analyzer_cls.return_value.analyze.call_args.kwargs["action_ids"], fake_actions)
        self.assertFalse(analyzer_cls.call_args.kwargs["invocation_expected"])
        self.assertEqual(analyzer_cls.call_args.kwargs["react_major"], 19)


class TestReactRouterAssessor(unittest.TestCase):
    def test_v6_short_circuits_as_not_applicable(self):
        assessor = ReactRouterAssessor()
        with patch("reactguard.vulnerability_detection.assessors.react_router.run_safe_args_action_probes") as run_probes:
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": DetectedVersion("19.0.0")},
                detect_context=make_detect_context(signals={"react_router_v6": True}, tags=["react-router-v6"]),
            )

        run_probes.assert_not_called()
        self.assertEqual(result["status"], PocStatus.NOT_VULNERABLE)
        self.assertIn("v7-only", result["details"]["reason"].lower())

    def test_skips_when_no_server_actions_surface(self):
        assessor = ReactRouterAssessor()
        with patch("reactguard.vulnerability_detection.assessors.react_router.run_safe_args_action_probes") as run_probes:
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": DetectedVersion("19.0.0")},
                detect_context=make_detect_context(
                    signals={
                        "react_router_v7": True,
                        "react_bundle_only": True,
                    },
                    tags=["react-router-v7"],
                ),
            )

        run_probes.assert_not_called()
        self.assertEqual(result["status"], PocStatus.LIKELY_NOT_VULNERABLE)
        self.assertIn("server functions", result["details"]["reason"].lower())


if __name__ == "__main__":
    unittest.main()
