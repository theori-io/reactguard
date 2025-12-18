"""
Unit tests for assessor orchestration.
"""

import unittest
from unittest.mock import patch

from reactguard.models.poc import PocStatus
from reactguard.vulnerability_detection.assessors.generic_rsc import GenericRSCAssessor
from reactguard.vulnerability_detection.assessors.nextjs import NextJSAssessor
from reactguard.vulnerability_detection.assessors.react_router import ReactRouterAssessor


class TestNextJSAssessor(unittest.TestCase):
    def test_react_18_still_runs_probes(self):
        assessor = NextJSAssessor()
        fake_actions = ["40aaa", "40bbb", "40ccc"]
        with (
            patch("reactguard.vulnerability_detection.assessors.nextjs.generate_action_ids", return_value=fake_actions),
            patch("reactguard.vulnerability_detection.assessors.nextjs.discover_nextjs_action_entrypoint", return_value=None),
            patch(
                "reactguard.vulnerability_detection.assessors.nextjs.run_rsc_action_probes",
                return_value=(
                    [{"status_code": 500, "body": "err", "headers": {}, "body_snippet": "err"}] * 3,
                    {"status_code": 200, "body": "ok", "headers": {}, "body_snippet": "ok"},
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
                detected_versions={"react_version": "18.2.0"},
                detect_context={"react_major": 18, "signals": {"rsc_endpoint_found": True}},
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
                "reactguard.vulnerability_detection.assessors.nextjs.discover_nextjs_action_entrypoint",
                return_value=None,
            ),
            patch(
                "reactguard.vulnerability_detection.assessors.nextjs.run_rsc_action_probes",
                return_value=(
                    [{"ok": True, "status_code": 500, "headers": {"content-type": "text/x-component"}, "body_snippet": '0:{"a":"$@1"}'}] * 3,
                    {"ok": True, "status_code": 200, "headers": {"content-type": "text/x-component"}, "body_snippet": '0:{"a":"$@1"}'},
                ),
            ) as run_probes,
            patch("reactguard.vulnerability_detection.assessors.nextjs.NextjsInterpreter") as analyzer_cls,
        ):
            analyzer_cls.return_value.analyze.return_value = {"status": PocStatus.NOT_VULNERABLE, "details": {"confidence": "medium"}}
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": "19.0.0"},
                detect_context={"react_major": 19, "signals": {"rsc_endpoint_found": True}},
            )

        self.assertEqual(result["status"], PocStatus.NOT_VULNERABLE)
        run_probes.assert_called_once()
        analyzer_cls.return_value.analyze.assert_called_once()
        self.assertEqual(analyzer_cls.return_value.analyze.call_args.kwargs["action_ids"], fake_actions)
        self.assertTrue(analyzer_cls.call_args.kwargs["server_actions_expected"])
        self.assertEqual(analyzer_cls.call_args.kwargs["react_major"], 19)

    def test_confirmation_round_runs_on_vulnerable(self):
        assessor = NextJSAssessor()
        action_batches = [
            ["40aaa", "40bbb", "40ccc"],
            ["50aaa", "50bbb"],
        ]
        with (
            patch("reactguard.vulnerability_detection.assessors.nextjs.generate_action_ids", side_effect=action_batches),
            patch("reactguard.vulnerability_detection.assessors.nextjs.discover_nextjs_action_entrypoint", return_value=None),
            patch(
                "reactguard.vulnerability_detection.assessors.nextjs.run_rsc_action_probes",
                side_effect=[
                    (
                        [{"status_code": 500, "body": "err", "headers": {}, "body_snippet": "err"}] * 3,
                        {"status_code": 500, "body": "err", "headers": {}, "body_snippet": "err"},
                    ),
                    (
                        [{"status_code": 500, "body": "err2", "headers": {}, "body_snippet": "err2"}] * 2,
                        {"status_code": 500, "body": "err2", "headers": {}, "body_snippet": "err2"},
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
                detected_versions={"react_version": "19.0.0"},
                detect_context={"react_major": 19, "signals": {"rsc_endpoint_found": True}},
            )

        self.assertEqual(result["status"], PocStatus.VULNERABLE)
        self.assertTrue(result["details"].get("confirmed"))
        self.assertEqual(result["details"].get("confidence"), "high")
        self.assertIn("confirmation", result["raw_data"])
        self.assertEqual(run_probes.call_count, 2)
        self.assertEqual(analyze.call_count, 2)


class TestGenericRSCAssessor(unittest.TestCase):
    def test_passes_server_actions_flag(self):
        assessor = GenericRSCAssessor()
        fake_actions = ["40ddd", "40eee", "40fff"]
        with (
            patch("reactguard.vulnerability_detection.assessors.generic_rsc.generate_action_ids", return_value=fake_actions),
            patch(
                "reactguard.vulnerability_detection.assessors.generic_rsc.run_rsc_action_probes",
                return_value=(
                    [{"ok": True, "status_code": 500, "headers": {}, "body_snippet": "err"}] * 3,
                    {"ok": True, "status_code": 200, "headers": {}, "body_snippet": "ok"},
                ),
            ) as run_probes,
            patch("reactguard.vulnerability_detection.assessors.generic_rsc.GenericRscInterpreter") as analyzer_cls,
        ):
            analyzer_cls.return_value.analyze.return_value = {"status": PocStatus.INCONCLUSIVE, "details": {}}
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": "19.0.0"},
                detect_context={"react_major": 19, "server_actions_enabled": False},
            )

        self.assertEqual(result["status"], PocStatus.INCONCLUSIVE)
        run_probes.assert_called_once()
        analyzer_cls.return_value.analyze.assert_called_once()
        self.assertEqual(analyzer_cls.return_value.analyze.call_args.kwargs["action_ids"], fake_actions)
        self.assertFalse(analyzer_cls.call_args.kwargs["server_actions_expected"])
        self.assertEqual(analyzer_cls.call_args.kwargs["react_major"], 19)


class TestReactRouterAssessor(unittest.TestCase):
    def test_v6_short_circuits_as_not_applicable(self):
        assessor = ReactRouterAssessor()
        with patch("reactguard.vulnerability_detection.assessors.react_router.run_rsc_action_probes") as run_probes:
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": "19.0.0"},
                detect_context={"signals": {"react_router_v6": True}, "tags": ["react-router-v6"]},
            )

        run_probes.assert_not_called()
        self.assertEqual(result["status"], PocStatus.NOT_VULNERABLE)
        self.assertIn("v7-only", result["details"]["reason"].lower())

    def test_skips_when_no_server_actions_surface(self):
        assessor = ReactRouterAssessor()
        with patch("reactguard.vulnerability_detection.assessors.react_router.run_rsc_action_probes") as run_probes:
            result = assessor.evaluate(
                base_url="http://localhost",
                detected_versions={"react_version": "19.0.0"},
                detect_context={
                    "signals": {
                        "react_router_v7": True,
                        "react_bundle_only": True,
                    },
                    "tags": ["react-router-v7"],
                },
            )

        run_probes.assert_not_called()
        self.assertEqual(result["status"], PocStatus.NOT_VULNERABLE)
        self.assertIn("server actions", result["details"]["reason"].lower())


if __name__ == "__main__":
    unittest.main()
