#!/usr/bin/env python3
import unittest
from unittest.mock import patch

from reactguard.vulnerability_detection.payloads import proto_probe, run_action_probes


class TestProtoProbe(unittest.TestCase):
    def test_send_proto_probe_builds_multipart_payload(self):
        captured = {}

        def fake_scan(url, **kwargs):
            captured.update(kwargs)
            return {
                "ok": True,
                "status_code": 500,
                "headers": {"content-type": "text/x-component"},
                "body": '1:E{"digest":"deadbeef"}',
            }

        with (
            patch("reactguard.vulnerability_detection.payloads.proto_probe.secrets.token_hex", return_value="feedface"),
            patch("reactguard.vulnerability_detection.payloads.proto_probe.scan_with_retry", side_effect=fake_scan),
        ):
            result = proto_probe.send_proto_probe("http://localhost")

        self.assertTrue(result.get("ok"))
        headers = captured["headers"]
        self.assertEqual(captured["method"], "POST")
        self.assertIn("multipart/form-data", headers["Content-Type"])
        self.assertIn("Next-Action", headers)
        self.assertIn("__proto__", captured["body"])
        self.assertIn("feedface", captured["body"])

    def test_send_control_probe_uses_non_proto_path(self):
        captured = {}

        def fake_scan(url, **kwargs):
            captured.update(kwargs)
            return {
                "ok": True,
                "status_code": 200,
                "headers": {"content-type": "text/x-component"},
                "body": "0:",
            }

        with (
            patch("reactguard.vulnerability_detection.payloads.proto_probe.secrets.token_hex", return_value="a1b2c3d4"),
            patch("reactguard.vulnerability_detection.payloads.proto_probe.scan_with_retry", side_effect=fake_scan),
        ):
            result = proto_probe.send_control_probe("http://localhost")

        self.assertTrue(result.get("ok"))
        headers = captured["headers"]
        self.assertIn("multipart/form-data", headers["Content-Type"])
        self.assertNotIn("__proto__", captured["body"])
        self.assertIn("a1b2c3d4", captured["body"])

    def test_run_action_probes_adds_ids_and_errors(self):
        def fake_probe(url, action_id=None, **kwargs):
            return {"ok": False, "error_category": "TIMEOUT", "headers": {}, "body_snippet": ""}

        def fake_control(url, action_id=None, **kwargs):
            return {"ok": True, "status_code": 200}

        actions = ["act1", "act2"]
        probe_results, control_result = run_action_probes(
            "http://localhost",
            actions,
            action_probe=fake_probe,
            control_probe=fake_control,
        )

        self.assertEqual([r["action_id"] for r in probe_results], actions)
        self.assertEqual(control_result.get("action_id"), "control_probe")
        self.assertEqual(probe_results[0].get("error_category"), "TIMEOUT")


if __name__ == "__main__":
    unittest.main()
