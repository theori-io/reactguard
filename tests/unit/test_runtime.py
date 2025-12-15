import unittest
from unittest.mock import patch

from reactguard.http import HttpResponse
from reactguard.http.adapters import StubHttpClient
from reactguard.runtime import ReactGuard


class ClosingStubHttpClient(StubHttpClient):
    def __init__(self, responses=None):
        super().__init__(responses)
        self.closed = False

    def close(self) -> None:
        self.closed = True


class TestReactGuardRuntime(unittest.TestCase):
    def test_detect_reuses_injected_client_and_closes(self):
        responses = {
            "http://localhost/": HttpResponse(ok=True, status_code=200, text="__NEXT_DATA__"),
        }
        client = ClosingStubHttpClient(responses)

        with (
            ReactGuard(http_client=client) as guard,
            patch(
                "reactguard.vulnerability_detection.engine.VulnerabilityDetectionEngine.run",
                return_value={"status": "INCONCLUSIVE", "details": {}},
            ) as vuln_run,
        ):
            detection = guard.detect("http://localhost/")
            self.assertIn("nextjs", detection.tags)

            scan = guard.scan("http://localhost/")
            self.assertIn("framework_detection", scan)
            vuln_run.assert_called_once()

        self.assertTrue(client.closed)


if __name__ == "__main__":
    unittest.main()
