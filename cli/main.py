from __future__ import annotations

"""
    ReactGuard, framework- and vulnerability-detection tooling for CVE-2025-55182 (React2Shell).
    Copyright (C) 2025  Theori Inc.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""ReactGuard CLI."""

import argparse
import json
import sys
from typing import Any, Dict

from ..config import HttpSettings, load_http_settings
from ..http import create_default_http_client
from ..log import setup_logging
from ..runtime import ReactGuard


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ReactGuard React2Shell scanner (framework + vulnerability detection)"
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON instead of human-friendly summary",
    )
    parser.add_argument(
        "--ignore-ssl-errors",
        action="store_true",
        help="Skip TLS verification (useful for lab/self-signed targets)",
    )
    return parser


def _print_json(data: Dict[str, Any] | Any) -> None:
    payload = data.to_dict() if hasattr(data, "to_dict") else data
    json.dump(payload, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _pretty_print(report: Dict[str, Any] | Any) -> None:
    payload = report.to_dict() if hasattr(report, "to_dict") else report
    if not isinstance(payload, dict):
        print(payload)
        return
    report_dict: Dict[str, Any] = payload
    status = report_dict.get("status") or report_dict.get("vulnerability_detection", {}).get("status")
    detection = report_dict.get("framework_detection", {}) or {}
    vuln = report_dict.get("vulnerability_detection", {}) or {}
    details = vuln.get("details", {}) or {}

    tags = detection.get("tags") or []
    signals = detection.get("signals") or {}
    true_signals = sorted(k for k, v in signals.items() if v is True)

    print(f"[ReactGuard] Status: {status}")
    print(f"Framework tags: {', '.join(tags) if tags else '-'}")
    if true_signals:
        print(f"Signals ({len(true_signals)}): {', '.join(true_signals)}")
    reason = details.get("reason") or vuln.get("reason")
    confidence = details.get("confidence") or vuln.get("confidence")
    if reason:
        print(f"Reason: {reason}")
    if confidence:
        print(f"Confidence: {confidence}")
    detected_versions = details.get("detected_versions") or {}
    if detected_versions:
        versions_str = ", ".join(f"{k}={v}" for k, v in detected_versions.items())
        print(f"Detected versions: {versions_str}")


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    settings: HttpSettings = load_http_settings()
    if args.ignore_ssl_errors:
        settings.verify_ssl = False

    http_client = create_default_http_client(settings)

    with ReactGuard(http_client=http_client) as guard:
        report = guard.scan(
            args.url,
        )

    if args.json:
        _print_json(report)
    else:
        _pretty_print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
