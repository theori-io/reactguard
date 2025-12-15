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
import re
import sys
from typing import Any

from ..config import HttpSettings, load_http_settings
from ..http import create_default_http_client
from ..log import setup_logging
from ..runtime import ReactGuard

CLI_TEXT_TRUNCATION_BYTES = 4096
_CVE_ID_RE = re.compile(r"^CVE-(?P<year>\d{4})-(?P<number>\d+)$")
_CVE_IMPACTS: dict[str, str] = {
    "CVE-2025-55182": "Remote Code Execution",
}


def _cve_sort_key(cve_id: str) -> tuple[int, int, str]:
    match = _CVE_ID_RE.match(cve_id or "")
    if not match:
        return (9999, 99999999, cve_id or "")
    return (int(match.group("year")), int(match.group("number")), cve_id)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ReactGuard React2Shell scanner (framework + vulnerability detection)")
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


def _truncate_text_bytes(text: str, max_bytes: int) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    suffix = "...[truncated]"
    suffix_bytes = suffix.encode("utf-8")
    keep = max_bytes - len(suffix_bytes)
    if keep <= 0:
        return suffix_bytes[:max_bytes].decode("utf-8", errors="ignore")
    prefix = raw[:keep].decode("utf-8", errors="ignore")
    return prefix + suffix


def _truncate_for_cli(value: Any, *, max_bytes: int, _stack: set[int] | None = None) -> Any:
    """
    Truncate large strings in JSON output while protecting against true reference cycles.

    Note: We track only the *current* recursion stack (not all visited objects) so repeated references
    don't get mislabeled as circular.
    """
    if _stack is None:
        _stack = set()

    if isinstance(value, str):
        return _truncate_text_bytes(value, max_bytes)

    if isinstance(value, dict):
        obj_id = id(value)
        if obj_id in _stack:
            return "<circular>"
        _stack.add(obj_id)
        try:
            return {k: _truncate_for_cli(v, max_bytes=max_bytes, _stack=_stack) for k, v in value.items()}
        finally:
            _stack.discard(obj_id)

    if isinstance(value, list):
        obj_id = id(value)
        if obj_id in _stack:
            return ["<circular>"]
        _stack.add(obj_id)
        try:
            return [_truncate_for_cli(v, max_bytes=max_bytes, _stack=_stack) for v in value]
        finally:
            _stack.discard(obj_id)

    return value


def _print_json(data: dict[str, Any] | Any) -> None:
    payload = data.to_dict() if hasattr(data, "to_dict") else data
    json.dump(_truncate_for_cli(payload, max_bytes=CLI_TEXT_TRUNCATION_BYTES), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _pretty_print(report: dict[str, Any] | Any) -> None:
    payload = report.to_dict() if hasattr(report, "to_dict") else report
    if not isinstance(payload, dict):
        print(payload)
        return
    report_dict: dict[str, Any] = payload
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
    vuln_list = report_dict.get("vulnerability_detections")
    if isinstance(vuln_list, list) and vuln_list:
        print("Findings:")
        for item in sorted(
            (v for v in vuln_list if isinstance(v, dict)),
            key=lambda v: _cve_sort_key(str((v.get("details") or {}).get("cve_id") or "")),
        ):
            if not isinstance(item, dict):
                continue
            item_status = item.get("status")
            item_details = item.get("details", {}) or {}
            cve_id = item_details.get("cve_id") or "unknown"
            impact = _CVE_IMPACTS.get(str(cve_id))
            impact_suffix = f" ({impact})" if impact else ""
            reason = item_details.get("reason") or ""
            confidence = item_details.get("confidence") or ""
            suffix = f" ({confidence})" if confidence else ""
            if reason:
                print(f"- {cve_id}{impact_suffix}: {item_status}{suffix} — {reason}")
            else:
                print(f"- {cve_id}{impact_suffix}: {item_status}{suffix}")
        return

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
