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

"""Version parsing and extraction utilities."""

import logging
import re
from dataclasses import dataclass
from typing import Any

from .version_thresholds import (
    NEXT_CANARY_SAFE_BUILD,
    NEXT_PATCHED_PATCH_BY_MINOR,
    REACT_FIXED_VERSIONS,
    REACT_VULNERABLE_VERSIONS,
)

logger = logging.getLogger(__name__)


@dataclass
class ParsedVersion:
    major: int
    minor: int
    patch: int
    suffix: str = ""

    def __lt__(self, other: "ParsedVersion") -> bool:
        if not isinstance(other, ParsedVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    def __le__(self, other: "ParsedVersion") -> bool:
        if not isinstance(other, ParsedVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) <= (other.major, other.minor, other.patch)

    def __gt__(self, other: "ParsedVersion") -> bool:
        if not isinstance(other, ParsedVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)

    def __ge__(self, other: "ParsedVersion") -> bool:
        if not isinstance(other, ParsedVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) >= (other.major, other.minor, other.patch)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ParsedVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        return f"{base}-{self.suffix}" if self.suffix else base

    def to_tuple(self) -> tuple[int, int, int, str]:
        return (self.major, self.minor, self.patch, self.suffix)


_CONFIDENCE_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _confidence_score(confidence: str | None) -> int:
    return _CONFIDENCE_ORDER.get(str(confidence or "").lower(), 0)


def _confidence_label(score: int) -> str:
    if score >= _CONFIDENCE_ORDER["high"]:
        return "high"
    if score >= _CONFIDENCE_ORDER["medium"]:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def parse_semver(version: str | None) -> ParsedVersion | None:
    if not version:
        return None
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?", str(version))
    if not match:
        return None
    return ParsedVersion(
        major=int(match.group(1)),
        minor=int(match.group(2) or 0),
        patch=int(match.group(3) or 0),
        suffix=match.group(4) or "",
    )


def compare_semver(a: str | None, b: str | None) -> int | None:
    pa = parse_semver(a)
    pb = parse_semver(b)
    if not pa or not pb:
        return None
    if pa < pb:
        return -1
    if pa > pb:
        return 1
    return 0


SEMVER_PATTERN = r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?"


class VersionPatterns:
    """Patterns curated from the lab containers for immutable version markers."""

    RSC_FLIGHT_IMPORT = re.compile(rf'\d+:I\["react-server-dom-(?:webpack|parcel|turbopack)"\s*,\s*"({SEMVER_PATTERN})"')

    CORE_REACT_PACKAGE = re.compile(
        rf"(?<![a-z-])react(?:-dom)?@({SEMVER_PATTERN})",
        re.IGNORECASE,
    )

    REACT_PACKAGE = re.compile(
        rf"(?:react(?:-dom)?|react-server-dom-(?:webpack|parcel|turbopack))@({SEMVER_PATTERN})",
        re.IGNORECASE,
    )

    RSC_RUNTIME_PACKAGE = re.compile(
        rf"react-server-dom-(?:webpack|parcel|turbopack)@({SEMVER_PATTERN})",
        re.IGNORECASE,
    )

    REACT_MANIFEST = re.compile(rf'"react"\s*:\s*"({SEMVER_PATTERN})"')
    NEXT_MANIFEST = re.compile(rf'"next"\s*:\s*"({SEMVER_PATTERN})"')

    REACT_PLAIN = re.compile(rf"React(?:\.js)?\s+({SEMVER_PATTERN})", re.IGNORECASE)
    NEXT_PLAIN = re.compile(rf"Next\.?js\s+({SEMVER_PATTERN})", re.IGNORECASE)
    WAKU_PLAIN = re.compile(rf"Waku\s+({SEMVER_PATTERN})", re.IGNORECASE)

    NEXT_LITERAL = re.compile(rf"next@({SEMVER_PATTERN})", re.IGNORECASE)
    WAKU_LITERAL = re.compile(rf"waku@({SEMVER_PATTERN})", re.IGNORECASE)

    REACT_ROUTER_VERSION = re.compile(r'__reactRouterVersion"?\s*[:=]\s*"(\d+\.\d+\.\d+)"')


def extract_versions(headers: dict[str, str], body: str) -> dict[str, Any]:
    versions: dict[str, Any] = {}
    body = body or ""
    body_lower = body.lower()

    def _maybe_set_version(key: str, value: str, source: str, confidence: str) -> None:
        """Set a version value with source/confidence, preferring stronger confidence."""
        current_confidence = _confidence_score(versions.get(f"{key}_confidence"))
        new_confidence = _confidence_score(confidence)
        if key not in versions or new_confidence > current_confidence:
            versions[key] = value
            versions[f"{key}_source"] = source
            versions[f"{key}_confidence"] = confidence

    def _confidence_from_source(source: str) -> str:
        if source in {"header", "rsc_flight", "rsc_runtime_package", "core_package"}:
            return "high"
        if source in {"manifest", "literal"}:
            return "medium"
        return "low"

    next_ver = headers.get("x-nextjs-version") or headers.get("x-next-version")
    if next_ver:
        _maybe_set_version("next_version", next_ver, "header", "high")

    waku_ver = headers.get("x-waku-version")
    if waku_ver:
        _maybe_set_version("waku_version", waku_ver, "header", "high")

    rsc_flight_match = VersionPatterns.RSC_FLIGHT_IMPORT.search(body)
    if rsc_flight_match:
        value = rsc_flight_match.group(1)
        _maybe_set_version("rsc_runtime_version", value, "rsc_flight", "high")
        _maybe_set_version("react_version", value, "rsc_flight", "high")
        versions["rsc_flight_version_source"] = "I_chunk"

    rsc_runtime = VersionPatterns.RSC_RUNTIME_PACKAGE.search(body)
    if rsc_runtime:
        value = rsc_runtime.group(1)
        _maybe_set_version("rsc_runtime_version", value, "rsc_runtime_package", "high")

    if "react_version" not in versions:
        core_react_match = VersionPatterns.CORE_REACT_PACKAGE.search(body)
        if core_react_match:
            _maybe_set_version("react_version", core_react_match.group(1), "core_package", "high")

    if "react_version" not in versions and versions.get("rsc_runtime_version"):
        _maybe_set_version(
            "react_version",
            versions["rsc_runtime_version"],
            "rsc_runtime_package",
            versions.get("rsc_runtime_version_confidence", "high"),
        )

    if "react_version" not in versions:
        react_match = VersionPatterns.REACT_PACKAGE.search(body)
        if react_match:
            _maybe_set_version("react_version", react_match.group(1), "package_literal", "medium")

    if "react_version" not in versions:
        manifest_match = VersionPatterns.REACT_MANIFEST.search(body)
        if manifest_match:
            _maybe_set_version("react_version", manifest_match.group(1), "manifest", "medium")

    if "react_version" not in versions:
        plain_match = VersionPatterns.REACT_PLAIN.search(body)
        if plain_match:
            _maybe_set_version("react_version", plain_match.group(1), "plain_text", "low")

    if "next_version" not in versions:
        next_literal = VersionPatterns.NEXT_LITERAL.search(body)
        if next_literal:
            _maybe_set_version("next_version", next_literal.group(1), "package_literal", "medium")

    if "next_version" not in versions:
        next_manifest = VersionPatterns.NEXT_MANIFEST.search(body)
        if next_manifest:
            _maybe_set_version("next_version", next_manifest.group(1), "manifest", "medium")

    if "next_version" not in versions:
        plain_next = VersionPatterns.NEXT_PLAIN.search(body)
        if plain_next:
            _maybe_set_version("next_version", plain_next.group(1), "plain_text", "low")

    if "waku_version" not in versions:
        waku_literal = VersionPatterns.WAKU_LITERAL.search(body)
        if waku_literal:
            _maybe_set_version("waku_version", waku_literal.group(1), "package_literal", "medium")

    if "waku_version" not in versions:
        waku_plain = VersionPatterns.WAKU_PLAIN.search(body_lower)
        if waku_plain:
            _maybe_set_version("waku_version", waku_plain.group(1), "plain_text", "low")

    rr_match = VersionPatterns.REACT_ROUTER_VERSION.search(body)
    if rr_match:
        _maybe_set_version("react_router_version", rr_match.group(1), "bundle_literal", "high")

    if versions.get("react_version"):
        react_ver = str(versions["react_version"])
        if react_ver and react_ver[0].isdigit():
            try:
                versions["react_major"] = int(react_ver.split(".")[0])
                versions["react_major_confidence"] = versions.get("react_version_confidence", "medium")
            except ValueError:
                logger.debug("Could not parse React major from: %s", react_ver)

    return versions


def is_react_version_vulnerable(version: str | None) -> bool | None:
    parsed = parse_semver(version)
    if not parsed:
        return None
    if parsed.major != 19:
        return False

    version_key = (parsed.major, parsed.minor, parsed.patch)
    if version_key in REACT_VULNERABLE_VERSIONS:
        return True
    if version_key in REACT_FIXED_VERSIONS:
        return False

    # Default for React 19.x not explicitly listed: assume fixed when patch >= latest known fix.
    if parsed.minor == 0:
        return parsed.patch == 0
    if parsed.minor == 1:
        return parsed.patch <= 1
    if parsed.minor == 2:
        return parsed.patch == 0
    return False


def is_next_version_vulnerable(version: str | None) -> bool | None:
    parsed = parse_semver(version)
    if not parsed:
        return None
    if parsed.major < 14:
        return False

    suffix = parsed.suffix or ""
    is_canary = "canary" in suffix

    def _canary_build(suf: str) -> int | None:
        match = re.search(r"canary\.?(\d+)", suf)
        return int(match.group(1)) if match else None

    if parsed.major == 14:
        if not is_canary:
            return False
        build = _canary_build(suffix)
        if parsed.minor > 3:
            return True
        if build is None:
            return True
        return build >= 77

    if parsed.major == 15:
        build = _canary_build(suffix) if is_canary else None
        if is_canary:
            if parsed.minor == 6 and build is not None:
                safe_build = NEXT_CANARY_SAFE_BUILD.get((15, 6))
                if safe_build is None:
                    return True
                return build < safe_build
            return True

        threshold = NEXT_PATCHED_PATCH_BY_MINOR.get(15, {}).get(parsed.minor)
        if threshold is None:
            return True
        return parsed.patch < threshold

    if parsed.major == 16:
        build = _canary_build(suffix) if is_canary else None
        if is_canary:
            if parsed.minor == 1 and build is not None:
                safe_build = NEXT_CANARY_SAFE_BUILD.get((16, 1))
                if safe_build is None:
                    return True
                return build < safe_build
            return True
        if parsed.minor == 0:
            return parsed.patch < NEXT_PATCHED_PATCH_BY_MINOR.get(16, {}).get(0, 0)
        # Future 16.x minors default to vulnerable unless explicitly patched
        return True

    # Unknown future major: treat as not vulnerable by default.
    return False


def waku_version_implies_react_major(waku_version: str | None) -> int | None:
    parsed = parse_semver(waku_version)
    if not parsed:
        return None
    if parsed.major == 0 and parsed.minor <= 17:
        return 18
    if parsed.major == 0 and parsed.minor >= 19:
        return 19
    return None
