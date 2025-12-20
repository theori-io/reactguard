# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Version parsing and extraction utilities."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Mapping

from .confidence import confidence_score
from .version_thresholds import (
    NEXT_CANARY_SAFE_BUILD,
    NEXT_PATCHED_PATCH_BY_MINOR,
    REACT_FIXED_VERSIONS,
    REACT_VULNERABLE_VERSIONS,
)


@lru_cache(maxsize=64)
def _compiled_pattern(pattern: str, flags: int) -> re.Pattern[str]:
    return re.compile(pattern, flags)


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


@dataclass(frozen=True)
class DetectedVersion:
    """Normalized version pick with source/confidence metadata."""

    value: str | int
    source: str | None = None
    confidence: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> "DetectedVersion" | None:
        if not isinstance(data, Mapping):
            return None
        if "value" not in data:
            return None
        return cls(
            value=data.get("value"),
            source=data.get("source"),
            confidence=data.get("confidence"),
        )


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


def normalize_version_map(raw: Mapping[str, Any] | None) -> dict[str, DetectedVersion]:
    """Coerce a mapping of version picks into DetectedVersion objects."""
    if not isinstance(raw, Mapping):
        return {}
    normalized: dict[str, DetectedVersion] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, DetectedVersion):
            normalized[key] = value
            continue
        if isinstance(value, Mapping):
            detected = DetectedVersion.from_mapping(value)
            if detected is not None:
                normalized[key] = detected
    return normalized


def flatten_version_map(versions: Mapping[str, DetectedVersion], *, prefix: str = "") -> dict[str, Any]:
    """Flatten a DetectedVersion map into legacy signal keys."""
    flat: dict[str, Any] = {}
    for key, detected in versions.items():
        flat[f"{prefix}{key}"] = detected.value
        if detected.source is not None:
            flat[f"{prefix}{key}_source"] = detected.source
        if detected.confidence is not None:
            flat[f"{prefix}{key}_confidence"] = detected.confidence
    return flat


def version_map_from_signals(signals: Mapping[str, Any] | None, *, prefix: str) -> dict[str, DetectedVersion]:
    """Build a DetectedVersion map from flattened legacy signal keys."""
    if not isinstance(signals, Mapping):
        return {}
    versions: dict[str, DetectedVersion] = {}
    for key, value in signals.items():
        if not isinstance(key, str) or not key.startswith(prefix):
            continue
        suffix = key[len(prefix) :]
        if suffix.endswith("_confidence") or suffix.endswith("_source"):
            continue
        if value is None:
            continue
        source = signals.get(f"{prefix}{suffix}_source")
        confidence = signals.get(f"{prefix}{suffix}_confidence")
        versions[suffix] = DetectedVersion(value=value, source=source, confidence=confidence)
    return versions


def version_values(versions: Mapping[str, DetectedVersion]) -> dict[str, Any]:
    """Return a simplified map of version values (dropping metadata)."""
    return {key: detected.value for key, detected in versions.items()}


def merge_version_maps(
    target: dict[str, DetectedVersion],
    source: Mapping[str, DetectedVersion],
    *,
    prefer_semver: bool = True,
) -> None:
    """Merge version picks into target, preferring stronger confidence."""
    for key, detected in source.items():
        update_version_pick(
            target,
            key,
            detected.value,
            source=detected.source,
            confidence=detected.confidence,
            prefer_semver=prefer_semver,
        )


def derive_react_major(versions: dict[str, DetectedVersion]) -> None:
    """Derive React major from the best available version pick."""
    major_source_key = None
    major_source = None
    major_confidence = None

    rsc_pick = versions.get("rsc_runtime_version")
    react_pick = versions.get("react_version")

    if rsc_pick:
        major_source_key = "rsc_runtime_version"
        major_source = rsc_pick.source
        major_confidence = rsc_pick.confidence
        parsed = parse_semver(str(rsc_pick.value))
    elif react_pick:
        major_source_key = "react_version"
        major_source = react_pick.source
        major_confidence = react_pick.confidence
        parsed = parse_semver(str(react_pick.value))
    else:
        parsed = None

    if not parsed:
        return

    source = f"derived:{major_source_key}" if major_source_key else "derived"
    if major_source:
        source = f"derived:{major_source}"
    update_version_pick(
        versions,
        "react_major",
        parsed.major,
        source=source,
        confidence=major_confidence or "medium",
        prefer_semver=False,
    )


def _semver_rank(value: object) -> tuple[int, int, int, int, str]:
    """
    Rank a semver-ish string for tie-breaking (when confidence scores are equal).

    Prefer stable releases over canary/rc markers to reduce false positives from unrelated bundles.
    """
    parsed = parse_semver(str(value)) if value is not None else None
    if not parsed:
        return (0, 0, 0, 0, "")

    suffix = str(parsed.suffix or "").lower()
    if not suffix:
        suffix_rank = 3
    elif "canary" in suffix:
        suffix_rank = 2
    elif "rc" in suffix:
        suffix_rank = 0
    else:
        suffix_rank = 1

    return (suffix_rank, parsed.major, parsed.minor, parsed.patch, suffix)


def _prefer_semver(existing: object, candidate: object) -> bool:
    """Return True if candidate should replace existing for equal-confidence version picks."""
    return _semver_rank(candidate) > _semver_rank(existing)


def update_version_pick(
    versions: dict[str, DetectedVersion],
    key: str,
    value: object,
    *,
    source: str | None,
    confidence: str | None,
    prefer_semver: bool = True,
) -> None:
    """Update a version pick in-place when the candidate is stronger."""
    if value is None:
        return
    current = versions.get(key)
    current_confidence = confidence_score(current.confidence if current else None)
    new_confidence = confidence_score(confidence)

    should_set = False
    if current is None:
        should_set = True
    elif new_confidence > current_confidence:
        should_set = True
    elif new_confidence == current_confidence and prefer_semver:
        should_set = _prefer_semver(current.value, value)

    if should_set:
        versions[key] = DetectedVersion(value=value, source=source, confidence=confidence)


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
    """Patterns curated from observed builds for immutable version markers."""

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

    # React bundles often assign the version onto the exported React object, e.g. `r.version="19.1.3"`.
    # This is useful for frameworks (like React Router / Parcel) that don't embed `react@x.y.z` literals.
    #
    # NOTE: Some toolchains may embed unrelated React builds (e.g. Expo CLI vendored assets). Callers
    # should validate/ignore matches based on surrounding context when possible.
    REACT_VERSION_ASSIGN = re.compile(rf'\bversion\s*=\s*"({SEMVER_PATTERN})"')

    # Some toolchains keep the version in a dedicated constant (often from unminified / DEV builds),
    # e.g. `var ReactVersion = '18.3.0-canary-...'` and later `exports.version = ReactVersion`.
    # Next.js dev bundles can embed these sources inside eval'd strings, so allow optionally-escaped quotes.
    REACT_VERSION_CONST = re.compile(rf"\bReactVersion\s*=\s*\\?['\"]({SEMVER_PATTERN})\\?['\"]")


def extract_versions(
    headers: dict[str, str],
    body: str,
    *,
    case_sensitive_body: bool = False,
) -> dict[str, DetectedVersion]:
    versions: dict[str, DetectedVersion] = {}
    # Be defensive: some callers may pass non-normalized header dicts.
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items() if k is not None}
    body = body or ""
    body_lower = None if case_sensitive_body else body.lower()

    def _search(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
        flags = pattern.flags & ~re.IGNORECASE if case_sensitive_body else pattern.flags
        return _compiled_pattern(pattern.pattern, flags).search(text)

    def _finditer(pattern: re.Pattern[str], text: str):
        flags = pattern.flags & ~re.IGNORECASE if case_sensitive_body else pattern.flags
        return _compiled_pattern(pattern.pattern, flags).finditer(text)

    def _maybe_set_version(key: str, value: str, source: str, confidence: str) -> None:
        """Set a version value with source/confidence, preferring stronger confidence."""
        update_version_pick(
            versions,
            key,
            value,
            source=source,
            confidence=confidence,
            prefer_semver=True,
        )

    next_ver = headers.get("x-nextjs-version") or headers.get("x-next-version")
    if next_ver:
        _maybe_set_version("next_version", next_ver, "header", "high")

    waku_ver = headers.get("x-waku-version")
    if waku_ver:
        _maybe_set_version("waku_version", waku_ver, "header", "high")

    rsc_flight_match = _search(VersionPatterns.RSC_FLIGHT_IMPORT, body)
    if rsc_flight_match:
        value = rsc_flight_match.group(1)
        _maybe_set_version("rsc_runtime_version", value, "rsc_flight", "high")
        _maybe_set_version("react_version", value, "rsc_flight", "high")

    rsc_runtime = _search(VersionPatterns.RSC_RUNTIME_PACKAGE, body)
    if rsc_runtime:
        value = rsc_runtime.group(1)
        _maybe_set_version("rsc_runtime_version", value, "rsc_runtime_package", "high")

    if "react_version" not in versions:
        core_react_match = _search(VersionPatterns.CORE_REACT_PACKAGE, body)
        if core_react_match:
            _maybe_set_version("react_version", core_react_match.group(1), "core_package", "high")

    if "react_version" not in versions and versions.get("rsc_runtime_version"):
        rsc_pick = versions.get("rsc_runtime_version")
        if rsc_pick:
            _maybe_set_version(
                "react_version",
                rsc_pick.value,
                "rsc_runtime_package",
                rsc_pick.confidence or "high",
            )

    if "react_version" not in versions:
        react_match = _search(VersionPatterns.REACT_PACKAGE, body)
        if react_match:
            _maybe_set_version("react_version", react_match.group(1), "package_literal", "medium")

    if "react_version" not in versions:
        manifest_match = _search(VersionPatterns.REACT_MANIFEST, body)
        if manifest_match:
            _maybe_set_version("react_version", manifest_match.group(1), "manifest", "medium")

    if "react_version" not in versions:
        plain_match = _search(VersionPatterns.REACT_PLAIN, body)
        if plain_match:
            _maybe_set_version("react_version", plain_match.group(1), "plain_text", "low")

    react_hint_body = body if case_sensitive_body else (body_lower or "")
    if (
        "react_version" not in versions
        and (
            "react/jsx-runtime" in react_hint_body
            or "react-dom" in react_hint_body
            or "react-server-dom" in react_hint_body
            or "react.dev/errors/" in react_hint_body
        )
    ):
        const_match = _search(VersionPatterns.REACT_VERSION_CONST, body)
        if const_match:
            _maybe_set_version("react_version", const_match.group(1), "react_version_const", "medium")

        # Fall back to the React.version string embedded in many bundled React builds.
        #
        # Guardrails:
        # - Only consider React 18+/19+ (older versions aren't relevant to our RSC CVEs).
        # - Ignore known Expo CLI vendored bundles that can embed unrelated canary builds.
        best_candidate: str | None = None
        best_rank: tuple[int, int, int, int] | None = None

        for match in _finditer(VersionPatterns.REACT_VERSION_ASSIGN, body):
            candidate = match.group(1)
            parsed = parse_semver(candidate)
            if not parsed or parsed.major < 18:
                continue

            window = body[max(0, match.start() - 160) : min(len(body), match.end() + 160)]
            window_check = window if case_sensitive_body else window.lower()
            if "canary-full" in window_check or "node_modules/@expo/cli/static" in window_check or "@expo/cli/static" in window_check:
                continue

            suffix = str(parsed.suffix or "").lower()
            if not suffix:
                suffix_rank = 3
            elif "canary" in suffix:
                suffix_rank = 2
            elif "rc" in suffix:
                suffix_rank = 0
            else:
                suffix_rank = 1

            rank = (suffix_rank, parsed.major, parsed.minor, parsed.patch)
            if best_rank is None or rank > best_rank:
                best_rank = rank
                best_candidate = candidate

        if best_candidate:
            _maybe_set_version("react_version", best_candidate, "bundle_assign", "medium")

    if "next_version" not in versions:
        next_literal = _search(VersionPatterns.NEXT_LITERAL, body)
        if next_literal:
            _maybe_set_version("next_version", next_literal.group(1), "package_literal", "medium")

    if "next_version" not in versions:
        next_manifest = _search(VersionPatterns.NEXT_MANIFEST, body)
        if next_manifest:
            _maybe_set_version("next_version", next_manifest.group(1), "manifest", "medium")

    if "next_version" not in versions:
        plain_next = _search(VersionPatterns.NEXT_PLAIN, body)
        if plain_next:
            _maybe_set_version("next_version", plain_next.group(1), "plain_text", "low")

    if "waku_version" not in versions:
        waku_literal = _search(VersionPatterns.WAKU_LITERAL, body)
        if waku_literal:
            _maybe_set_version("waku_version", waku_literal.group(1), "package_literal", "medium")

    if "waku_version" not in versions:
        waku_plain = _search(VersionPatterns.WAKU_PLAIN, body if case_sensitive_body else (body_lower or ""))
        if waku_plain:
            _maybe_set_version("waku_version", waku_plain.group(1), "plain_text", "low")

    rr_match = _search(VersionPatterns.REACT_ROUTER_VERSION, body)
    if rr_match:
        _maybe_set_version("react_router_version", rr_match.group(1), "bundle_literal", "high")

    derive_react_major(versions)

    return versions


def is_react_version_vulnerable(version: str | None) -> bool | None:
    parsed = parse_semver(version)
    if not parsed:
        return None
    if parsed.major != 19:
        return False

    # Note: For CVE-2025-55182, the relevant version is the `react-server-dom-*` runtime that
    # implements `decodeReply()` deserialization. In most deployments this tracks React's semver,
    # and many code paths in this repo store that runtime version under the `react_version` key.

    # React canary builds often include a date suffix, e.g.:
    #   19.3.0-canary-06fcc8f3-20251009
    # The canary date matters: builds released before 2025-12-03 predate the patch.
    suffix = parsed.suffix or ""
    if "canary" in suffix:
        canary_date: int | None = None
        for token in reversed(suffix.split("-")):
            if len(token) == 8 and token.isdigit():
                canary_date = int(token)
                break
        if canary_date is None:
            # Conservative: unknown canary version => assume vulnerable.
            return True
        return canary_date < 20251203

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

