# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dataclasses for vulnerability and scan reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .poc import PocStatus
from .scan import FrameworkDetectionResult


def _normalize_confidence_label(value: Any) -> str:
    """
    External contract: only ``low | medium | high``.

    Treat ``none``/unknown/empty as ``low``.
    """
    raw = str(value or "").strip().lower()
    if raw == "high":
        return "high"
    if raw in {"med", "medium"}:
        return "medium"
    if raw == "low":
        return "low"
    return "low"


def _normalize_confidence_fields(value: Any) -> Any:
    """
    Recursively normalize *confidence-like* fields inside mappings/lists.

    Any key containing the substring "confidence" is treated as a confidence label when its
    value is a string or None, and normalized to ``low | medium | high``.
    """
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            inner = _normalize_confidence_fields(item)
            if isinstance(key, str) and "confidence" in key.lower() and (inner is None or isinstance(inner, str)):
                normalized[key] = _normalize_confidence_label(inner)
            else:
                normalized[key] = inner
        return normalized
    if isinstance(value, list):
        return [_normalize_confidence_fields(item) for item in value]
    return value


def _apply_verdict_invariants(status: PocStatus, details: dict[str, Any]) -> PocStatus:
    # Require "VULNERABLE" to be backed by high confidence; otherwise downgrade.
    confidence = details.get("confidence")
    if status == PocStatus.VULNERABLE and confidence != "high":
        return PocStatus.LIKELY_VULNERABLE
    return status


@dataclass
class VulnerabilityReport:
    """Normalized PoC result wrapper."""

    status: PocStatus
    details: dict[str, Any] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like access for backwards compatibility."""
        if key == "status":
            return self.status
        if key == "details":
            return self.details
        if key == "raw_data":
            return self.raw_data
        return default

    def __getitem__(self, key: str) -> Any:
        value = self.get(key, default=None)
        if value is None and key not in {"status", "details", "raw_data"}:
            raise KeyError(key)
        return value

    def __setitem__(self, key: str, value: Any) -> None:
        if key == "status":
            self.status = value
            return
        if key == "details":
            self.details = value
            return
        if key == "raw_data":
            self.raw_data = value
            return
        raise KeyError(key)

    def to_dict(self) -> dict[str, Any]:
        details = _normalize_confidence_fields(dict(self.details or {}))
        raw_data = _normalize_confidence_fields(dict(self.raw_data or {}))
        status = _apply_verdict_invariants(self.status, details) if isinstance(self.status, PocStatus) else self.status
        return {
            "status": status,
            "details": details,
            "raw_data": raw_data,
        }

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> VulnerabilityReport:
        status_val = data.get("status")
        try:
            status = PocStatus(status_val) if status_val is not None else PocStatus.INCONCLUSIVE
        except Exception:
            status = PocStatus.INCONCLUSIVE
        return cls(
            status=status,
            details=dict(data.get("details") or {}),
            raw_data=dict(data.get("raw_data") or {}),
        )


@dataclass
class ScanReport:
    """Combined framework + vulnerability report."""

    status: PocStatus
    framework_detection: FrameworkDetectionResult
    vulnerability_detection: VulnerabilityReport
    vulnerability_detections: list[VulnerabilityReport] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Keep the "primary" field consistent when callers provide an explicit list.
        if self.vulnerability_detections:
            self.vulnerability_detection = self.vulnerability_detections[0]

    @property
    def findings(self) -> list[VulnerabilityReport]:
        """Return all vulnerability findings, falling back to the primary finding."""
        return self.vulnerability_detections or [self.vulnerability_detection]

    @staticmethod
    def _aggregate_status(reports: list[VulnerabilityReport]) -> PocStatus:
        """
        Compute an overall scan status across multiple CVE results.

        Ordering is intentionally conservative: any confirmed vulnerability dominates; otherwise any inconclusive
        result dominates; otherwise fall back to the strongest "not vulnerable" style result available.
        """
        if any(r.status == PocStatus.VULNERABLE for r in reports):
            return PocStatus.VULNERABLE
        if any(r.status == PocStatus.LIKELY_VULNERABLE for r in reports):
            return PocStatus.LIKELY_VULNERABLE
        if any(r.status == PocStatus.INCONCLUSIVE for r in reports):
            return PocStatus.INCONCLUSIVE
        if any(r.status == PocStatus.LIKELY_NOT_VULNERABLE for r in reports):
            return PocStatus.LIKELY_NOT_VULNERABLE
        if any(r.status == PocStatus.NOT_VULNERABLE for r in reports):
            return PocStatus.NOT_VULNERABLE
        return PocStatus.NOT_APPLICABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "framework_detection": {
                "tags": self.framework_detection.tags,
                "signals": _normalize_confidence_fields(dict(self.framework_detection.signals or {})),
            },
            "vulnerability_detection": self.vulnerability_detection.to_dict(),
            "vulnerability_detections": [v.to_dict() for v in self.vulnerability_detections],
        }

    def __contains__(self, item: str) -> bool:
        return item in self.to_dict()

    @classmethod
    def from_parts(
        cls,
        detection: FrameworkDetectionResult,
        vulnerability: VulnerabilityReport | dict[str, Any] | list[VulnerabilityReport] | list[dict[str, Any]],
    ) -> ScanReport:
        if isinstance(vulnerability, list):
            vuln_reports: list[VulnerabilityReport] = [v if isinstance(v, VulnerabilityReport) else VulnerabilityReport.from_mapping(v) for v in vulnerability]
        else:
            vuln_reports = [vulnerability if isinstance(vulnerability, VulnerabilityReport) else VulnerabilityReport.from_mapping(vulnerability)]

        if not vuln_reports:
            tags = detection.tags or []
            reason = "No applicable CVE detectors for detected framework tags"
            if tags:
                reason = f"{reason}: {', '.join(tags)}"
            primary = VulnerabilityReport(status=PocStatus.NOT_APPLICABLE, details={"reason": reason})
            return cls(
                status=PocStatus.NOT_APPLICABLE,
                framework_detection=detection,
                vulnerability_detection=primary,
                vulnerability_detections=[],
            )

        primary = vuln_reports[0]
        overall = cls._aggregate_status(vuln_reports)
        return cls(
            status=overall,
            framework_detection=detection,
            vulnerability_detection=primary,
            vulnerability_detections=vuln_reports,
        )


__all__ = ["VulnerabilityReport", "ScanReport"]
