# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dataclasses for vulnerability and scan reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from .poc import PocStatus
from .scan import FrameworkDetectionResult


ExternalConfidence = Literal["low", "medium", "high"]
EvidenceClass = Literal["STRONG_POS", "WEAK_POS", "STRONG_NEG", "WEAK_NEG", "CONTRADICTORY", "NONE"]


def normalize_confidence(value: Any) -> ExternalConfidence:
    """
    External contract: only ``low | medium | high``.

    Treat ``none``/unknown/empty as ``low``.
    """
    raw = str(value or "").strip().lower()
    if raw == "high":
        return "high"
    if raw in {"med", "medium"}:
        return "medium"
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
                normalized[key] = normalize_confidence(inner)
            else:
                normalized[key] = inner
        return normalized
    if isinstance(value, list):
        return [_normalize_confidence_fields(item) for item in value]
    return value


def apply_verdict_invariants(status: PocStatus, details: dict[str, Any]) -> PocStatus:
    # Require definitive verdicts to be backed by matching confidence tiers.
    confidence = normalize_confidence(details.get("confidence"))
    if status == PocStatus.VULNERABLE:
        if confidence == "medium":
            return PocStatus.LIKELY_VULNERABLE
        if confidence == "low":
            return PocStatus.INCONCLUSIVE
    if status == PocStatus.NOT_VULNERABLE:
        if confidence == "medium":
            return PocStatus.LIKELY_NOT_VULNERABLE
        if confidence == "low":
            return PocStatus.INCONCLUSIVE
    if status == PocStatus.NOT_APPLICABLE:
        if confidence != "high":
            return PocStatus.INCONCLUSIVE
    if status in {PocStatus.LIKELY_VULNERABLE, PocStatus.LIKELY_NOT_VULNERABLE} and confidence == "low":
        return PocStatus.INCONCLUSIVE
    return status


@dataclass(frozen=True)
class DecisionInputs:
    transport_ok: bool
    precondition_confident_false: bool
    evidence_class: EvidenceClass
    expected_surface: bool
    decode_surface_reached: bool | None
    coverage_multi: bool
    has_comparable_baseline: bool = True


def decide_verdict(inputs: DecisionInputs) -> tuple[PocStatus, ExternalConfidence]:
    """Shared decision table for verdict+confidence normalization."""
    if not inputs.transport_ok:
        return (PocStatus.INCONCLUSIVE, "low")

    if inputs.precondition_confident_false:
        return (PocStatus.NOT_APPLICABLE, "high")

    if inputs.evidence_class == "CONTRADICTORY":
        confidence: ExternalConfidence = "high" if inputs.coverage_multi else "medium"
        return (PocStatus.INCONCLUSIVE, confidence)

    if inputs.evidence_class == "STRONG_POS" and inputs.decode_surface_reached is True:
        return (PocStatus.VULNERABLE, "high")

    if inputs.evidence_class == "WEAK_POS" and inputs.decode_surface_reached is True:
        confidence = "high" if inputs.coverage_multi else "medium"
        return (PocStatus.LIKELY_VULNERABLE, confidence)

    if inputs.evidence_class == "STRONG_NEG" and inputs.decode_surface_reached is True:
        return (PocStatus.NOT_VULNERABLE, "high")

    if inputs.evidence_class == "WEAK_NEG" and inputs.decode_surface_reached is True:
        return (PocStatus.LIKELY_NOT_VULNERABLE, "medium")

    # No usable directional signal.
    if inputs.expected_surface:
        confidence = "medium" if inputs.coverage_multi else "low"
        return (PocStatus.INCONCLUSIVE, confidence)

    # Missing surface / not observed surface (maps to NOT_VULNERABLE by contract).
    confidence = "medium" if inputs.coverage_multi else "low"
    return (PocStatus.NOT_VULNERABLE, confidence)


def normalize_report_mapping(report: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize a mapping-style report (status/details/raw_data) to match external contract.
    """
    if not isinstance(report, dict):
        return report
    status = report.get("status")
    details = report.get("details")
    if isinstance(details, dict):
        details_conf = normalize_confidence(details.get("confidence"))
        details["confidence"] = details_conf
        if isinstance(status, PocStatus):
            report["status"] = apply_verdict_invariants(status, details)
    return report


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
        status = apply_verdict_invariants(self.status, details) if isinstance(self.status, PocStatus) else self.status
        return {
            "status": status,
            "details": details,
            "raw_data": raw_data,
        }

    def normalized_status(self) -> PocStatus | Any:
        """Return a verdict normalized by confidence invariants."""
        if not isinstance(self.status, PocStatus):
            return self.status
        details = dict(self.details or {})
        details["confidence"] = normalize_confidence(details.get("confidence"))
        return apply_verdict_invariants(self.status, details)

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
        normalized = [r.normalized_status() for r in reports]
        if any(status == PocStatus.VULNERABLE for status in normalized):
            return PocStatus.VULNERABLE
        if any(status == PocStatus.LIKELY_VULNERABLE for status in normalized):
            return PocStatus.LIKELY_VULNERABLE
        if any(status == PocStatus.INCONCLUSIVE for status in normalized):
            return PocStatus.INCONCLUSIVE
        if any(status == PocStatus.LIKELY_NOT_VULNERABLE for status in normalized):
            return PocStatus.LIKELY_NOT_VULNERABLE
        if any(status == PocStatus.NOT_VULNERABLE for status in normalized):
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


__all__ = [
    "DecisionInputs",
    "EvidenceClass",
    "ExternalConfidence",
    "ScanReport",
    "VulnerabilityReport",
    "apply_verdict_invariants",
    "decide_verdict",
    "normalize_confidence",
    "normalize_report_mapping",
]
