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

"""Confidence scoring for framework detection."""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent / "confidence_config.json"


def _load_config() -> dict[str, Any] | None:
    if not CONFIG_PATH.exists():
        return None
    try:
        return json.loads(CONFIG_PATH.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load confidence config: %s", exc)
        return None


_config = _load_config()

# Default weights derived from lab container observations; confidence_config.json
# can override these for experimentation without code changes.
_DEFAULT_STRONG_SIGNAL_WEIGHTS: dict[str, int] = {
    # Next.js
    "nextjs_hydration_array": 25,
    "nextjs_data_script": 15,
    "nextjs_static_paths": 12,
    "nextjs_chunk_pattern": 10,
    "nextjs_manifest": 10,
    # RSC
    "rsc_content_type": 30,
    "rsc_flight_payload": 22,
    # Waku
    "waku_root": 24,
    "waku_header": 18,
    "waku_meta_generator": 26,
    # React Router
    "react_router_manifest": 16,
    "react_router_version": 14,
    "react_router_v7_bundle": 14,
    "react_router_v6_bundle": 12,
    "react_router_v5_bundle": 10,
    # Expo
    "expo_router": 14,
    # Attack surface
    "server_actions_enabled": 8,
}

_DEFAULT_SUPPORTING_SIGNAL_WEIGHTS: dict[str, int] = {
    "header_powered_by_nextjs": 6,
    "vite_assets": 4,
    "vite_modulepreload_assets": 6,
    "react_spa_structure": 4,
    "react_streaming_markers": 6,
}

STRONG_SIGNAL_WEIGHTS = _config.get("strong_signal_weights", _DEFAULT_STRONG_SIGNAL_WEIGHTS) if _config else _DEFAULT_STRONG_SIGNAL_WEIGHTS
SUPPORTING_SIGNAL_WEIGHTS = _config.get("supporting_signal_weights", _DEFAULT_SUPPORTING_SIGNAL_WEIGHTS) if _config else _DEFAULT_SUPPORTING_SIGNAL_WEIGHTS


def score_confidence(signals: dict[str, Any]) -> tuple[int, str, dict[str, Any]]:
    score = 0
    strong_hits: list[str] = []
    supporting_hits: list[str] = []

    for signal_name, weight in STRONG_SIGNAL_WEIGHTS.items():
        if signals.get(signal_name):
            score += weight
            strong_hits.append(signal_name)

    for signal_name, weight in SUPPORTING_SIGNAL_WEIGHTS.items():
        if signals.get(signal_name):
            score += weight
            supporting_hits.append(signal_name)

    router_confidence = str(signals.get("react_router_confidence") or "").lower()
    router_bonus = {"high": 10, "medium": 6, "low": 3}.get(router_confidence, 0)
    score += router_bonus

    if len(strong_hits) > 1:
        score += min((len(strong_hits) - 1) * 3, 9)

    penalties: list[str] = []

    has_strong = bool(strong_hits)
    has_only_mutable = not has_strong and supporting_hits and all(sig in {"header_powered_by_nextjs", "vite_assets"} for sig in supporting_hits)

    if has_only_mutable:
        penalties.append("mutable_signals_only")
        score -= 10

    if has_strong:
        score = min(score, 100)
    else:
        score = min(score, 50)

    if score >= 75:
        level = "high"
    elif score >= 45:
        level = "medium"
    else:
        level = "low"

    breakdown = {
        "strong_hits": strong_hits,
        "supporting_hits": supporting_hits,
        "router_bonus": router_bonus,
        "penalties": penalties,
    }

    return score, level, breakdown
