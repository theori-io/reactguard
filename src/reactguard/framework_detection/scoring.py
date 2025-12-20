# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Confidence scoring for framework detection."""

from typing import Any

from .keys import (
    SIG_EXPO_REGISTRY,
    SIG_EXPO_ROUTER,
    SIG_HEADER_POWERED_BY_NEXTJS,
    SIG_INVOCATION_ENABLED,
    SIG_NEXTJS_CHUNK_PATTERN,
    SIG_NEXTJS_DATA_SCRIPT,
    SIG_NEXTJS_HYDRATION_ARRAY,
    SIG_NEXTJS_MANIFEST,
    SIG_NEXTJS_STATIC_PATHS,
    SIG_REACT_ROUTER_CONFIDENCE,
    SIG_REACT_ROUTER_MANIFEST,
    SIG_REACT_ROUTER_VERSION,
    SIG_REACT_ROUTER_V5_BUNDLE,
    SIG_REACT_ROUTER_V6_BUNDLE,
    SIG_REACT_ROUTER_V7_BUNDLE,
    SIG_REACT_SPA_STRUCTURE,
    SIG_REACT_STREAMING_MARKERS,
    SIG_RSC_CONTENT_TYPE,
    SIG_RSC_FLIGHT_PAYLOAD,
    SIG_VITE_ASSETS,
    SIG_VITE_MODULEPRELOAD_ASSETS,
    SIG_WAKU_HEADER,
    SIG_WAKU_LEGACY_ARCHITECTURE,
    SIG_WAKU_META_GENERATOR,
    SIG_WAKU_MINIMAL_HTML,
    SIG_WAKU_MODULE_CACHE,
    SIG_WAKU_ROOT,
    SIG_WAKU_RSC_SURFACE,
    SIG_WAKU_VARS,
)

# Default weights derived from lab container observations; confidence_config.json
# can override these for experimentation without code changes.
STRONG_SIGNAL_WEIGHTS: dict[str, int] = {
    # Next.js
    SIG_NEXTJS_HYDRATION_ARRAY: 25,
    SIG_NEXTJS_DATA_SCRIPT: 15,
    SIG_NEXTJS_STATIC_PATHS: 12,
    SIG_NEXTJS_CHUNK_PATTERN: 10,
    SIG_NEXTJS_MANIFEST: 10,
    # RSC
    SIG_RSC_CONTENT_TYPE: 30,
    SIG_RSC_FLIGHT_PAYLOAD: 22,
    # Waku
    SIG_WAKU_ROOT: 24,
    SIG_WAKU_HEADER: 18,
    SIG_WAKU_META_GENERATOR: 26,
    # Some older Waku variants (0.17-0.20 in our lab) do not expose the meta generator or version header,
    # but still have stable Waku-specific globals and bootstrapping markers.
    SIG_WAKU_VARS: 14,
    SIG_WAKU_MODULE_CACHE: 12,
    SIG_WAKU_LEGACY_ARCHITECTURE: 20,
    SIG_WAKU_RSC_SURFACE: 10,
    # Newer Waku builds sometimes serve an ultra-minimal HTML shell and require fetching a module script
    # to reveal Waku globals; treat that probe as a strong signal when it hits.
    SIG_WAKU_MINIMAL_HTML: 18,
    # React Router
    SIG_REACT_ROUTER_MANIFEST: 16,
    SIG_REACT_ROUTER_VERSION: 14,
    SIG_REACT_ROUTER_V7_BUNDLE: 14,
    SIG_REACT_ROUTER_V6_BUNDLE: 12,
    SIG_REACT_ROUTER_V5_BUNDLE: 10,
    # Expo
    SIG_EXPO_ROUTER: 14,
    SIG_EXPO_REGISTRY: 18,
    # Attack surface
    SIG_INVOCATION_ENABLED: 8,
}

SUPPORTING_SIGNAL_WEIGHTS: dict[str, int] = {
    SIG_HEADER_POWERED_BY_NEXTJS: 6,
    SIG_VITE_ASSETS: 4,
    SIG_VITE_MODULEPRELOAD_ASSETS: 6,
    SIG_REACT_SPA_STRUCTURE: 4,
    SIG_REACT_STREAMING_MARKERS: 6,
}


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

    router_confidence = str(signals.get(SIG_REACT_ROUTER_CONFIDENCE) or "").lower()
    router_bonus = {"high": 10, "medium": 6, "low": 3}.get(router_confidence, 0)
    score += router_bonus

    if len(strong_hits) > 1:
        score += min((len(strong_hits) - 1) * 3, 9)

    penalties: list[str] = []

    has_strong = bool(strong_hits)
    has_only_mutable = not has_strong and supporting_hits and all(
        sig in {SIG_HEADER_POWERED_BY_NEXTJS, SIG_VITE_ASSETS} for sig in supporting_hits
    )

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
