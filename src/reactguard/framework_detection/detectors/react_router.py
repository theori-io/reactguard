# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""React Router detector."""

from typing import Any

from ...utils import flatten_version_map, normalize_version_map
from ...utils.version import update_version_pick
from ..base import DetectionContext, DetectionState, FrameworkDetector
from ..constants import (
    REMIX_CONTEXT_PATTERN,
    RR_CONTEXT_PATTERN,
    RR_MANIFEST_PATTERN,
    RR_VERSION_PATTERN,
)
from ..keys import (
    SIG_INVOCATION_CONFIDENCE,
    SIG_INVOCATION_ENABLED,
    SIG_INVOCATION_ENDPOINTS,
    SIG_RSC_ENDPOINT_FOUND,
    SIG_REACT_ROUTER_CONFIDENCE,
    SIG_REACT_ROUTER_MANIFEST,
    SIG_REACT_ROUTER_SERVER_ACTION_IDS,
    SIG_REACT_ROUTER_VERSION,
    SIG_REACT_ROUTER_V5,
    SIG_REACT_ROUTER_V6,
    SIG_REACT_ROUTER_V7,
    SIG_REMIX_HERITAGE,
    SIG_DETECTED_VERSIONS,
    SIG_REACT_ROUTER_V5_BUNDLE,
    SIG_REACT_ROUTER_V6_BUNDLE,
    SIG_REACT_ROUTER_V7_BUNDLE,
    TAG_REACT_ROUTER_V5,
    TAG_REACT_ROUTER_V6,
    TAG_REACT_ROUTER_V7,
    TAG_REACT_ROUTER_V7_RSC,
    TAG_REACT_ROUTER_V7_SERVER_ACTIONS,
)
from ..signals.bundle import probe_js_bundles, promote_bundle_versions
from ..signals.react_router_server_functions import discover_react_router_server_functions


class ReactRouterDetector(FrameworkDetector):
    name = "react_router"
    produces_tags = [
        TAG_REACT_ROUTER_V5,
        TAG_REACT_ROUTER_V6,
        TAG_REACT_ROUTER_V7,
        TAG_REACT_ROUTER_V7_RSC,
        TAG_REACT_ROUTER_V7_SERVER_ACTIONS,
    ]
    priority = 20

    def detect(
        self,
        body: str,
        headers: dict[str, str],
        state: DetectionState,
        context: DetectionContext,
    ) -> None:
        tags = state.tags
        signals = state.signals
        detected_version = None
        confidence = "low"

        has_v7_manifest = bool(RR_MANIFEST_PATTERN.search(body))
        has_v7_context = bool(RR_CONTEXT_PATTERN.search(body))
        has_remix_heritage = bool(REMIX_CONTEXT_PATTERN.search(body))

        if has_v7_manifest or has_v7_context:
            signals[SIG_REACT_ROUTER_MANIFEST] = True
            detected_version = "v7"
            confidence = "high"

        if has_remix_heritage:
            signals[SIG_REMIX_HERITAGE] = True
            detected_version = "v7"
            confidence = "high"

        version_match = RR_VERSION_PATTERN.search(body)
        if version_match:
            version_str = version_match.group(1)
            signals[SIG_REACT_ROUTER_VERSION] = True
            detected_versions = normalize_version_map(signals.get(SIG_DETECTED_VERSIONS))
            update_version_pick(
                detected_versions,
                "react_router_version",
                version_str,
                source="html_literal",
                confidence="high",
                prefer_semver=True,
            )
            signals[SIG_DETECTED_VERSIONS] = {key: pick.to_mapping() for key, pick in detected_versions.items()}
            signals.update(flatten_version_map(detected_versions, prefix="detected_"))

            try:
                major = int(version_str.split(".")[0])
                if major == 7:
                    detected_version = "v7"
                    confidence = "high"
                elif major == 6:
                    detected_version = "v6"
                    confidence = "high"
                elif major == 5:
                    detected_version = "v5"
                    confidence = "high"
            except (ValueError, IndexError):
                pass

        detected_versions = normalize_version_map(signals.get(SIG_DETECTED_VERSIONS))
        needs_bundle_versions = bool(
            context.url
            and (
                detected_versions.get("react_version") is None
                or detected_versions.get("react_major") is None
                or detected_versions.get("react_router_version") is None
            )
        )

        if context.url and (confidence != "high" or needs_bundle_versions):
            bundle_signals = probe_js_bundles(
                context.url,
                body,
            )
            signals.update(bundle_signals)

            promote_bundle_versions(
                signals,
                bundle_signals,
                keys=("react_version", "react_major", "react_router_version", "rsc_runtime_version"),
            )

            if confidence != "high":
                if bundle_signals.get(SIG_REACT_ROUTER_V7_BUNDLE):
                    detected_version = "v7"
                    confidence = "medium"
                elif bundle_signals.get(SIG_REACT_ROUTER_V6_BUNDLE):
                    detected_version = "v6"
                    confidence = "medium"
                elif bundle_signals.get(SIG_REACT_ROUTER_V5_BUNDLE):
                    detected_version = "v5"
                    confidence = "medium"

        # React Router Server Functions are v7-only. When present, action IDs are embedded in HTML
        # as `$ACTION_ID_<id>` hidden inputs, which is a strong v7 signal even when bundle-based
        # heuristics misclassify the major.
        if context.url and signals.get(SIG_INVOCATION_ENABLED) is None:
            should_try_actions = detected_version == "v7" or "$ACTION_ID_" in body
            if should_try_actions:
                discovery = discover_react_router_server_functions(body, context.url)
                if discovery.action_ids:
                    detected_version = "v7"
                    confidence = "high"
                    tags.add(TAG_REACT_ROUTER_V7_RSC)
                    tags.add(TAG_REACT_ROUTER_V7_SERVER_ACTIONS)
                    signals[SIG_RSC_ENDPOINT_FOUND] = True
                    signals[SIG_INVOCATION_ENABLED] = True
                    signals[SIG_INVOCATION_CONFIDENCE] = "medium"
                    signals[SIG_REACT_ROUTER_SERVER_ACTION_IDS] = list(discovery.action_ids)
                    if discovery.action_endpoints:
                        signals[SIG_INVOCATION_ENDPOINTS] = list(discovery.action_endpoints)
                        signals[SIG_INVOCATION_CONFIDENCE] = "high"

        if detected_version == "v7":
            tags.add(TAG_REACT_ROUTER_V7)
            signals[SIG_REACT_ROUTER_V7] = True
        elif detected_version == "v6":
            tags.add(TAG_REACT_ROUTER_V6)
            signals[SIG_REACT_ROUTER_V6] = True
        elif detected_version == "v5":
            tags.add(TAG_REACT_ROUTER_V5)
            signals[SIG_REACT_ROUTER_V5] = True

        if detected_version:
            signals[SIG_REACT_ROUTER_CONFIDENCE] = confidence
