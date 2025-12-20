# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Expo framework detector."""

from typing import Any

from ..base import DetectionContext, DetectionState, FrameworkDetector
from ..constants import (
    EXPO_REGISTRY_PATTERN,
    EXPO_RESET_STYLE_PATTERN,
    EXPO_ROUTER_HYDRATE_PATTERN,
    EXPO_ROUTER_PATTERN,
    EXPO_STATIC_WEB_PATTERN,
)
from ..keys import (
    SIG_INVOCATION_CONFIDENCE,
    SIG_INVOCATION_ENABLED,
    SIG_INVOCATION_ENDPOINTS,
    SIG_EXPO_FLIGHT_SURFACE,
    SIG_EXPO_REGISTRY,
    SIG_EXPO_RESET_STYLE,
    SIG_EXPO_ROUTER,
    SIG_EXPO_ROUTER_PACKAGE,
    SIG_EXPO_RSC_EVIDENCE,
    SIG_EXPO_STATIC_ASSETS,
    SIG_REACT_BUNDLE,
    SIG_REACT_DOM_BUNDLE,
    SIG_REACT_SERVER_DOM_BUNDLE,
    SIG_RSC_ENDPOINT_FOUND,
    TAG_EXPO,
    TAG_EXPO_RSC,
    TAG_EXPO_SERVER_ACTIONS,
    TAG_RSC,
)
from ..signals.bundle import probe_js_bundles, promote_bundle_versions
from ..signals.expo_server_functions import probe_expo_server_functions


class ExpoDetector(FrameworkDetector):
    name = "expo"
    produces_tags = [TAG_EXPO, TAG_EXPO_RSC, TAG_EXPO_SERVER_ACTIONS, TAG_RSC]
    priority = 25

    def detect(
        self,
        body: str,
        headers: dict[str, str],
        state: DetectionState,
        context: DetectionContext,
    ) -> None:
        tags = state.tags
        signals = state.signals
        has_registry = bool(EXPO_REGISTRY_PATTERN.search(body))
        has_hydrate = bool(EXPO_ROUTER_HYDRATE_PATTERN.search(body))
        has_router_pkg = bool(EXPO_ROUTER_PATTERN.search(body))
        has_static_assets = bool(EXPO_STATIC_WEB_PATTERN.search(body))
        has_reset_style = bool(EXPO_RESET_STYLE_PATTERN.search(body))

        if has_registry:
            signals[SIG_EXPO_REGISTRY] = True
        if has_hydrate:
            signals[SIG_EXPO_ROUTER] = True
        if has_router_pkg:
            signals[SIG_EXPO_ROUTER_PACKAGE] = True
        if has_static_assets:
            signals[SIG_EXPO_STATIC_ASSETS] = True
        if has_reset_style:
            signals[SIG_EXPO_RESET_STYLE] = True

        bundle_signals: dict[str, Any] = {}
        if context.url:
            bundle_signals = probe_js_bundles(
                context.url,
                body,
            )
            if bundle_signals.get(SIG_EXPO_ROUTER):
                signals[SIG_EXPO_ROUTER] = True
            if bundle_signals.get(SIG_REACT_BUNDLE):
                signals[SIG_REACT_BUNDLE] = True
            if bundle_signals.get(SIG_REACT_DOM_BUNDLE):
                signals[SIG_REACT_DOM_BUNDLE] = True
            if bundle_signals.get(SIG_REACT_SERVER_DOM_BUNDLE):
                signals[SIG_REACT_SERVER_DOM_BUNDLE] = True

            promote_bundle_versions(
                signals,
                bundle_signals,
                keys=("react_version", "react_major", "rsc_runtime_version"),
            )

        bundle_hit = bundle_signals.get(SIG_EXPO_ROUTER)
        is_expo = bool(has_registry or has_hydrate or bundle_hit or has_router_pkg or has_static_assets or has_reset_style)

        if is_expo:
            tags.add(TAG_EXPO)
            if context.url and signals.get(SIG_INVOCATION_ENABLED) is None:
                probe = probe_expo_server_functions(context.url)

                if probe.has_rsc_surface:
                    tags.add(TAG_EXPO_RSC)
                    tags.add(TAG_RSC)
                    signals[SIG_RSC_ENDPOINT_FOUND] = True
                    signals[SIG_EXPO_FLIGHT_SURFACE] = True

                if probe.invocation_endpoints:
                    tags.add(TAG_EXPO_SERVER_ACTIONS)
                    signals[SIG_INVOCATION_ENABLED] = True
                    signals[SIG_INVOCATION_ENDPOINTS] = list(probe.invocation_endpoints)
                    signals.setdefault(SIG_INVOCATION_CONFIDENCE, "medium")
                else:
                    # We have an Expo Router surface but did not discover a concrete action endpoint.
                    # Treat this as "unknown" rather than a confident negative.
                    signals.setdefault(SIG_INVOCATION_ENABLED, None)
                    signals.setdefault(SIG_INVOCATION_CONFIDENCE, "none")
                if probe.evidence:
                    signals[SIG_EXPO_RSC_EVIDENCE] = dict(probe.evidence)

    def should_skip(self, state: DetectionState) -> bool:
        return TAG_EXPO in state.tags
