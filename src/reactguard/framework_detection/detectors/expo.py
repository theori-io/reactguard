# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Expo framework detector."""

from typing import Any

from ...utils import TagSet
from ..base import DetectionContext, FrameworkDetector
from ..constants import (
    EXPO_REGISTRY_PATTERN,
    EXPO_RESET_STYLE_PATTERN,
    EXPO_ROUTER_HYDRATE_PATTERN,
    EXPO_ROUTER_PATTERN,
    EXPO_STATIC_WEB_PATTERN,
)
from ..keys import (
    SIG_REACT_BUNDLE,
    SIG_REACT_DOM_BUNDLE,
    SIG_REACT_SERVER_DOM_BUNDLE,
    SIG_RSC_ENDPOINT_FOUND,
    SIG_SERVER_ACTION_ENDPOINTS,
    SIG_SERVER_ACTIONS_CONFIDENCE,
    SIG_SERVER_ACTIONS_ENABLED,
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
        tags: TagSet,
        signals: dict[str, Any],
        context: DetectionContext,
    ) -> None:
        has_registry = bool(EXPO_REGISTRY_PATTERN.search(body))
        has_hydrate = bool(EXPO_ROUTER_HYDRATE_PATTERN.search(body))
        has_router_pkg = bool(EXPO_ROUTER_PATTERN.search(body))
        has_static_assets = bool(EXPO_STATIC_WEB_PATTERN.search(body))
        has_reset_style = bool(EXPO_RESET_STYLE_PATTERN.search(body))

        if has_registry:
            signals["expo_registry"] = True
        if has_hydrate:
            signals["expo_router"] = True
        if has_router_pkg:
            signals["expo_router_package"] = True
        if has_static_assets:
            signals["expo_static_assets"] = True
        if has_reset_style:
            signals["expo_reset_style"] = True

        bundle_signals: dict[str, Any] = {}
        if context.url:
            bundle_signals = probe_js_bundles(
                context.url,
                body,
            )
            if bundle_signals.get("expo_router"):
                signals["expo_router"] = True
            if bundle_signals.get("react_bundle"):
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

        bundle_hit = bundle_signals.get("expo_router")
        is_expo = bool(has_registry or has_hydrate or bundle_hit or has_router_pkg or has_static_assets or has_reset_style)

        if is_expo:
            tags.add(TAG_EXPO)
            if context.url and signals.get(SIG_SERVER_ACTIONS_ENABLED) is None:
                probe = probe_expo_server_functions(context.url)

                if probe.has_rsc_surface:
                    tags.add(TAG_EXPO_RSC)
                    tags.add(TAG_RSC)
                    signals[SIG_RSC_ENDPOINT_FOUND] = True
                    signals["expo_flight_surface"] = True

                if probe.server_action_endpoints:
                    tags.add(TAG_EXPO_SERVER_ACTIONS)
                    signals[SIG_SERVER_ACTIONS_ENABLED] = True
                    signals[SIG_SERVER_ACTION_ENDPOINTS] = list(probe.server_action_endpoints)
                    signals.setdefault(SIG_SERVER_ACTIONS_CONFIDENCE, "medium")
                else:
                    # We have an Expo Router surface but did not discover a concrete action endpoint.
                    # Treat this as "unknown" rather than a confident negative.
                    signals.setdefault(SIG_SERVER_ACTIONS_ENABLED, None)
                    signals.setdefault(SIG_SERVER_ACTIONS_CONFIDENCE, "none")
                if probe.evidence:
                    signals["expo_rsc_evidence"] = dict(probe.evidence)

    def should_skip(self, tags: TagSet) -> bool:
        return TAG_EXPO in tags
