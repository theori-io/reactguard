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
from ..keys import SIG_REACT_BUNDLE, SIG_REACT_DOM_BUNDLE, SIG_REACT_SERVER_DOM_BUNDLE, TAG_EXPO, TAG_EXPO_RSC, TAG_EXPO_SERVER_ACTIONS
from ..signals.bundle import probe_js_bundles
from ..signals.rsc import apply_rsc_probe_results


class ExpoDetector(FrameworkDetector):
    name = "expo"
    produces_tags = [TAG_EXPO, TAG_EXPO_RSC, TAG_EXPO_SERVER_ACTIONS]
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

        bundle_hit = bundle_signals.get("expo_router")
        is_expo = bool(has_registry or has_hydrate or bundle_hit or has_router_pkg or has_static_assets or has_reset_style)

        if is_expo:
            tags.add(TAG_EXPO)

        if is_expo and context.url:
            rsc_result = apply_rsc_probe_results(
                context.url,
                tags=tags,
                signals=signals,
                rsc_tag=TAG_EXPO_RSC,
                server_actions_tag=TAG_EXPO_SERVER_ACTIONS,
                server_actions_imply_rsc=True,
                set_defaults=True,
            )

            if rsc_result["rsc_endpoint_found"] or rsc_result["server_actions_enabled"]:
                signals["expo_rsc_experimental"] = True

            if rsc_result["server_actions_enabled"]:
                signals["expo_server_actions_experimental"] = True

    def should_skip(self, tags: TagSet) -> bool:
        return TAG_EXPO in tags
