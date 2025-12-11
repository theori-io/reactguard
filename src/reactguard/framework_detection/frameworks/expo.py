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
from ..signals.bundle import probe_js_bundles
from ..signals.rsc import apply_rsc_probe_results


class ExpoDetector(FrameworkDetector):
    name = "expo"
    produces_tags = ["expo", "expo-rsc", "expo-server-actions"]
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
                proxy_profile=context.proxy_profile,
                correlation_id=context.correlation_id,
                http_client=context.http_client,
            )
            if bundle_signals.get("expo_router"):
                signals["expo_router"] = True
            if bundle_signals.get("react_bundle"):
                signals["react_bundle"] = True

        bundle_hit = bundle_signals.get("expo_router")
        is_expo = bool(has_registry or has_hydrate or bundle_hit or has_router_pkg or has_static_assets or has_reset_style)

        if is_expo:
            tags.add("expo")

        if is_expo and context.url:
            rsc_result = apply_rsc_probe_results(
                context.url,
                tags=tags,
                signals=signals,
                proxy_profile=context.proxy_profile,
                correlation_id=context.correlation_id,
                rsc_tag="expo-rsc",
                server_actions_tag="expo-server-actions",
                server_actions_imply_rsc=True,
                set_defaults=True,
                http_client=context.http_client,
            )

            if rsc_result["rsc_endpoint_found"] or rsc_result["server_actions_enabled"]:
                signals["expo_rsc_experimental"] = True

            if rsc_result["server_actions_enabled"]:
                signals["expo_server_actions_experimental"] = True

        if is_expo and not context.url:
            signals.setdefault("server_actions_enabled", False)

    def should_skip(self, tags: TagSet) -> bool:
        return "expo" in tags
