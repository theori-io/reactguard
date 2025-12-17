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

"""React Router detector."""

from typing import Any

from ...utils import TagSet
from ..base import DetectionContext, FrameworkDetector
from ..constants import (
    REMIX_CONTEXT_PATTERN,
    RR_CONTEXT_PATTERN,
    RR_MANIFEST_PATTERN,
    RR_VERSION_PATTERN,
)
from ..keys import (
    SIG_RSC_ENDPOINT_FOUND,
    SIG_SERVER_ACTION_ENDPOINTS,
    SIG_SERVER_ACTIONS_CONFIDENCE,
    SIG_SERVER_ACTIONS_ENABLED,
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
        tags: TagSet,
        signals: dict[str, Any],
        context: DetectionContext,
    ) -> None:
        detected_version = None
        confidence = "low"

        has_v7_manifest = bool(RR_MANIFEST_PATTERN.search(body))
        has_v7_context = bool(RR_CONTEXT_PATTERN.search(body))
        has_remix_heritage = bool(REMIX_CONTEXT_PATTERN.search(body))

        if has_v7_manifest or has_v7_context:
            signals["react_router_manifest"] = True
            detected_version = "v7"
            confidence = "high"

        if has_remix_heritage:
            signals["remix_heritage"] = True
            detected_version = "v7"
            confidence = "high"

        version_match = RR_VERSION_PATTERN.search(body)
        if version_match:
            version_str = version_match.group(1)
            signals["react_router_version"] = True
            signals["detected_react_router_version"] = version_str

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

        needs_bundle_versions = bool(
            context.url and (signals.get("detected_react_version") is None or signals.get("detected_react_major") is None or signals.get("detected_react_router_version") is None)
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
                if bundle_signals.get("react_router_v7_bundle"):
                    detected_version = "v7"
                    confidence = "medium"
                elif bundle_signals.get("react_router_v6_bundle"):
                    detected_version = "v6"
                    confidence = "medium"
                elif bundle_signals.get("react_router_v5_bundle"):
                    detected_version = "v5"
                    confidence = "medium"

        # React Router Server Functions are v7-only. When present, action IDs are embedded in HTML
        # as `$ACTION_ID_<id>` hidden inputs, which is a strong v7 signal even when bundle-based
        # heuristics misclassify the major.
        if context.url and signals.get(SIG_SERVER_ACTIONS_ENABLED) is None:
            should_try_actions = detected_version == "v7" or "$ACTION_ID_" in body
            if should_try_actions:
                discovery = discover_react_router_server_functions(body, context.url)
                if discovery.action_ids:
                    detected_version = "v7"
                    confidence = "high"
                    tags.add(TAG_REACT_ROUTER_V7_RSC)
                    tags.add(TAG_REACT_ROUTER_V7_SERVER_ACTIONS)
                    signals[SIG_RSC_ENDPOINT_FOUND] = True
                    signals[SIG_SERVER_ACTIONS_ENABLED] = True
                    signals[SIG_SERVER_ACTIONS_CONFIDENCE] = "medium"
                    signals["react_router_server_action_ids"] = list(discovery.action_ids)
                    if discovery.action_endpoints:
                        signals[SIG_SERVER_ACTION_ENDPOINTS] = list(discovery.action_endpoints)
                        signals[SIG_SERVER_ACTIONS_CONFIDENCE] = "high"

        if detected_version == "v7":
            tags.add(TAG_REACT_ROUTER_V7)
            signals["react_router_v7"] = True
        elif detected_version == "v6":
            tags.add(TAG_REACT_ROUTER_V6)
            signals["react_router_v6"] = True
        elif detected_version == "v5":
            tags.add(TAG_REACT_ROUTER_V5)
            signals["react_router_v5"] = True

        if detected_version:
            signals["react_router_confidence"] = confidence
