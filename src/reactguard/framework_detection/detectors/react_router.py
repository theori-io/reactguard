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
from ..keys import TAG_REACT_ROUTER_V5, TAG_REACT_ROUTER_V6, TAG_REACT_ROUTER_V7, TAG_REACT_ROUTER_V7_RSC, TAG_REACT_ROUTER_V7_SERVER_ACTIONS
from ..signals.bundle import probe_js_bundles
from ..signals.rsc import apply_rsc_probe_results


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

        if context.url and confidence != "high":
            bundle_signals = probe_js_bundles(
                context.url,
                body,
            )
            signals.update(bundle_signals)

            if bundle_signals.get("react_router_v7_bundle"):
                detected_version = "v7"
                confidence = "medium"
            elif bundle_signals.get("react_router_v6_bundle"):
                detected_version = "v6"
                confidence = "medium"
            elif bundle_signals.get("react_router_v5_bundle"):
                detected_version = "v5"
                confidence = "medium"

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

        if detected_version == "v7" and context.url:
            apply_rsc_probe_results(
                context.url,
                tags=tags,
                signals=signals,
                rsc_tag=TAG_REACT_ROUTER_V7_RSC,
                server_actions_tag=TAG_REACT_ROUTER_V7_SERVER_ACTIONS,
            )
