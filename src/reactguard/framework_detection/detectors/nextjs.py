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

"""Next.js framework detector."""

from typing import Any

from ...utils import TagSet
from ..base import DetectionContext, FrameworkDetector
from ..constants import (
    NEXTJS_CHUNK_PATTERN,
    NEXTJS_MANIFEST_PATTERN,
    NEXTJS_NEXT_DATA_PATTERN,
    NEXTJS_NEXT_F_PATTERN,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML_ESCAPED,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE,
    NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE_ESCAPED,
    NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML,
    NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED,
    NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT,
    NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT_ESCAPED,
    NEXTJS_STATIC_PATH_PATTERN,
)
from ..keys import (
    SIG_RSC_CONTENT_TYPE,
    SIG_RSC_ENDPOINT_FOUND,
    SIG_RSC_FLIGHT_PAYLOAD,
    SIG_SERVER_ACTIONS_ENABLED,
    TAG_NEXTJS,
    TAG_NEXTJS_APP_ROUTER,
    TAG_NEXTJS_PAGES_ROUTER,
)
from ..signals.server_actions import (
    ServerActionsSignalApplier,
    probe_server_actions_support,
)


class NextJSDetector(FrameworkDetector):
    name = "nextjs"
    produces_tags = [TAG_NEXTJS, TAG_NEXTJS_APP_ROUTER, TAG_NEXTJS_PAGES_ROUTER]
    priority = 10

    @classmethod
    def _react_major_from_flight(cls, body: str) -> Any:
        """Infer React major version from Flight payloads embedded in HTML."""
        if not body:
            return None
        if (
            NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML in body
            or NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED in body
            or NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT in body
            or NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT_ESCAPED in body
        ):
            return 19
        if (
            NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML.search(body)
            or NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML_ESCAPED.search(body)
            or NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE.search(body)
            or NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE_ESCAPED.search(body)
        ):
            return 18
        return None

    def detect(
        self,
        body: str,
        headers: dict[str, str],
        tags: TagSet,
        signals: dict[str, Any],
        context: DetectionContext,
    ) -> None:
        is_nextjs = False
        page_body = body or ""
        page_body_lower = page_body.lower()

        next_data_hit = NEXTJS_NEXT_DATA_PATTERN.search(body)
        if next_data_hit:
            is_nextjs = True
            signals["nextjs_data_script"] = True
            if not NEXTJS_NEXT_F_PATTERN.search(body):
                tags.add(TAG_NEXTJS)
                tags.add(TAG_NEXTJS_PAGES_ROUTER)
                signals["nextjs_pages_router"] = True

        if NEXTJS_NEXT_F_PATTERN.search(body):
            is_nextjs = True
            tags.add(TAG_NEXTJS)
            tags.add(TAG_NEXTJS_APP_ROUTER)
            signals["nextjs_app_router"] = True
            signals["nextjs_hydration_array"] = True

        if NEXTJS_STATIC_PATH_PATTERN.search(body):
            is_nextjs = True
            signals["nextjs_static_paths"] = True

        if NEXTJS_CHUNK_PATTERN.search(body):
            is_nextjs = True
            signals["nextjs_chunk_pattern"] = True

        if NEXTJS_MANIFEST_PATTERN.search(body):
            is_nextjs = True
            signals["nextjs_manifest"] = True

        powered_by = headers.get("x-powered-by", "")
        if "next.js" in powered_by.lower():
            is_nextjs = True
            signals["header_powered_by_nextjs"] = True

        if headers.get("x-nextjs-cache"):
            is_nextjs = True
            signals["nextjs_signature"] = True

        if is_nextjs and context.url and signals.get(SIG_SERVER_ACTIONS_ENABLED) is None:
            sa_result = probe_server_actions_support(
                context.url,
                payload_style="multipart",
            )
            probe_body = (sa_result.get("body") or sa_result.get("body_snippet") or "").lower()
            has_next_marker = sa_result.get("has_next_marker") or "__next_f" in probe_body or "__next_data__" in probe_body or "__next_f" in page_body_lower
            ServerActionsSignalApplier(
                tags=tags,
                signals=signals,
                not_found_signal_key="nextjs_action_not_found",
                vary_signal_key="nextjs_action_vary_rsc",
                react_major_signal_key="detected_react_major",
                rsc_flight_signal_key=SIG_RSC_FLIGHT_PAYLOAD,
                fallback_html_signal_key="nextjs_probe_html_with_next_marker",
                default_confidence="medium",
            ).apply(probe_result=sa_result, html_marker_hint=has_next_marker)

        if is_nextjs:
            tags.add(TAG_NEXTJS)

        if signals.get("detected_react_major") is None:
            react_major = self._react_major_from_flight(page_body)
            detected_react_version = signals.get("detected_react_version")
            detected_react_version_major = None
            if detected_react_version:
                try:
                    detected_react_version_major = int(str(detected_react_version).split(".")[0])
                except (ValueError, TypeError):
                    detected_react_version_major = None

            if react_major == 19 or (react_major == 18 and detected_react_version_major is None):
                signals["detected_react_major"] = react_major
                signals.setdefault("detected_react_major_confidence", "medium")

        # Only promote to App Router when we have RSC markers or action support
        if signals.get(SIG_SERVER_ACTIONS_ENABLED) or signals.get(SIG_RSC_ENDPOINT_FOUND) or signals.get(SIG_RSC_CONTENT_TYPE):
            if tags.remove(TAG_NEXTJS_PAGES_ROUTER):
                signals["nextjs_pages_router"] = False
            tags.add(TAG_NEXTJS_APP_ROUTER)

    def should_skip(self, tags: TagSet) -> bool:
        return TAG_NEXTJS in tags
