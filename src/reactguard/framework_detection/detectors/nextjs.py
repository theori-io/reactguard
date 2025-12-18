# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Next.js framework detector."""

from typing import Any

from ...utils import TagSet
from ...utils.confidence import confidence_score
from ...utils.react_major import react_major_source_priority
from ..base import DetectionContext, FrameworkDetector
from ..constants import (
    NEXTJS_CHUNK_PATTERN,
    NEXTJS_MANIFEST_PATTERN,
    NEXTJS_NEXT_DATA_PATTERN,
    NEXTJS_NEXT_F_PATTERN,
    NEXTJS_STATIC_PATH_PATTERN,
)
from ..keys import (
    SIG_INVOCATION_ENABLED,
    SIG_RSC_CONTENT_TYPE,
    SIG_RSC_ENDPOINT_FOUND,
    SIG_RSC_FLIGHT_PAYLOAD,
    TAG_NEXTJS,
    TAG_NEXTJS_APP_ROUTER,
    TAG_NEXTJS_PAGES_ROUTER,
)
from ..nextjs_flight import infer_react_major_from_nextjs_html
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
        return infer_react_major_from_nextjs_html(body)

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

        if is_nextjs and context.url and signals.get(SIG_INVOCATION_ENABLED) is None:
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

        # Avoid React-major inference from arbitrary HTML/JS that happens to contain
        # Flight-looking substrings. Only attempt this once we've positively identified Next.js.
        react_major = self._react_major_from_flight(page_body) if is_nextjs else None
        if react_major is not None:
            detected_react_version = signals.get("detected_react_version")
            detected_react_version_major = None
            if detected_react_version:
                try:
                    detected_react_version_major = int(str(detected_react_version).split(".")[0])
                except (ValueError, TypeError):
                    detected_react_version_major = None

            if react_major == 19 or (react_major == 18 and detected_react_version_major is None):
                key = "detected_react_major"
                new_confidence = "medium"
                new_source = "flight:nextjs_html"

                current_confidence = str(signals.get(f"{key}_confidence") or "none")
                current_source = str(signals.get(f"{key}_source") or "")
                current_major = signals.get(key)

                should_set = False
                if current_major is None:
                    should_set = True
                elif confidence_score(new_confidence) > confidence_score(current_confidence):
                    should_set = True
                elif (
                    confidence_score(new_confidence) == confidence_score(current_confidence)
                    and react_major_source_priority(new_source) > react_major_source_priority(current_source)
                ):
                    should_set = True

                if should_set:
                    signals[key] = react_major
                    signals[f"{key}_confidence"] = new_confidence
                    signals[f"{key}_source"] = new_source

        # Only promote to App Router when we have RSC markers or action support
        if signals.get(SIG_INVOCATION_ENABLED) or signals.get(SIG_RSC_ENDPOINT_FOUND) or signals.get(SIG_RSC_CONTENT_TYPE):
            if tags.remove(TAG_NEXTJS_PAGES_ROUTER):
                signals["nextjs_pages_router"] = False
            tags.add(TAG_NEXTJS_APP_ROUTER)

    def should_skip(self, tags: TagSet) -> bool:
        return TAG_NEXTJS in tags
