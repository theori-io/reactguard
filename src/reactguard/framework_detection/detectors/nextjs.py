# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Next.js framework detector."""

from collections.abc import Mapping
from typing import Any

from ...utils import flatten_version_map, normalize_version_map
from ...utils.confidence import confidence_score
from ...utils.react_major import react_major_source_priority
from ...utils.version import update_version_pick
from ..base import DetectionContext, DetectionState, FrameworkDetector
from ..constants import (
    NEXTJS_CHUNK_PATTERN,
    NEXTJS_MANIFEST_PATTERN,
    NEXTJS_NEXT_DATA_PATTERN,
    NEXTJS_NEXT_F_PATTERN,
    NEXTJS_STATIC_PATH_PATTERN,
)
from ..keys import (
    SIG_INVOCATION_ENABLED,
    SIG_NEXTJS_ACTION_NOT_FOUND,
    SIG_NEXTJS_ACTION_VARY_RSC,
    SIG_NEXTJS_APP_ROUTER,
    SIG_NEXTJS_CHUNK_PATTERN,
    SIG_NEXTJS_DATA_SCRIPT,
    SIG_NEXTJS_HYDRATION_ARRAY,
    SIG_NEXTJS_MANIFEST,
    SIG_NEXTJS_PAGES_ROUTER,
    SIG_NEXTJS_PROBE_HTML_WITH_NEXT_MARKER,
    SIG_NEXTJS_SIGNATURE,
    SIG_NEXTJS_STATIC_PATHS,
    SIG_HEADER_POWERED_BY_NEXTJS,
    SIG_DETECTED_REACT_MAJOR,
    SIG_DETECTED_VERSIONS,
    SIG_RSC_CONTENT_TYPE,
    SIG_RSC_ENDPOINT_FOUND,
    SIG_RSC_FLIGHT_PAYLOAD,
    TAG_NEXTJS,
    TAG_NEXTJS_APP_ROUTER,
    TAG_NEXTJS_PAGES_ROUTER,
)
from ..nextjs_flight import infer_react_major_from_nextjs_html
from ..signals.server_actions import (
    ServerActionsProbeResult,
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
        state: DetectionState,
        context: DetectionContext,
    ) -> None:
        tags = state.tags
        signals = state.signals
        is_nextjs = False
        page_body = body or ""
        page_body_lower = page_body.lower()

        next_data_hit = NEXTJS_NEXT_DATA_PATTERN.search(body)
        if next_data_hit:
            is_nextjs = True
            signals[SIG_NEXTJS_DATA_SCRIPT] = True
            if not NEXTJS_NEXT_F_PATTERN.search(body):
                tags.add(TAG_NEXTJS)
                tags.add(TAG_NEXTJS_PAGES_ROUTER)
                signals[SIG_NEXTJS_PAGES_ROUTER] = True

        if NEXTJS_NEXT_F_PATTERN.search(body):
            is_nextjs = True
            tags.add(TAG_NEXTJS)
            tags.add(TAG_NEXTJS_APP_ROUTER)
            signals[SIG_NEXTJS_APP_ROUTER] = True
            signals[SIG_NEXTJS_HYDRATION_ARRAY] = True

        if NEXTJS_STATIC_PATH_PATTERN.search(body):
            is_nextjs = True
            signals[SIG_NEXTJS_STATIC_PATHS] = True

        if NEXTJS_CHUNK_PATTERN.search(body):
            is_nextjs = True
            signals[SIG_NEXTJS_CHUNK_PATTERN] = True

        if NEXTJS_MANIFEST_PATTERN.search(body):
            is_nextjs = True
            signals[SIG_NEXTJS_MANIFEST] = True

        powered_by = headers.get("x-powered-by", "")
        if "next.js" in powered_by.lower():
            is_nextjs = True
            signals[SIG_HEADER_POWERED_BY_NEXTJS] = True

        if headers.get("x-nextjs-cache"):
            is_nextjs = True
            signals[SIG_NEXTJS_SIGNATURE] = True

        if is_nextjs and context.url and signals.get(SIG_INVOCATION_ENABLED) is None:
            sa_result = probe_server_actions_support(
                context.url,
                payload_style="multipart",
            )
            if isinstance(sa_result, Mapping):
                sa_result = ServerActionsProbeResult.from_mapping(sa_result)
            probe_body = str(sa_result.body or sa_result.body_snippet or "").lower()
            has_next_marker = bool(sa_result.has_next_marker or "__next_f" in probe_body or "__next_data__" in probe_body or "__next_f" in page_body_lower)
            ServerActionsSignalApplier.from_state(
                state,
                not_found_signal_key=SIG_NEXTJS_ACTION_NOT_FOUND,
                vary_signal_key=SIG_NEXTJS_ACTION_VARY_RSC,
                react_major_signal_key=SIG_DETECTED_REACT_MAJOR,
                rsc_flight_signal_key=SIG_RSC_FLIGHT_PAYLOAD,
                fallback_html_signal_key=SIG_NEXTJS_PROBE_HTML_WITH_NEXT_MARKER,
                default_confidence="medium",
            ).apply(probe_result=sa_result, html_marker_hint=has_next_marker)

        if is_nextjs:
            tags.add(TAG_NEXTJS)

        # Avoid React-major inference from arbitrary HTML/JS that happens to contain
        # Flight-looking substrings. Only attempt this once we've positively identified Next.js.
        react_major = self._react_major_from_flight(page_body) if is_nextjs else None
        if react_major is not None:
            detected_versions = normalize_version_map(signals.get(SIG_DETECTED_VERSIONS))
            detected_react_version = detected_versions.get("react_version")
            detected_react_version_major = None
            if detected_react_version:
                try:
                    detected_react_version_major = int(str(detected_react_version.value).split(".")[0])
                except (ValueError, TypeError):
                    detected_react_version_major = None

            if react_major == 19 or (react_major == 18 and detected_react_version_major is None):
                new_confidence = "medium"
                new_source = "flight:nextjs_html"

                current_major_pick = detected_versions.get("react_major")
                current_confidence = str(current_major_pick.confidence if current_major_pick else "none")
                current_source = str(current_major_pick.source if current_major_pick else "")
                current_major = current_major_pick.value if current_major_pick else None

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
                    update_version_pick(
                        detected_versions,
                        "react_major",
                        react_major,
                        source=new_source,
                        confidence=new_confidence,
                        prefer_semver=False,
                    )
                    signals[SIG_DETECTED_VERSIONS] = {key: pick.to_mapping() for key, pick in detected_versions.items()}
                    signals.update(flatten_version_map(detected_versions, prefix="detected_"))

        # Only promote to App Router when we have RSC markers or action support
        if signals.get(SIG_INVOCATION_ENABLED) or signals.get(SIG_RSC_ENDPOINT_FOUND) or signals.get(SIG_RSC_CONTENT_TYPE):
            if tags.remove(TAG_NEXTJS_PAGES_ROUTER):
                signals[SIG_NEXTJS_PAGES_ROUTER] = False
            tags.add(TAG_NEXTJS_APP_ROUTER)

    def should_skip(self, state: DetectionState) -> bool:
        return TAG_NEXTJS in state.tags
