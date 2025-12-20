# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Waku framework detector."""

from typing import Any

from ...http.url import build_endpoint_candidates
from ...utils import flatten_version_map, normalize_version_map
from ...utils.version import update_version_pick
from ..base import DetectionContext, DetectionState, FrameworkDetector
from ..constants import (
    WAKU_META_GENERATOR_PATTERN,
    WAKU_MODULE_CACHE_PATTERN,
    WAKU_ROOT_PATTERN,
    WAKU_RSC_CALL_PATTERN,
    WAKU_VARS_PATTERN,
    WAKU_WEBPACK_CHUNK_PATTERN,
)
from ..keys import (
    SIG_INVOCATION_ENABLED,
    SIG_INVOCATION_ENDPOINTS,
    SIG_RSC_ENDPOINT_FOUND,
    SIG_WAKU_ACTION_ENDPOINTS,
    SIG_WAKU_HEADER,
    SIG_WAKU_LEGACY_ARCHITECTURE,
    SIG_WAKU_META_GENERATOR,
    SIG_WAKU_MINIMAL_HTML,
    SIG_WAKU_MODULE_CACHE,
    SIG_WAKU_RSC_CALL,
    SIG_WAKU_RSC_SURFACE,
    SIG_WAKU_ROOT,
    SIG_WAKU_VARS,
    SIG_WAKU_VERSION_HEADER,
    SIG_WAKU_VERSION_RANGE,
    SIG_DETECTED_VERSIONS,
    TAG_RSC,
    TAG_WAKU,
)
from ..signals.waku import (
    probe_waku_minimal_html,
    probe_waku_rsc_surface,
    probe_waku_server_actions_result,
)


class WakuDetector(FrameworkDetector):
    name = "waku"
    produces_tags = [TAG_WAKU, TAG_RSC]
    priority = 15

    def detect(
        self,
        body: str,
        headers: dict[str, str],
        state: DetectionState,
        context: DetectionContext,
    ) -> None:
        tags = state.tags
        signals = state.signals
        is_waku = False
        has_rsc_surface = False
        endpoints_list: list[str] = []

        if WAKU_META_GENERATOR_PATTERN.search(body):
            is_waku = True
            signals[SIG_WAKU_META_GENERATOR] = True

        if WAKU_ROOT_PATTERN.search(body):
            is_waku = True
            signals[SIG_WAKU_ROOT] = True

        if WAKU_VARS_PATTERN.search(body):
            is_waku = True
            signals[SIG_WAKU_VARS] = True

        if WAKU_RSC_CALL_PATTERN.search(body):
            is_waku = True
            signals[SIG_WAKU_RSC_CALL] = True

        waku_version = headers.get("x-waku-version")
        if waku_version:
            is_waku = True
            signals[SIG_WAKU_HEADER] = True
            signals[SIG_WAKU_VERSION_HEADER] = waku_version
            detected_versions = normalize_version_map(signals.get(SIG_DETECTED_VERSIONS))
            update_version_pick(
                detected_versions,
                "waku_version",
                waku_version,
                source="header",
                confidence="high",
                prefer_semver=True,
            )
            signals[SIG_DETECTED_VERSIONS] = {key: pick.to_mapping() for key, pick in detected_versions.items()}
            signals.update(flatten_version_map(detected_versions, prefix="detected_"))

        has_module_cache = WAKU_MODULE_CACHE_PATTERN.search(body) is not None
        has_webpack_chunk = WAKU_WEBPACK_CHUNK_PATTERN.search(body) is not None
        if has_module_cache and has_webpack_chunk:
            is_waku = True
            signals[SIG_WAKU_MODULE_CACHE] = True
            signals[SIG_WAKU_LEGACY_ARCHITECTURE] = True
            detected_versions = normalize_version_map(signals.get(SIG_DETECTED_VERSIONS))
            if detected_versions.get("waku_version") is None:
                signals[SIG_WAKU_VERSION_RANGE] = "0.17-0.20"

        if context.url and probe_waku_minimal_html(body, context.url):
            is_waku = True
            signals[SIG_WAKU_MINIMAL_HTML] = True

        if is_waku and context.url and not has_rsc_surface:
            if probe_waku_rsc_surface(context.url):
                signals[SIG_WAKU_RSC_SURFACE] = True
                has_rsc_surface = True

        if is_waku and context.url:
            action_probe = probe_waku_server_actions_result(context.url)
            has_actions = action_probe.has_actions
            action_count = action_probe.count
            if action_probe.endpoints:
                endpoints_list = []
                for endpoint_path, _action_name in action_probe.endpoints:
                    for candidate in build_endpoint_candidates(context.url, endpoint_path):
                        if candidate not in endpoints_list:
                            endpoints_list.append(candidate)

            if has_actions:
                signals[SIG_INVOCATION_ENABLED] = True
                signals[SIG_WAKU_ACTION_ENDPOINTS] = action_count
                has_rsc_surface = True
                if endpoints_list:
                    signals[SIG_INVOCATION_ENDPOINTS] = endpoints_list

        if is_waku:
            tags.add(TAG_WAKU)
            tags.add(TAG_RSC)
            signals[SIG_RSC_ENDPOINT_FOUND] = bool(has_rsc_surface)

    def should_skip(self, state: DetectionState) -> bool:
        return TAG_WAKU in state.tags
