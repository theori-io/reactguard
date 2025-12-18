# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Waku framework detector."""

from typing import Any

from ...http.url import build_endpoint_candidates
from ...utils import TagSet
from ..base import DetectionContext, FrameworkDetector
from ..constants import (
    WAKU_META_GENERATOR_PATTERN,
    WAKU_MODULE_CACHE_PATTERN,
    WAKU_ROOT_PATTERN,
    WAKU_RSC_CALL_PATTERN,
    WAKU_VARS_PATTERN,
    WAKU_WEBPACK_CHUNK_PATTERN,
)
from ..keys import SIG_INVOCATION_ENABLED, SIG_INVOCATION_ENDPOINTS, SIG_RSC_ENDPOINT_FOUND, TAG_RSC, TAG_WAKU
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
        tags: TagSet,
        signals: dict[str, Any],
        context: DetectionContext,
    ) -> None:
        is_waku = False
        has_rsc_surface = False
        endpoints_list: list[str] = []

        if WAKU_META_GENERATOR_PATTERN.search(body):
            is_waku = True
            signals["waku_meta_generator"] = True

        if WAKU_ROOT_PATTERN.search(body):
            is_waku = True
            signals["waku_root"] = True

        if WAKU_VARS_PATTERN.search(body):
            is_waku = True
            signals["waku_vars"] = True

        if WAKU_RSC_CALL_PATTERN.search(body):
            is_waku = True
            signals["waku_rsc_call"] = True

        waku_version = headers.get("x-waku-version")
        if waku_version:
            is_waku = True
            signals["waku_header"] = True
            signals["waku_version_header"] = waku_version
            signals["detected_waku_version"] = waku_version

        has_module_cache = WAKU_MODULE_CACHE_PATTERN.search(body) is not None
        has_webpack_chunk = WAKU_WEBPACK_CHUNK_PATTERN.search(body) is not None
        if has_module_cache and has_webpack_chunk:
            is_waku = True
            signals["waku_module_cache"] = True
            signals["waku_legacy_architecture"] = True
            if "detected_waku_version" not in signals:
                signals["waku_version_range"] = "0.17-0.20"

        if context.url and probe_waku_minimal_html(body, context.url):
            is_waku = True
            signals["waku_minimal_html"] = True

        if is_waku and context.url and not has_rsc_surface:
            if probe_waku_rsc_surface(context.url):
                signals["waku_rsc_surface"] = True
                has_rsc_surface = True

        if is_waku and context.url:
            action_probe = probe_waku_server_actions_result(context.url)
            has_actions = action_probe.has_actions
            action_count = action_probe.count
            if action_probe.endpoints:
                endpoints_list = []
                for endpoint_path, _action_name in action_probe.endpoints:
                    if not context.url:
                        continue
                    for candidate in build_endpoint_candidates(context.url, endpoint_path):
                        if candidate not in endpoints_list:
                            endpoints_list.append(candidate)

            if has_actions:
                signals[SIG_INVOCATION_ENABLED] = True
                signals["waku_action_endpoints"] = action_count
                has_rsc_surface = True
                if endpoints_list:
                    signals[SIG_INVOCATION_ENDPOINTS] = endpoints_list

        if is_waku:
            tags.add(TAG_WAKU)
            tags.add(TAG_RSC)
            signals[SIG_RSC_ENDPOINT_FOUND] = bool(has_rsc_surface)

    def should_skip(self, tags: TagSet) -> bool:
        return TAG_WAKU in tags
