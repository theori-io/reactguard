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

"""Waku framework detector."""

from typing import Any
from urllib.parse import urljoin

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
from ..keys import SIG_RSC_ENDPOINT_FOUND, SIG_SERVER_ACTION_ENDPOINTS, SIG_SERVER_ACTIONS_ENABLED, TAG_RSC, TAG_WAKU
from ..signals.waku import (
    probe_waku_minimal_html,
    probe_waku_rsc_surface,
    probe_waku_server_actions,
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
            action_probe = probe_waku_server_actions(
                context.url,
            )
            if isinstance(action_probe, tuple):
                has_actions = bool(action_probe[0])
                action_count = action_probe[1] if len(action_probe) > 1 else 0
                if len(action_probe) >= 3 and isinstance(action_probe[2], list):
                    endpoints_list = [urljoin(context.url, ep[0]) if context.url else ep[0] for ep in action_probe[2]]
            else:
                has_actions = bool(action_probe)
                action_count = 0

            if has_actions:
                signals[SIG_SERVER_ACTIONS_ENABLED] = True
                signals["waku_action_endpoints"] = action_count
                has_rsc_surface = True
                if endpoints_list:
                    signals[SIG_SERVER_ACTION_ENDPOINTS] = endpoints_list

        if is_waku:
            tags.add(TAG_WAKU)
            tags.add(TAG_RSC)
            signals[SIG_RSC_ENDPOINT_FOUND] = bool(has_rsc_surface)

    def should_skip(self, tags: TagSet) -> bool:
        return TAG_WAKU in tags
