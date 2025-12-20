# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Generic React SPA detector."""

from typing import Any

from ..base import DetectionContext, DetectionState, FrameworkDetector
from ..constants import (
    FRAMEWORK_HTML_MARKERS,
    SPA_MODULEPRELOAD_PATTERN,
    SPA_MOUNT_POINT_PATTERN,
    SPA_SCRIPT_MODULE_PATTERN,
    SPA_VITE_ASSETS_PATTERN,
)
from ..keys import (
    SIG_REACT_BUNDLE,
    SIG_REACT_DOM_BUNDLE,
    SIG_REACT_SERVER_DOM_BUNDLE,
    SIG_REACT_SPA_MOUNT,
    SIG_REACT_SPA_MODULES,
    SIG_REACT_SPA_STRUCTURE,
    SIG_REACT_SSR_VITE,
    SIG_VITE_ASSETS,
    SIG_VITE_MODULEPRELOAD_ASSETS,
    TAG_EXPO,
    TAG_NEXTJS,
    TAG_REACT_ROUTER_V7,
    TAG_REACT_SPA,
    TAG_REACT_SSR_VITE,
    TAG_WAKU,
)
from ..signals.bundle import probe_js_bundles


class SPADetector(FrameworkDetector):
    name = "spa"
    produces_tags = [TAG_REACT_SPA, TAG_REACT_SSR_VITE]
    priority = 100

    def detect(
        self,
        body: str,
        headers: dict[str, str],
        state: DetectionState,
        context: DetectionContext,
    ) -> None:
        tags = state.tags
        signals = state.signals
        body_lower = body.lower()
        has_data_reactroot = "data-reactroot" in body_lower
        framework_tags = {TAG_NEXTJS, TAG_WAKU, TAG_EXPO}
        if any(tag in tags for tag in framework_tags):
            return

        for marker in FRAMEWORK_HTML_MARKERS:
            if marker in body_lower:
                return

        spa_signals = 0

        has_mount = bool(SPA_MOUNT_POINT_PATTERN.search(body))
        if has_mount:
            spa_signals += 1
            signals[SIG_REACT_SPA_MOUNT] = True

        if SPA_SCRIPT_MODULE_PATTERN.search(body):
            spa_signals += 1
            signals[SIG_REACT_SPA_MODULES] = True

        if SPA_VITE_ASSETS_PATTERN.search(body):
            spa_signals += 1
            signals[SIG_VITE_ASSETS] = True

        if SPA_MODULEPRELOAD_PATTERN.search(body):
            signals[SIG_VITE_MODULEPRELOAD_ASSETS] = True

        if context.url and spa_signals >= 1:
            bundle_signals = probe_js_bundles(
                context.url,
                body,
            )
            if bundle_signals.get(SIG_REACT_BUNDLE):
                spa_signals += 1
                signals[SIG_REACT_BUNDLE] = True
            if bundle_signals.get(SIG_REACT_DOM_BUNDLE):
                signals[SIG_REACT_DOM_BUNDLE] = True
            if bundle_signals.get(SIG_REACT_SERVER_DOM_BUNDLE):
                signals[SIG_REACT_SERVER_DOM_BUNDLE] = True

        if spa_signals >= 2 and has_mount and (has_data_reactroot or signals.get(SIG_REACT_BUNDLE)):
            tags.add(TAG_REACT_SPA)
            signals[SIG_REACT_SPA_STRUCTURE] = True
        elif signals.get(SIG_VITE_MODULEPRELOAD_ASSETS):
            if (signals.get(SIG_REACT_BUNDLE) or signals.get(SIG_REACT_SPA_MODULES)) and (has_data_reactroot or signals.get(SIG_REACT_BUNDLE)):
                tags.add(TAG_REACT_SSR_VITE)
                signals[SIG_REACT_SSR_VITE] = True

    def should_skip(self, state: DetectionState) -> bool:
        framework_tags = {TAG_NEXTJS, TAG_WAKU, TAG_EXPO, TAG_REACT_ROUTER_V7}
        return any(tag in state.tags for tag in framework_tags)
