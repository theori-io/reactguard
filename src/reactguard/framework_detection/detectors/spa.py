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

"""Generic React SPA detector."""

from typing import Any

from ...utils import TagSet
from ..base import DetectionContext, FrameworkDetector
from ..constants import (
    FRAMEWORK_HTML_MARKERS,
    SPA_MODULEPRELOAD_PATTERN,
    SPA_MOUNT_POINT_PATTERN,
    SPA_VITE_ASSETS_PATTERN,
)
from ..keys import (
    SIG_REACT_BUNDLE,
    SIG_REACT_DOM_BUNDLE,
    SIG_REACT_SERVER_DOM_BUNDLE,
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
        tags: TagSet,
        signals: dict[str, Any],
        context: DetectionContext,
    ) -> None:
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
            signals["react_spa_mount"] = True

        if 'type="module"' in body:
            spa_signals += 1
            signals["react_spa_modules"] = True

        if SPA_VITE_ASSETS_PATTERN.search(body):
            spa_signals += 1
            signals["vite_assets"] = True

        if SPA_MODULEPRELOAD_PATTERN.search(body):
            signals["vite_modulepreload_assets"] = True

        if context.url and spa_signals >= 1:
            bundle_signals = probe_js_bundles(
                context.url,
                body,
            )
            if bundle_signals.get("react_bundle"):
                spa_signals += 1
                signals[SIG_REACT_BUNDLE] = True
            if bundle_signals.get(SIG_REACT_DOM_BUNDLE):
                signals[SIG_REACT_DOM_BUNDLE] = True
            if bundle_signals.get(SIG_REACT_SERVER_DOM_BUNDLE):
                signals[SIG_REACT_SERVER_DOM_BUNDLE] = True

        if spa_signals >= 2 and has_mount and (has_data_reactroot or signals.get(SIG_REACT_BUNDLE)):
            tags.add(TAG_REACT_SPA)
            signals["react_spa_structure"] = True
        elif signals.get("vite_modulepreload_assets"):
            if (signals.get(SIG_REACT_BUNDLE) or signals.get("react_spa_modules")) and (has_data_reactroot or signals.get(SIG_REACT_BUNDLE)):
                tags.add(TAG_REACT_SSR_VITE)
                signals["react_ssr_vite"] = True

    def should_skip(self, tags: TagSet) -> bool:
        framework_tags = {TAG_NEXTJS, TAG_WAKU, TAG_EXPO, TAG_REACT_ROUTER_V7}
        return any(tag in tags for tag in framework_tags)
