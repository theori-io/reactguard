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

"""Generic RSC detector."""

from typing import Any

from ...utils import TagSet
from ..base import DetectionContext, FrameworkDetector
from ..constants import GENERIC_FLIGHT_PAYLOAD_PATTERN, GENERIC_FRAGMENT_PATTERN
from ..keys import SIG_RSC_CONTENT_TYPE, SIG_RSC_FLIGHT_PAYLOAD, TAG_REACT_STREAMING, TAG_RSC


class GenericRSCDetector(FrameworkDetector):
    name = "generic_rsc"
    produces_tags = [TAG_RSC, TAG_REACT_STREAMING]
    priority = 90

    def detect(
        self,
        body: str,
        headers: dict[str, str],
        tags: TagSet,
        signals: dict[str, Any],
        context: DetectionContext,
    ) -> None:
        content_type = headers.get("content-type", "")
        if "text/x-component" in content_type:
            tags.add(TAG_RSC)
            signals[SIG_RSC_CONTENT_TYPE] = True

        if GENERIC_FLIGHT_PAYLOAD_PATTERN.search(body):
            tags.add(TAG_RSC)
            signals[SIG_RSC_FLIGHT_PAYLOAD] = True

        if GENERIC_FRAGMENT_PATTERN.search(body) or "<!--$-->" in body:
            tags.add(TAG_REACT_STREAMING)
            signals["react_streaming_markers"] = True
