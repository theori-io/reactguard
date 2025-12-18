# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Generic RSC detector."""

import re
from typing import Any

from ...http.headers import header_value
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
        content_type = header_value(headers, "content-type")
        if "text/x-component" in content_type:
            tags.add(TAG_RSC)
            signals[SIG_RSC_CONTENT_TYPE] = True

        # Avoid flagging generic HTML as RSC just because it contains a Flight-looking substring
        # somewhere in a script tag. Real Flight responses start with `<row_id>:` lines.
        looks_like_flight_document = bool(re.match(r"^\d+:", (body or "").lstrip()))
        if looks_like_flight_document and GENERIC_FLIGHT_PAYLOAD_PATTERN.search(body):
            tags.add(TAG_RSC)
            signals[SIG_RSC_FLIGHT_PAYLOAD] = True

        if GENERIC_FRAGMENT_PATTERN.search(body) or "<!--$-->" in body:
            tags.add(TAG_REACT_STREAMING)
            signals["react_streaming_markers"] = True
