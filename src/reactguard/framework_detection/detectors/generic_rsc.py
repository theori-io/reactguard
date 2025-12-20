# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Generic RSC detector."""

from typing import Any

from ...http.heuristics import looks_like_html
from ...rsc.heuristics import is_rsc_content_type, looks_like_flight_payload
from ..base import DetectionContext, DetectionState, FrameworkDetector
from ..constants import GENERIC_FRAGMENT_PATTERN
from ..keys import SIG_REACT_STREAMING_MARKERS, SIG_RSC_CONTENT_TYPE, SIG_RSC_FLIGHT_PAYLOAD, TAG_REACT_STREAMING, TAG_RSC


class GenericRSCDetector(FrameworkDetector):
    name = "generic_rsc"
    produces_tags = [TAG_RSC, TAG_REACT_STREAMING]
    priority = 90

    def detect(
        self,
        body: str,
        headers: dict[str, str],
        state: DetectionState,
        context: DetectionContext,
    ) -> None:
        tags = state.tags
        signals = state.signals
        if is_rsc_content_type(headers):
            tags.add(TAG_RSC)
            signals[SIG_RSC_CONTENT_TYPE] = True

        # Avoid flagging generic HTML as RSC just because it contains a Flight-looking substring
        # somewhere in a script tag. Real Flight responses start with `<row_id>:` lines.
        if looks_like_flight_payload(body) and not looks_like_html(headers, body):
            tags.add(TAG_RSC)
            signals[SIG_RSC_FLIGHT_PAYLOAD] = True

        if GENERIC_FRAGMENT_PATTERN.search(body) or "<!--$-->" in body:
            tags.add(TAG_REACT_STREAMING)
            signals[SIG_REACT_STREAMING_MARKERS] = True
