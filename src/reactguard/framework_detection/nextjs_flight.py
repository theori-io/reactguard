# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Next.js HTML helpers for RSC Flight markers (compat wrapper)."""

from __future__ import annotations

from ..rsc.nextjs import infer_nextjs_rsc_signals_from_html, infer_react_major_from_nextjs_html

__all__ = ["infer_nextjs_rsc_signals_from_html", "infer_react_major_from_nextjs_html"]
