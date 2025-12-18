# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""React Router RSC / Server Functions discovery helpers (HTML-only)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...http import request_with_retries
from ...http.url import build_endpoint_candidates
from .bundle import extract_js_urls

_FORM_BLOCK_RE = re.compile(r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>", re.IGNORECASE | re.DOTALL)
_FORM_ACTION_RE = re.compile(r"\baction\s*=\s*(?:[\"']([^\"']*)[\"']|([^\s>]+))", re.IGNORECASE)
_ACTION_ID_RE = re.compile(r"name\s*=\s*(?:[\"'])?\$ACTION_ID_([^\"'\s>]+)", re.IGNORECASE)
_ACTION_ID_BUNDLE_RE = re.compile(r"\$ACTION_ID_([^\"'\s>]+)", re.IGNORECASE)

_DEFAULT_MAX_ASSETS = 8
_DEFAULT_MAX_ACTION_IDS = 8


@dataclass(frozen=True)
class ReactRouterServerFunctionsDiscovery:
    action_ids: list[str]
    action_endpoints: list[str]


def _scan_action_ids_from_bundles(
    html: str,
    base_url: str,
    *,
    max_assets: int = _DEFAULT_MAX_ASSETS,
    max_action_ids: int = _DEFAULT_MAX_ACTION_IDS,
) -> list[str]:
    action_ids: list[str] = []
    for asset_url in extract_js_urls(html, base_url)[: max(1, int(max_assets))]:
        resp = request_with_retries(
            asset_url,
            headers={"Accept": "application/javascript, text/javascript, */*"},
            allow_redirects=True,
        )
        if not resp.get("ok") or (resp.get("status_code") or 0) != 200:
            continue
        body = str(resp.get("body") or resp.get("body_snippet") or "")
        if not body:
            continue
        for match in _ACTION_ID_BUNDLE_RE.finditer(body):
            aid = match.group(1)
            if not aid or aid in action_ids:
                continue
            action_ids.append(aid)
            if len(action_ids) >= max_action_ids:
                return action_ids
    return action_ids


def discover_react_router_server_functions(
    html: str,
    base_url: str | None,
    *,
    max_assets: int = _DEFAULT_MAX_ASSETS,
    max_action_ids: int = _DEFAULT_MAX_ACTION_IDS,
) -> ReactRouterServerFunctionsDiscovery:
    """
    Discover React Router Server Function (form action) IDs and likely POST endpoints from HTML.

    React Router encodes Server Function IDs in hidden inputs like:
      <input type="hidden" name="$ACTION_ID_<id>">

    The actual network request uses header `rsc-action-id: <id>` and typically POSTs to the form's
    `action` attribute (often empty => same route).
    """
    action_ids: list[str] = []
    endpoints: list[str] = []

    if not html:
        return ReactRouterServerFunctionsDiscovery(action_ids=[], action_endpoints=[])

    # Prefer form-scoped discovery to preserve the per-form action URL.
    for form_match in _FORM_BLOCK_RE.finditer(html):
        attrs = form_match.group("attrs") or ""
        body = form_match.group("body") or ""
        ids = [m.group(1) for m in _ACTION_ID_RE.finditer(body) if m.group(1)]
        if not ids:
            continue
        for aid in ids:
            if aid not in action_ids:
                action_ids.append(aid)

        if not base_url:
            continue

        action_attr = None
        action_match = _FORM_ACTION_RE.search(attrs)
        if action_match:
            action_attr = action_match.group(1) or action_match.group(2)

        # Empty action => same route; otherwise join relative to base_url.
        if not action_attr:
            if base_url not in endpoints:
                endpoints.append(base_url)
            continue

        # Absolute URLs should be used as-is (avoid `/http://...` artifacts).
        if action_attr.startswith(("http://", "https://")):
            if action_attr not in endpoints:
                endpoints.append(action_attr)
            continue

        for candidate in build_endpoint_candidates(base_url, action_attr):
            if candidate not in endpoints:
                endpoints.append(candidate)

    # Fallback: action IDs without any form boundary (e.g. streamed HTML fragments).
    if not action_ids:
        for match in _ACTION_ID_RE.finditer(html):
            aid = match.group(1)
            if aid and aid not in action_ids:
                action_ids.append(aid)
        if base_url and action_ids:
            endpoints.append(base_url)

    # If action IDs are still missing, fall back to scanning same-origin JS bundles.
    if not action_ids and base_url:
        action_ids = _scan_action_ids_from_bundles(html, base_url, max_assets=max_assets, max_action_ids=max_action_ids)
        if action_ids and base_url:
            endpoints.append(base_url)

    return ReactRouterServerFunctionsDiscovery(action_ids=action_ids, action_endpoints=endpoints)


__all__ = ["ReactRouterServerFunctionsDiscovery", "discover_react_router_server_functions"]
