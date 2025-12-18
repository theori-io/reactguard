# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""URL helpers shared across probes."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse


def same_origin(a: str, b: str) -> bool:
    """Return True when both URLs share the same scheme + netloc."""
    pa = urlparse(str(a or ""))
    pb = urlparse(str(b or ""))
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def build_base_dir_url(base_url: str) -> str:
    """
    Convert a scan URL into a "directory" URL suitable for relative `urljoin()` calls.

    Example:
      http://host/app -> http://host/app/
    """
    parsed = urlparse(str(base_url or ""))
    path = parsed.path.rstrip("/") + "/"
    return parsed._replace(path=path, params="", query="", fragment="").geturl()


def build_endpoint_candidates(base_url: str, path: str) -> list[str]:
    """
    Build candidate probe URLs for an endpoint path.

    We try both:
    - root-relative (`/rsc`)
    - base-relative (`<base_path>/rsc`) to support subpath deployments (e.g., `/app`)
    """
    if not base_url or not path:
        return []

    raw_path = str(path)
    root_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
    root_url = urljoin(base_url, root_path)

    base_dir = build_base_dir_url(base_url)
    base_relative_url = urljoin(base_dir, raw_path.lstrip("/"))

    if root_url == base_relative_url:
        return [root_url]
    return [root_url, base_relative_url]


__all__ = ["build_base_dir_url", "build_endpoint_candidates", "same_origin"]
