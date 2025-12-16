from __future__ import annotations

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

"""URL helpers shared across probes."""

from urllib.parse import urljoin, urlparse


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


__all__ = ["build_base_dir_url", "build_endpoint_candidates"]

