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

"""Signal probe exports."""

from .bundle import probe_js_bundles
from .rsc import (
    apply_rsc_probe_results,
    probe_rsc_and_actions,
    probe_rsc_endpoint,
    probe_server_actions,
)
from .server_actions import (
    apply_server_actions_probe_results,
    detect_server_actions,
    generate_action_id,
    probe_server_actions_support,
)
from .waku import (
    probe_waku_minimal_html,
    probe_waku_rsc_surface,
    probe_waku_server_actions,
)

__all__ = [
    "apply_server_actions_probe_results",
    "apply_rsc_probe_results",
    "detect_server_actions",
    "generate_action_id",
    "probe_js_bundles",
    "probe_rsc_and_actions",
    "probe_rsc_endpoint",
    "probe_server_actions",
    "probe_server_actions_support",
    "probe_waku_minimal_html",
    "probe_waku_rsc_surface",
    "probe_waku_server_actions",
]
