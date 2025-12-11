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

"""Shared framework detection constants and markers."""

import re

# Common markers seen in HTML pages rendered by supported frameworks.
FRAMEWORK_HTML_MARKERS = [
    "__next_f",
    "__next_data__",
    "__reactroutermanifest",
    "__reactroutercontext",
    "__remixcontext",
    "__remixmanifest",
    "/_next/static/",
    "wakuroot",
    "__waku",
]

# Next.js detection markers.
NEXTJS_NEXT_DATA_PATTERN = re.compile(r"__NEXT_DATA__")
NEXTJS_NEXT_F_PATTERN = re.compile(r"self\.__next_f|__next_f\.push|__next_f=")
NEXTJS_STATIC_PATH_PATTERN = re.compile(r"/_next/static/")
NEXTJS_CHUNK_PATTERN = re.compile(r"/_next/static/chunks/[a-zA-Z0-9_-]+(-[a-f0-9]+)?\.js")
NEXTJS_MANIFEST_PATTERN = re.compile(r"_buildManifest\.js")
NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML = '0:[null,["$"'
NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED = '0:[null,[\\"$"'
NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT = '0:{"a":"$@'
NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT_ESCAPED = '0:{\\"a\\":\\"$@'
NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML = re.compile(r'^\s*0:\["\$","\$L', re.MULTILINE)
NEXTJS_RSC_FLIGHT_PATTERN_V18_HTML_ESCAPED = re.compile(r'^\s*0:\[\\"\\$\\",\\"\$L', re.MULTILINE)
NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE = re.compile(r'^\s*0:"\$L', re.MULTILINE)
NEXTJS_RSC_FLIGHT_PATTERN_V18_SIMPLE_ESCAPED = re.compile(r'^\s*0:\\"\\$L', re.MULTILINE)

# Expo detection markers.
EXPO_REGISTRY_PATTERN = re.compile(r"__ExpoImportMetaRegistry")
EXPO_ROUTER_HYDRATE_PATTERN = re.compile(r"__EXPO_ROUTER_HYDRATE__")
EXPO_ROUTER_PATTERN = re.compile(r"expo-router|@expo/router")
EXPO_STATIC_WEB_PATTERN = re.compile(r"/_expo/static/js/web/")
EXPO_RESET_STYLE_PATTERN = re.compile(r'id=["\']expo-reset["\']')

# Waku detection markers.
WAKU_ROOT_PATTERN = re.compile(r"wakuRoot|globalThis\.wakuRoot")
WAKU_VARS_PATTERN = re.compile(r"__waku[A-Za-z_]+", re.IGNORECASE)
WAKU_RSC_CALL_PATTERN = re.compile(r"__waku_rsc_call_server|__waku_ssr_handler")
WAKU_META_GENERATOR_PATTERN = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Waku["\']', re.IGNORECASE)
WAKU_MODULE_CACHE_PATTERN = re.compile(r"__waku_module_cache__")
WAKU_WEBPACK_CHUNK_PATTERN = re.compile(r"globalThis\.__webpack_chunk_load__")
WAKU_RSC_ENDPOINT_PATTERN = re.compile(r"/RSC/F/([a-f0-9]+)/(\w+)\.txt")
WAKU_RSC_DEV_ENDPOINT_PATTERN = re.compile(r"/RSC/F/_/(.+)/(\w+)\.txt")
WAKU_ACTION_ID_PATTERN_V025 = re.compile(r"([a-f0-9]{12,40})#([\w$-]+)")
WAKU_ACTION_ID_PATTERN_V021 = re.compile(r"@id/([^#]+)#([\w$-]+)")
WAKU_CREATE_SERVER_REF_PATTERN = re.compile(r'createServerReference\(["\']([^"#]+)#([\w$-]+)')
WAKU_MINIMAL_HTML_PATTERN = re.compile(
    r'^<html><body><script>import\(["\'][^"\']+["\']\)</script></body></html>$',
    re.IGNORECASE,
)
WAKU_JS_FALLBACK_PATTERN = re.compile(r'/(?:assets|src)/[^"\']+\.(?:js|ts)')
WAKU_ACTION_LITERAL_PATTERN = re.compile(r'"([a-f0-9]{12})#(\w+)"')
WAKU_VITE_ACTION_VIRTUAL_PATH_PATTERN = re.compile(r'/@id/[^"\']*actions\.ts[^"\']*')

# React Router detection markers.
RR_MANIFEST_PATTERN = re.compile(r"__reactRouterManifest")
RR_CONTEXT_PATTERN = re.compile(r"__reactRouterContext")
RR_VERSION_PATTERN = re.compile(r'__reactRouterVersion"?\s*[:=]\s*"(\d+\.\d+\.\d+)"')
REMIX_CONTEXT_PATTERN = re.compile(r"__remixContext|__remixManifest")

# Generic RSC detection markers.
GENERIC_FLIGHT_PAYLOAD_PATTERN = re.compile(r'^\d+:(?:\["\$|\{\s*"a"\s*:\s*"\$|\{\s*"id"\s*:\s*"\$)', re.MULTILINE)
GENERIC_FRAGMENT_PATTERN = re.compile(r"^\$[A-Z]", re.MULTILINE)

# SPA detection markers.
SPA_MOUNT_POINT_PATTERN = re.compile(r'id="(root|app)"|data-reactroot')
SPA_VITE_ASSETS_PATTERN = re.compile(r"/assets/[a-zA-Z0-9_-]+[.-][a-f0-9]+\.js")
SPA_MODULEPRELOAD_PATTERN = re.compile(r'rel=["\']modulepreload["\']\s+href=["\']/assets/[^\s"\']+\.js')

# RSC probe markers.
RSC_PROBE_FLIGHT_BODY_PATTERN = re.compile(
    r'^0:(?:\["\$|\[null,\["\$|\{"a"\s*:\s*"\$|I\["react-server-dom-)',
    re.IGNORECASE,
)

# Server action probe markers.
SERVER_ACTIONS_RSC_CONTENT_TYPE = "text/x-component"
SERVER_ACTIONS_RSC_FLIGHT_PATTERN = re.compile(r'^\d+:[{\["\']')
SERVER_ACTIONS_RSC_ERROR_PATTERN = re.compile(r'"digest"\s*:\s*"[0-9a-fA-F-]+"')
SERVER_ACTIONS_HTML_PATTERN = re.compile(r"<!doctype|<html", re.IGNORECASE)
SERVER_ACTIONS_STRONG_ACTION_KEYWORDS = [
    "next-action",
    "missing next-action",
    "server action not found",
    "missing action",
    "decode reply",
    "decodereply",
]
SERVER_ACTIONS_GENERIC_ACTION_KEYWORDS = [
    "action not found",
    "invalid action",
    "action error",
    "action id",
]
SERVER_ACTIONS_ACTION_KEYWORDS = SERVER_ACTIONS_STRONG_ACTION_KEYWORDS + SERVER_ACTIONS_GENERIC_ACTION_KEYWORDS
SERVER_ACTIONS_FLIGHT_PATTERN = re.compile(r"^\d+:[{\[]")
SERVER_ACTIONS_DEFAULT_ACTION_HEADER = "Next-Action"
