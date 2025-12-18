# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

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
# React 19+ Flight payloads encode the root segment (`0:`) as an object.
# NOTE: Avoid using overly-generic markers like `0:{` for *HTML* detection; prefer escaped/structured
# patterns (e.g. `0:{\\\"`) and/or framework-specific hydration markers to reduce false positives.
NEXTJS_RSC_FLIGHT_PATTERN_V19_HTML_ESCAPED = '0:{\\"'
NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT = '0:{"a":"$@'
NEXTJS_RSC_FLIGHT_PATTERN_V19_OBJECT_ESCAPED = '0:{\\"a\\":\\"$@'
# React 18 Flight payloads sometimes wrap the array root segment, e.g.:
#   0:[null,["$","$L1",...]]
NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED = '0:[null,["$"'
NEXTJS_RSC_FLIGHT_PATTERN_V18_WRAPPED_ESCAPED = '0:[null,[\\"$"'
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
# Waku server-action endpoints are commonly `.txt` (e.g., `/RSC/F/<hash>/<action>.txt`).
# While `/RSC/index.rsc` exists on some Waku targets as an alternate "index" endpoint, we keep `.rsc` out of
# server-action endpoint extraction to avoid speculative expansions.
WAKU_RSC_ENDPOINT_PATTERN = re.compile(r"/RSC/F/([a-f0-9]{8,64})/([\w$-]+)\.txt", re.IGNORECASE)
WAKU_RSC_DEV_ENDPOINT_PATTERN = re.compile(r"/RSC/F/_/([^\"']+)/([\w$-]+)\.txt", re.IGNORECASE)
# Accept both hashed (`/RSC/F/<hash>/<action>.txt`), dev (`/RSC/F/_/<file>/<action>.txt`) and ActionId routes
# (`/RSC/ACTION_<file>/<action>.txt`).
WAKU_SERVER_ACTION_ENDPOINT_PATTERN = re.compile(
    r"/RSC/(?:F/[a-f0-9]{8,64}/[\w$-]+|F/_/[^\"']+/[\w$-]+|ACTION_[^\"']+/[\w$-]+)\.txt",
    re.IGNORECASE,
)
WAKU_RSC_PREFETCH_KEY_PATTERN = re.compile(r'["\'](/RSC/[^"\']+\.txt)["\']\s*:', re.IGNORECASE)
WAKU_RSC_PREFETCH_ROUTE_KEY_PATTERN = re.compile(r'["\'](R/[^"\']+)["\']\s*:', re.IGNORECASE)
WAKU_ACTION_ID_PATTERN_V025 = re.compile(r"([a-f0-9]{8,64})#([\w$-]+)", re.IGNORECASE)
WAKU_ACTION_ID_PATTERN_V021 = re.compile(r"@id/([^#]+)#([\w$-]+)")
WAKU_CREATE_SERVER_REF_PATTERN = re.compile(r'createServerReference\(["\']([^"#]+)#([\w$-]+)')
WAKU_MINIMAL_HTML_PATTERN = re.compile(
    r'^\s*<html[^>]*>\s*(?:<head[^>]*>.*?</head>\s*)?<body[^>]*>\s*<script[^>]*>\s*import\(\s*["\'][^"\']+["\']\s*\)\s*</script>\s*</body>\s*</html>\s*$',
    re.IGNORECASE | re.DOTALL,
)
# Note: order matters here (`tsx` before `ts`, `jsx` before `js`) so we don't truncate matches like `.tsx` -> `.ts`.
WAKU_JS_FALLBACK_PATTERN = re.compile(r'/(?:assets|src)/[^"\']+\.(?:tsx|ts|jsx|js|mjs|cjs)')
WAKU_ACTION_LITERAL_PATTERN = re.compile(r'"([a-f0-9]{8,64})#([\w$-]+)"', re.IGNORECASE)
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
SPA_MOUNT_POINT_PATTERN = re.compile(r"id=['\"](?:root|app)['\"]|data-reactroot", re.IGNORECASE)
SPA_SCRIPT_MODULE_PATTERN = re.compile(r"<script[^>]*\btype\s*=\s*(?:['\"]module['\"]|module)", re.IGNORECASE)
SPA_VITE_ASSETS_PATTERN = re.compile(r"/assets/[a-zA-Z0-9_-]+[.-][a-f0-9]+\.js")
SPA_MODULEPRELOAD_PATTERN = re.compile(r'rel=["\']modulepreload["\']\s+href=["\']/assets/[^\s"\']+\.js')

# RSC probe markers.
RSC_PROBE_FLIGHT_BODY_PATTERN = re.compile(
    r'^0:(?:\["\$|\[null,\["\$|\{|I\["react-server-dom-)',
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
