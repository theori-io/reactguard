# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared tag and signal keys used across framework/vulnerability detection."""

# Tags
TAG_EXPO = "expo"
TAG_EXPO_RSC = "expo-rsc"
TAG_EXPO_SERVER_ACTIONS = "expo-server-actions"
TAG_NEXTJS = "nextjs"
TAG_NEXTJS_APP_ROUTER = "nextjs-app-router"
TAG_NEXTJS_PAGES_ROUTER = "nextjs-pages-router"
TAG_REACT_ROUTER_V5 = "react-router-v5"
TAG_REACT_ROUTER_V6 = "react-router-v6"
TAG_REACT_ROUTER_V6_RSC = "react-router-v6-rsc"
TAG_REACT_ROUTER_V7 = "react-router-v7"
TAG_REACT_ROUTER_V7_RSC = "react-router-v7-rsc"
TAG_REACT_ROUTER_V7_SERVER_ACTIONS = "react-router-v7-server-actions"
TAG_REACT_SPA = "react-spa"
TAG_REACT_SSR_VITE = "react-ssr-vite"
TAG_REACT_STREAMING = "react-streaming"
TAG_RSC = "rsc"
TAG_WAKU = "waku"

# Common signals
SIG_DETECTION_CONFIDENCE = "detection_confidence"
SIG_DETECTION_CONFIDENCE_BREAKDOWN = "detection_confidence_breakdown"
SIG_DETECTION_CONFIDENCE_LEVEL = "detection_confidence_level"
SIG_DETECTOR_ERRORS = "detector_errors"
SIG_FETCH_ERROR_MESSAGE = "fetch_error_message"
SIG_FINAL_URL = "final_url"
SIG_REACT_MAJOR_EVIDENCE = "react_major_evidence"
SIG_REACT_MAJOR_CONFLICT = "react_major_conflict"
SIG_REACT_MAJOR_CONFLICT_CONFIDENCE = "react_major_conflict_confidence"
SIG_REACT_MAJOR_CONFLICT_MAJORS = "react_major_conflict_majors"
SIG_REACT_MAJOR_FROM_PAGE = "react_major_from_page"
SIG_DETECTED_REACT_MAJOR = "detected_react_major"
SIG_DETECTED_REACT_MAJOR_CONFIDENCE = "detected_react_major_confidence"
SIG_DETECTED_REACT_MAJOR_SOURCE = "detected_react_major_source"
SIG_DETECTED_REACT_VERSION = "detected_react_version"
SIG_DETECTED_RSC_RUNTIME_VERSION = "detected_rsc_runtime_version"
SIG_DETECTED_NEXT_VERSION = "detected_next_version"
SIG_DETECTED_WAKU_VERSION = "detected_waku_version"
SIG_DETECTED_REACT_ROUTER_VERSION = "detected_react_router_version"
SIG_DETECTED_VERSIONS = "detected_versions"
SIG_BUNDLE_VERSIONS = "bundle_versions"
SIG_REACT_BUNDLE = "react_bundle"
SIG_REACT_DOM_BUNDLE = "react_dom_bundle"
SIG_REACT_SERVER_DOM_BUNDLE = "react_server_dom_bundle"
SIG_REACT_BUNDLE_ONLY = "react_bundle_only"
SIG_RSC_CONTENT_TYPE = "rsc_content_type"
SIG_RSC_DEPENDENCY_ONLY = "rsc_dependency_only"
SIG_RSC_ENDPOINT_FOUND = "rsc_endpoint_found"
SIG_RSC_FLIGHT_PAYLOAD = "rsc_flight_payload"
SIG_RSC_FLIGHT_PAYLOAD_HTML_WRAPPED = "rsc_flight_payload_html_wrapped"
SIG_INVOCATION_CONFIDENCE = "invocation_confidence"
SIG_INVOCATION_ENABLED = "invocation_enabled"
SIG_INVOCATION_ENDPOINTS = "invocation_endpoints"

# Next.js signals
SIG_NEXTJS_DATA_SCRIPT = "nextjs_data_script"
SIG_NEXTJS_PAGES_ROUTER = "nextjs_pages_router"
SIG_NEXTJS_APP_ROUTER = "nextjs_app_router"
SIG_NEXTJS_HYDRATION_ARRAY = "nextjs_hydration_array"
SIG_NEXTJS_STATIC_PATHS = "nextjs_static_paths"
SIG_NEXTJS_CHUNK_PATTERN = "nextjs_chunk_pattern"
SIG_NEXTJS_MANIFEST = "nextjs_manifest"
SIG_HEADER_POWERED_BY_NEXTJS = "header_powered_by_nextjs"
SIG_NEXTJS_SIGNATURE = "nextjs_signature"
SIG_NEXTJS_ACTION_NOT_FOUND = "nextjs_action_not_found"
SIG_NEXTJS_ACTION_VARY_RSC = "nextjs_action_vary_rsc"
SIG_NEXTJS_PROBE_HTML_WITH_NEXT_MARKER = "nextjs_probe_html_with_next_marker"

# Expo signals
SIG_EXPO_REGISTRY = "expo_registry"
SIG_EXPO_ROUTER = "expo_router"
SIG_EXPO_ROUTER_PACKAGE = "expo_router_package"
SIG_EXPO_STATIC_ASSETS = "expo_static_assets"
SIG_EXPO_RESET_STYLE = "expo_reset_style"
SIG_EXPO_FLIGHT_SURFACE = "expo_flight_surface"
SIG_EXPO_RSC_EVIDENCE = "expo_rsc_evidence"

# React Router signals
SIG_REACT_ROUTER_MANIFEST = "react_router_manifest"
SIG_REMIX_HERITAGE = "remix_heritage"
SIG_REACT_ROUTER_VERSION = "react_router_version"
SIG_REACT_ROUTER_SERVER_ACTION_IDS = "react_router_server_action_ids"
SIG_REACT_ROUTER_V7 = "react_router_v7"
SIG_REACT_ROUTER_V6 = "react_router_v6"
SIG_REACT_ROUTER_V5 = "react_router_v5"
SIG_REACT_ROUTER_CONFIDENCE = "react_router_confidence"
SIG_REACT_ROUTER_V7_BUNDLE = "react_router_v7_bundle"
SIG_REACT_ROUTER_V6_BUNDLE = "react_router_v6_bundle"
SIG_REACT_ROUTER_V5_BUNDLE = "react_router_v5_bundle"

# Waku signals
SIG_WAKU_META_GENERATOR = "waku_meta_generator"
SIG_WAKU_ROOT = "waku_root"
SIG_WAKU_VARS = "waku_vars"
SIG_WAKU_RSC_CALL = "waku_rsc_call"
SIG_WAKU_HEADER = "waku_header"
SIG_WAKU_VERSION_HEADER = "waku_version_header"
SIG_WAKU_MODULE_CACHE = "waku_module_cache"
SIG_WAKU_LEGACY_ARCHITECTURE = "waku_legacy_architecture"
SIG_WAKU_VERSION_RANGE = "waku_version_range"
SIG_WAKU_MINIMAL_HTML = "waku_minimal_html"
SIG_WAKU_RSC_SURFACE = "waku_rsc_surface"
SIG_WAKU_ACTION_ENDPOINTS = "waku_action_endpoints"

# SPA / Vite signals
SIG_REACT_STREAMING_MARKERS = "react_streaming_markers"
SIG_REACT_SPA_MOUNT = "react_spa_mount"
SIG_REACT_SPA_MODULES = "react_spa_modules"
SIG_REACT_SPA_STRUCTURE = "react_spa_structure"
SIG_REACT_SSR_VITE = "react_ssr_vite"
SIG_VITE_ASSETS = "vite_assets"
SIG_VITE_MODULEPRELOAD_ASSETS = "vite_modulepreload_assets"

__all__ = [
    "TAG_EXPO",
    "TAG_EXPO_RSC",
    "TAG_EXPO_SERVER_ACTIONS",
    "TAG_NEXTJS",
    "TAG_NEXTJS_APP_ROUTER",
    "TAG_NEXTJS_PAGES_ROUTER",
    "TAG_REACT_ROUTER_V5",
    "TAG_REACT_ROUTER_V6",
    "TAG_REACT_ROUTER_V6_RSC",
    "TAG_REACT_ROUTER_V7",
    "TAG_REACT_ROUTER_V7_RSC",
    "TAG_REACT_ROUTER_V7_SERVER_ACTIONS",
    "TAG_REACT_SPA",
    "TAG_REACT_SSR_VITE",
    "TAG_REACT_STREAMING",
    "TAG_RSC",
    "TAG_WAKU",
    "SIG_DETECTION_CONFIDENCE",
    "SIG_DETECTION_CONFIDENCE_BREAKDOWN",
    "SIG_DETECTION_CONFIDENCE_LEVEL",
    "SIG_DETECTOR_ERRORS",
    "SIG_FETCH_ERROR_MESSAGE",
    "SIG_FINAL_URL",
    "SIG_REACT_MAJOR_EVIDENCE",
    "SIG_REACT_MAJOR_CONFLICT",
    "SIG_REACT_MAJOR_CONFLICT_CONFIDENCE",
    "SIG_REACT_MAJOR_CONFLICT_MAJORS",
    "SIG_REACT_MAJOR_FROM_PAGE",
    "SIG_DETECTED_REACT_MAJOR",
    "SIG_DETECTED_REACT_MAJOR_CONFIDENCE",
    "SIG_DETECTED_REACT_MAJOR_SOURCE",
    "SIG_DETECTED_REACT_VERSION",
    "SIG_DETECTED_RSC_RUNTIME_VERSION",
    "SIG_DETECTED_NEXT_VERSION",
    "SIG_DETECTED_WAKU_VERSION",
    "SIG_DETECTED_REACT_ROUTER_VERSION",
    "SIG_DETECTED_VERSIONS",
    "SIG_BUNDLE_VERSIONS",
    "SIG_REACT_BUNDLE",
    "SIG_REACT_DOM_BUNDLE",
    "SIG_REACT_SERVER_DOM_BUNDLE",
    "SIG_REACT_BUNDLE_ONLY",
    "SIG_RSC_CONTENT_TYPE",
    "SIG_RSC_DEPENDENCY_ONLY",
    "SIG_RSC_ENDPOINT_FOUND",
    "SIG_RSC_FLIGHT_PAYLOAD",
    "SIG_RSC_FLIGHT_PAYLOAD_HTML_WRAPPED",
    "SIG_INVOCATION_CONFIDENCE",
    "SIG_INVOCATION_ENABLED",
    "SIG_INVOCATION_ENDPOINTS",
    "SIG_NEXTJS_DATA_SCRIPT",
    "SIG_NEXTJS_PAGES_ROUTER",
    "SIG_NEXTJS_APP_ROUTER",
    "SIG_NEXTJS_HYDRATION_ARRAY",
    "SIG_NEXTJS_STATIC_PATHS",
    "SIG_NEXTJS_CHUNK_PATTERN",
    "SIG_NEXTJS_MANIFEST",
    "SIG_HEADER_POWERED_BY_NEXTJS",
    "SIG_NEXTJS_SIGNATURE",
    "SIG_NEXTJS_ACTION_NOT_FOUND",
    "SIG_NEXTJS_ACTION_VARY_RSC",
    "SIG_NEXTJS_PROBE_HTML_WITH_NEXT_MARKER",
    "SIG_EXPO_REGISTRY",
    "SIG_EXPO_ROUTER",
    "SIG_EXPO_ROUTER_PACKAGE",
    "SIG_EXPO_STATIC_ASSETS",
    "SIG_EXPO_RESET_STYLE",
    "SIG_EXPO_FLIGHT_SURFACE",
    "SIG_EXPO_RSC_EVIDENCE",
    "SIG_REACT_ROUTER_MANIFEST",
    "SIG_REMIX_HERITAGE",
    "SIG_REACT_ROUTER_VERSION",
    "SIG_REACT_ROUTER_SERVER_ACTION_IDS",
    "SIG_REACT_ROUTER_V7",
    "SIG_REACT_ROUTER_V6",
    "SIG_REACT_ROUTER_V5",
    "SIG_REACT_ROUTER_CONFIDENCE",
    "SIG_REACT_ROUTER_V7_BUNDLE",
    "SIG_REACT_ROUTER_V6_BUNDLE",
    "SIG_REACT_ROUTER_V5_BUNDLE",
    "SIG_WAKU_META_GENERATOR",
    "SIG_WAKU_ROOT",
    "SIG_WAKU_VARS",
    "SIG_WAKU_RSC_CALL",
    "SIG_WAKU_HEADER",
    "SIG_WAKU_VERSION_HEADER",
    "SIG_WAKU_MODULE_CACHE",
    "SIG_WAKU_LEGACY_ARCHITECTURE",
    "SIG_WAKU_VERSION_RANGE",
    "SIG_WAKU_MINIMAL_HTML",
    "SIG_WAKU_RSC_SURFACE",
    "SIG_WAKU_ACTION_ENDPOINTS",
    "SIG_REACT_STREAMING_MARKERS",
    "SIG_REACT_SPA_MOUNT",
    "SIG_REACT_SPA_MODULES",
    "SIG_REACT_SPA_STRUCTURE",
    "SIG_REACT_SSR_VITE",
    "SIG_VITE_ASSETS",
    "SIG_VITE_MODULEPRELOAD_ASSETS",
]
