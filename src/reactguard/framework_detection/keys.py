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
SIG_REACT_BUNDLE = "react_bundle"
SIG_REACT_DOM_BUNDLE = "react_dom_bundle"
SIG_REACT_SERVER_DOM_BUNDLE = "react_server_dom_bundle"
SIG_REACT_BUNDLE_ONLY = "react_bundle_only"
SIG_RSC_CONTENT_TYPE = "rsc_content_type"
SIG_RSC_DEPENDENCY_ONLY = "rsc_dependency_only"
SIG_RSC_ENDPOINT_FOUND = "rsc_endpoint_found"
SIG_RSC_FLIGHT_PAYLOAD = "rsc_flight_payload"
SIG_SERVER_ACTIONS_CONFIDENCE = "server_actions_confidence"
SIG_SERVER_ACTIONS_ENABLED = "server_actions_enabled"
SIG_SERVER_ACTION_ENDPOINTS = "server_action_endpoints"

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
    "SIG_REACT_BUNDLE",
    "SIG_REACT_DOM_BUNDLE",
    "SIG_REACT_SERVER_DOM_BUNDLE",
    "SIG_REACT_BUNDLE_ONLY",
    "SIG_RSC_CONTENT_TYPE",
    "SIG_RSC_DEPENDENCY_ONLY",
    "SIG_RSC_ENDPOINT_FOUND",
    "SIG_RSC_FLIGHT_PAYLOAD",
    "SIG_SERVER_ACTIONS_CONFIDENCE",
    "SIG_SERVER_ACTIONS_ENABLED",
    "SIG_SERVER_ACTION_ENDPOINTS",
]
