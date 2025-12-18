# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.utils import actions, tag_manager, version


def test_tagset_operations():
    tags = tag_manager.TagSet()
    assert tags.add("a") is True
    assert tags.add("a") is False  # dedupe
    assert tags.add_many("b", "c", "a") == 2
    assert "b" in tags
    assert list(tags) == ["a", "b", "c"]
    assert tags.remove("b") is True
    assert tags.remove("missing") is False
    removed = tags.remove_if(lambda t: t.startswith("c"))
    assert removed == 1
    assert tags.to_list() == ["a"]
    tags.clear()
    assert len(tags) == 0


def test_action_id_helpers():
    action_id = actions.generate_action_id(prefix="99", token_bytes=2)
    assert action_id.startswith("99")
    assert len(action_id) > 4
    ids = actions.generate_action_ids(3, prefix="77", token_bytes=1)
    assert len(ids) == 3
    assert all(i.startswith("77") for i in ids)
    assert actions.generate_action_ids(-5) == []


def test_semver_utils_and_version_flags():
    parsed = version.parse_semver("15.2.1-canary.5")
    assert parsed and parsed.to_tuple() == (15, 2, 1, "canary.5")
    assert version.parse_semver("1.2.3junk") is None
    assert version.compare_semver("1.2.3", "2.0.0") == -1
    assert version.compare_semver("2.0.0", "2.0.0") == 0
    assert version.compare_semver("bad", "2.0.0") is None

    assert version.is_react_version_vulnerable("19.1.0") is True
    assert version.is_react_version_vulnerable("19.1.2") is False
    assert version.is_react_version_vulnerable("18.2.0") is False
    assert version.is_react_version_vulnerable(None) is None
    assert version.is_react_version_vulnerable("19.3.0-canary-06fcc8f3-20251009") is True
    assert version.is_react_version_vulnerable("19.3.0-canary-deadbeef-20251202") is True
    assert version.is_react_version_vulnerable("19.3.0-canary-deadbeef-20251203") is False
    assert version.is_react_version_vulnerable("19.3.0-canary") is True

    assert version.is_next_version_vulnerable("15.4.7") is True
    assert version.is_next_version_vulnerable("15.4.8") is False
    assert version.is_next_version_vulnerable("14.3.0-canary.80") is True
    assert version.is_next_version_vulnerable("15.6.0-canary.50") is True
    assert version.is_next_version_vulnerable("15.6.0-canary.60") is False
    assert version.is_next_version_vulnerable("16.1.0-canary.5") is True
    assert version.is_next_version_vulnerable("16.1.0-canary.20") is False
    assert version.is_next_version_vulnerable("16.0.5") is True
    assert version.is_next_version_vulnerable("15.10.0") is True
    assert version.is_next_version_vulnerable("99.0.0") is False

    assert version.waku_version_implies_react_major("0.17.0") == 18
    assert version.waku_version_implies_react_major("0.19.1") == 19
    assert version.waku_version_implies_react_major("1.0.0") is None


def test_extract_versions_prefers_high_confidence_sources():
    headers = {
        "x-nextjs-version": "15.5.0",
        "x-waku-version": "0.20.1",
    }
    body = """
    0:I["react-server-dom-webpack","19.2.0"]
    react@19.1.0
    __reactRouterVersion":"7.0.1"
    next@15.4.9
    Waku 0.19.0
    """
    versions = version.extract_versions(headers, body)
    assert versions["react_version"] == "19.2.0"
    assert versions["react_version_source"] == "rsc_flight"
    assert versions["next_version"] == "15.5.0"
    assert versions["waku_version"] == "0.20.1"
    assert versions["react_router_version"] == "7.0.1"
    assert versions["react_major"] == 19
    assert versions["react_major_confidence"] == versions["react_version_confidence"]


def test_parsed_version_comparisons_and_labels():
    a = version.ParsedVersion(1, 2, 3)
    b = version.ParsedVersion(1, 2, 4, "alpha")
    assert a < b
    assert str(b) == "1.2.4-alpha"
    assert version._confidence_label(version._confidence_score("high")) == "high"
    assert version._confidence_label(0) == "none"
    assert version._confidence_label(1) == "low"


def test_extract_versions_manifest_and_plain_paths():
    body = """
    "react":"19.0.1"
    "next":"16.0.2"
    React 19.0.1
    Waku 0.19.0
    """
    versions = version.extract_versions({}, body)
    assert versions["react_version_source"] in {"manifest", "plain_text"}
    assert versions["next_version_source"] in {"manifest", "plain_text"}
    assert versions["waku_version_source"] == "plain_text"

    versions_literal = version.extract_versions({}, "react-server-dom-webpack@19.0.2 react@19.0.3 next@15.10.0")
    assert versions_literal["react_version"] in {"19.0.2", "19.0.3"}
