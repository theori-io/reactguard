# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.framework_detection.nextjs_flight import (
    infer_nextjs_rsc_signals_from_html,
    infer_react_major_from_nextjs_html,
)


def test_infer_nextjs_rsc_signals_from_html_empty():
    assert infer_nextjs_rsc_signals_from_html("") == (False, None)
    assert infer_react_major_from_nextjs_html("") is None


def test_infer_nextjs_rsc_signals_from_html_next_f_only():
    body = "<script>self.__next_f.push([1])</script>"
    assert infer_nextjs_rsc_signals_from_html(body) == (True, None)
    assert infer_react_major_from_nextjs_html(body) is None


def test_infer_nextjs_rsc_signals_from_html_react19_object():
    body = '...0:{"a":"$@1"}...'
    assert infer_nextjs_rsc_signals_from_html(body) == (True, 19)
    assert infer_react_major_from_nextjs_html(body) == 19


def test_infer_nextjs_rsc_signals_from_html_react19_html_escaped():
    body = '...0:{\\"a\\":\\"$@1\\"}...'
    assert infer_nextjs_rsc_signals_from_html(body) == (True, 19)


def test_infer_nextjs_rsc_signals_from_html_react18_wrapped():
    body = '...0:[null,["$", "$L1", null]]...'
    assert infer_nextjs_rsc_signals_from_html(body) == (True, 18)
    assert infer_react_major_from_nextjs_html(body) == 18


def test_infer_nextjs_rsc_signals_from_html_react18_multiline_html_payload():
    body = '\n0:["$","$L1",null]\n'
    assert infer_nextjs_rsc_signals_from_html(body) == (True, 18)


def test_infer_nextjs_rsc_signals_from_html_prefers_react19_when_both_hints_present():
    body = '0:[null,["$"\n0:{"a":"$@1"}'
    assert infer_nextjs_rsc_signals_from_html(body) == (True, 19)

