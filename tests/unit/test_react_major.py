# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

from reactguard.utils.react_major import infer_react_major_from_flight_text


def test_infer_react_major_from_flight_text_rejects_html():
    assert infer_react_major_from_flight_text('<html><script>var x={0:{a:1}};</script></html>') is None


def test_infer_react_major_from_flight_text_v19_object_root():
    assert infer_react_major_from_flight_text('0:{"P":null}\n') == 19
    assert infer_react_major_from_flight_text('1:I["x"]\n0:{"P":null}\n') == 19
    assert infer_react_major_from_flight_text(r'0:{\"P\":null' + "\n") == 19


def test_infer_react_major_from_flight_text_v18_array_root_and_lref():
    assert infer_react_major_from_flight_text('0:[null,["$","$L1",null,{}]]\n') == 18
    assert infer_react_major_from_flight_text('0:"$L1"\n') == 18
