# SPDX-FileCopyrightText: 2025 Theori Inc.
# SPDX-License-Identifier: AGPL-3.0-or-later

import shutil
import subprocess

import pytest

from reactguard.rsc.payloads import SAFE_ARGS_LENGTH_TOKEN, build_no_invoke_args_container


def test_no_invoke_args_container_includes_bigint_length_token():
    args = build_no_invoke_args_container(["$K1", "$2:x:__proto__"])
    assert isinstance(args, dict)
    assert args["length"] == SAFE_ARGS_LENGTH_TOKEN


def test_no_invoke_args_container_prevents_call_via_spread_or_apply():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available; skipping JS call-site safety check")

    # Verify the "no-invoke args" concept: regardless of the callee, a non-iterable object
    # will throw on spread, and a BigInt length throws on apply's ToLength coercion.
    script = r"""
let called = 0;
function user() { called++; }
const args = { 0: "x", length: 1n };
try { user(...args); } catch (e) {}
try { user.apply(null, args); } catch (e) {}
if (called !== 0) process.exit(3);
console.log("ok");
"""
    completed = subprocess.run(
        [node, "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "ok"
