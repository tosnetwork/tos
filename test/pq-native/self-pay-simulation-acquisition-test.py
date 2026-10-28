#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Exercise simulation acquisition callbacks, then authenticate the collected inputs."""

import ctypes as c
import hashlib
import json
import struct
import sys
from pathlib import Path

library = c.CDLL(sys.argv[1])
root = Path(sys.argv[2])
Query = c.CFUNCTYPE(
    c.c_int, c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)
)
Emit = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_uint32, c.c_void_p, c.c_size_t)
arguments = [
    c.c_char_p,
    c.c_size_t,
    c.c_char_p,
    c.c_size_t,
    c.c_char_p,
    c.c_size_t,
    Query,
    c.c_void_p,
    Emit,
    c.c_void_p,
]
acquire = library.tos_proof_acquire_self_pay_simulation
ordinary = library.tos_proof_acquire
for function in (acquire, ordinary):
    function.restype = c.c_int
    function.argtypes = arguments

anchor = (root / "anchor.json").read_bytes()
request_object = json.loads((root / "request.json").read_bytes())
request_object.pop(
    "target"
)  # Exercise latest-target selection and its exact remaining-byte budget.
request = json.dumps(request_object).encode()
state = json.dumps({"interface": "tos-proof-verify-state/1", "anchor": json.loads(anchor)}).encode()
message = (root / "message.boc").read_bytes()
clock = int((root / "clock.txt").read_text())
replies = [
    (root / "material" / name).read_bytes()
    for name in ["masterchain-info.tl", "chain-0000.tl", "account.tl", "exec-config.tl"]
]


def check(name, condition):
    print("SELF_PAY_ACQUISITION_CASE", name, "PASS" if condition else "FAIL", flush=True)
    assert condition, name


def run(*, raw_request=request, raw_state=state, raw_anchor=anchor, failure=None, legacy=False):
    queries, capacities, emitted, attempted, errors = [], [], [], [], []
    remaining = 64 * 1024 * 1024
    if not legacy:
        remaining -= len(raw_anchor) + len(raw_request) + len(raw_state) + 1024 * 1024

    @Query
    def query(context, data, size, output, capacity, used):
        nonlocal remaining
        try:
            index = len(queries)
            queries.append(c.string_at(data, size))
            capacities.append(capacity)
            used[0] = 0
            expected = min(remaining, 16 * 1024 * 1024) if not legacy and index >= 2 else remaining
            assert capacity == expected, (
                "input-and-message-reserve-before-receive"
                if index == 0
                else "remaining-byte-budget",
                index,
                capacity,
                expected,
            )
            assert message not in queries[-1], "signed-message-forwarded-to-endpoint"
            if failure == "transport" and index == 2:
                return -1
            if failure == "oversized" and index == 2:
                used[0] = capacity + 1
                return 0
            if failure == "empty" and index == 2:
                return 0
            assert index < (3 if legacy else 4), "unexpected-extra-query"
            reply = replies[index]
            assert len(reply) <= capacity
            c.memmove(output, reply, len(reply))
            used[0] = len(reply)
            remaining -= len(reply)
            return 0
        except Exception as error:
            errors.append(str(error))
            return -1

    @Emit
    def emit(context, kind, data, size):
        attempted.append(kind)
        if failure == "collector" and len(attempted) == 3:
            return -1
        emitted.append((kind, c.string_at(data, size)))
        return 0

    function = ordinary if legacy else acquire
    code = function(
        raw_anchor,
        len(raw_anchor),
        raw_request,
        len(raw_request),
        raw_state,
        len(raw_state),
        query,
        None,
        emit,
        None,
    )
    assert not errors, errors
    # This is a required caller contract, including when emit failed after some copies.
    if code != 0:
        emitted.clear()
    return code, emitted, queries, capacities, attempted


code, material, queries, capacities, attempted = run()
check("live-account-fetches-full-config-without-getters", code == 0 and len(queries) == 4)
check("complete-execution-config-mode", struct.unpack_from("<i", queries[3], 4)[0] == 928)
check(
    "same-public-material-and-no-selected-config-or-library",
    [k for k, _ in material] == [1, 2, 5, 6] and [v for _, v in material] == replies,
)
check(
    "input-and-message-reserve-before-receive",
    capacities[0] == 64 * 1024 * 1024 - len(anchor) - len(request) - len(state) - 1024 * 1024,
)
check("aggregate-decrement-before-next-query", capacities[1] == capacities[0] - len(replies[0]))
check("account-and-config-receive-limits", capacities[2:] == [16 * 1024 * 1024] * 2)
old_code, old_parts, old_queries, old_capacities, _ = run(legacy=True)
check(
    "ordinary-account-path-retained",
    old_code == 0
    and len(old_queries) == 3
    and [k for k, _ in old_parts] == [1, 2, 5]
    and old_queries == queries[:3],
)
check("ordinary-receive-budget-retained", old_capacities[0] == 64 * 1024 * 1024)
for failure in ["transport", "oversized", "empty"]:
    rc, parts, asked, _, sent = run(failure=failure)
    check(failure + "-before-any-emission", rc == -2 and not parts and not sent and len(asked) == 3)
rc, parts, _, _, sent = run(failure="collector")
check("partial-collector-failure-discards-all-parts", rc == -3 and not parts and sent == [1, 2, 5])

variants = []
for name, updates in [
    ("selected-config", {"config_params": [19]}),
    ("getter", {"get_methods": [{"method": "seqno"}]}),
    ("masterchain-account", {"account": "-1:" + request_object["account"].split(":")[1]}),
]:
    value = dict(request_object)
    value.update(updates)
    variants.append((name, {"raw_request": json.dumps(value).encode()}))
no_account = dict(request_object)
no_account.pop("account")
variants.append(("no-account", {"raw_request": json.dumps(no_account).encode()}))
historical = json.loads((root / "request.json").read_bytes())
historical["mode"] = "historical"
variants.append(("historical", {"raw_request": json.dumps(historical).encode(), "raw_state": b""}))
variants.append(("no-prior-live-state", {"raw_state": b""}))
wrong_state = json.loads(state)
wrong_state["anchor"]["root_hash"] = "11" * 32
variants.append(("wrong-anchor-state", {"raw_state": json.dumps(wrong_state).encode()}))
variants.append(("oversized-request", {"raw_request": b" " * (1024 * 1024 + 1)}))
for name, kwargs in variants:
    rc, parts, asked, _, sent = run(**kwargs)
    check(name + "-refused-before-callback", rc == -1 and not parts and not asked and not sent)


class Part(c.Structure):
    _fields_ = [("kind", c.c_uint32), ("data", c.c_void_p), ("size", c.c_size_t)]


simulate = library.tos_proof_simulate_self_pay_embedded
simulate.restype = c.c_int
simulate.argtypes = [
    c.c_char_p,
    c.c_size_t,
    c.c_char_p,
    c.c_size_t,
    c.c_char_p,
    c.c_size_t,
    c.c_int64,
    c.POINTER(Part),
    c.c_size_t,
    c.c_char_p,
    c.c_size_t,
    c.c_void_p,
    c.c_size_t,
    c.POINTER(c.c_size_t),
    c.c_void_p,
    c.c_size_t,
    c.POINTER(c.c_size_t),
]


def authenticate(items):
    buffers = [c.create_string_buffer(data) for _, data in items]
    parts = (Part * len(items))(
        *[
            Part(kind, c.cast(buf, c.c_void_p), len(data))
            for (kind, data), buf in zip(items, buffers)
        ]
    )
    output, next_state = c.create_string_buffer(2 * 1024 * 1024), c.create_string_buffer(4096)
    size, used = c.c_size_t(), c.c_size_t()
    code = simulate(
        anchor,
        len(anchor),
        request,
        len(request),
        state,
        len(state),
        clock,
        parts,
        len(items),
        message,
        len(message),
        output,
        len(output),
        c.byref(size),
        next_state,
        len(next_state),
        c.byref(used),
    )
    if code != 0:
        assert not size.value and not used.value and not any(output.raw) and not any(next_state.raw)
        return code, None
    assert used.value and size.value
    return code, json.loads(output.raw[: size.value])


rc, estimate = authenticate(material)
check(
    "collected-material-authenticates-and-executes",
    rc == 0
    and estimate["scope"] == "local_estimate"
    and estimate["status"] == "executed"
    and estimate["message_bytes_hash"] == hashlib.sha256(message).hexdigest(),
)
damaged = [(kind, b"not a proof" if kind == 6 else data) for kind, data in material]
check("acquisition-is-not-authentication", authenticate(damaged)[0] == -2)
