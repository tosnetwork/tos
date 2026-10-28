#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Exercise the actual local simulation C ABI and its two-output refusal contract."""

import ctypes as c
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc  # noqa: E402


class Part(c.Structure):
    _fields_ = [("kind", c.c_uint32), ("data", c.c_void_p), ("size", c.c_size_t)]


library = c.CDLL(sys.argv[1])
root = Path(sys.argv[2])
old = Path(sys.argv[3])
import_root = Path(sys.argv[4])
simulate = library.tos_proof_simulate_self_pay_embedded
simulate.restype = c.c_int
simulate.argtypes = [
    c.c_void_p,
    c.c_size_t,
    c.c_void_p,
    c.c_size_t,
    c.c_void_p,
    c.c_size_t,
    c.c_int64,
    c.POINTER(Part),
    c.c_size_t,
    c.c_void_p,
    c.c_size_t,
    c.c_void_p,
    c.c_size_t,
    c.POINTER(c.c_size_t),
    c.c_void_p,
    c.c_size_t,
    c.POINTER(c.c_size_t),
]
anchor = (root / "anchor.json").read_bytes()
request = (root / "request.json").read_bytes()
state = json.dumps({"interface": "tos-proof-verify-state/1", "anchor": json.loads(anchor)}).encode()
message = (root / "message.boc").read_bytes()
clock = int((root / "clock.txt").read_text())


def load(directory):
    names = [(1, "masterchain-info.tl"), (5, "account.tl"), (6, "exec-config.tl")]
    result = [
        (kind, (directory / name).read_bytes())
        for kind, name in names
        if (directory / name).exists()
    ]
    result.extend((2, p.read_bytes()) for p in sorted(directory.glob("chain-*.tl")))
    result.extend((3, p.read_bytes()) for p in sorted(directory.glob("descent-*.tl")))
    return result


parts = load(root / "material")


def call(
    *,
    a=anchor,
    r=request,
    s=state,
    msg=message,
    items=parts,
    now=clock,
    capacity=65536,
    state_capacity=4096,
):
    buffers = [c.create_string_buffer(value, len(value)) for _, value in items]
    material = (Part * len(items))(
        *[Part(kind, c.cast(b, c.c_void_p), len(value)) for (kind, value), b in zip(items, buffers)]
    )
    output = c.create_string_buffer(b"x" * (capacity + 16), capacity + 16)
    next_state = c.create_string_buffer(b"y" * (state_capacity + 16), state_capacity + 16)
    size, used = c.c_size_t(99), c.c_size_t(99)
    code = simulate(
        a,
        len(a),
        r,
        len(r),
        s,
        len(s),
        now,
        material,
        len(items),
        msg,
        len(msg),
        output,
        capacity,
        c.byref(size),
        next_state,
        state_capacity,
        c.byref(used),
    )
    assert output.raw[capacity:] == b"x" * 16
    assert next_state.raw[state_capacity:] == b"y" * 16
    if code:
        assert size.value == used.value == 0, "failure-lengths-not-cleared"
        assert output.raw[:capacity] == b"\0" * capacity, "result-output-not-cleared"
        assert next_state.raw[:state_capacity] == b"\0" * state_capacity, (
            "next-state-output-not-cleared"
        )
        return code, None, None
    assert 0 < size.value <= capacity and 0 < used.value <= state_capacity
    value = json.loads(output.raw[: size.value])
    next_value = json.loads(next_state.raw[: used.value])
    assert value["interface"] == "tos-self-pay-simulation/1" and value["scope"] == "local_estimate"
    assert value["message_bytes_hash"] == hashlib.sha256(msg).hexdigest(), (
        "exact-message-bytes-hash"
    )
    assert value["message_root_hash"] == from_boc(msg).hash.hex()
    assert next_value["interface"] == "tos-proof-verify-state/1"
    expected_anchor = json.loads(a)
    returned_anchor = dict(next_value["anchor"])
    for key in ("root_hash", "file_hash"):
        expected_anchor[key] = expected_anchor[key].lower()
        returned_anchor[key] = returned_anchor[key].lower()
    assert returned_anchor == expected_anchor
    forbidden = {
        "vm_log",
        "message_boc",
        "transaction_boc",
        "state_boc",
        "body",
        "private_key",
        "signature",
    }

    def private(obj):
        if isinstance(obj, dict):
            assert not forbidden.intersection(obj), "private-field-in-local-estimate:" + ",".join(
                sorted(forbidden.intersection(obj))
            )
            for item in obj.values():
                private(item)
        elif isinstance(obj, list):
            for item in obj:
                private(item)

    private(value)
    return code, value, next_value


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    print("SELF_PAY_SIMULATION_ABI_CASE", name, "PASS", flush=True)


code, good, next_value = call()
expected = json.loads((root / "expected.json").read_text())
check("authenticated-execution", code == 0 and good["status"] == "executed")
check("bound-target", good["target"] == json.loads(request)["target"])
check(
    "observed-account",
    good["account"]["address"] == expected["account"]
    and good["account"]["observed_balance"] == expected["balance_before"]
    and good["account"]["exists"]
    and len(good["account"]["state_hash"]) == 64,
)
tx = good["transaction"]
check(
    "fee-payment-poststate",
    tx["codec"]["hash"] == expected["transaction_hash"]
    and tx["codec"]["fees"] == expected["fees"]
    and tx["codec"]["out_msgs"][0]["destination"] == expected["recipient"]
    and tx["codec"]["out_msgs"][0]["value"] == expected["value"]
    and tx["expected_balance"] == expected["balance_after"]
    and len(tx["expected_state_hash"]) == 64,
)
check(
    "u64-context-strings",
    isinstance(good["context"]["block_start_lt"], str)
    and int(good["context"]["transaction_lt"]) == int(good["context"]["block_start_lt"]) + 1,
)
check("deterministic-repeat", call()[1:] == (good, next_value))
forged = (root / "forged-message.boc").read_bytes()
code, refused, _ = call(msg=forged)
check(
    "forged-no-transaction",
    code == 0
    and refused["status"] == "not_accepted"
    and refused["vm_exit_code"] == 1808
    and "transaction" not in refused,
)

# Widen the valid BoC offset width without changing any cell or message hash.
w, ow = message[4], message[5]
offset = 6 + 3 * w
alternate = message[:5] + bytes([ow + 1]) + message[6:offset] + b"\0" + message[offset:]
code, different, _ = call(msg=alternate)
check(
    "exact-wire-binding",
    code == 0
    and different["message_root_hash"] == good["message_root_hash"]
    and different["message_bytes_hash"] != good["message_bytes_hash"]
    and different["seed"] != good["seed"],
)
wrong_destination = (
    Cell()
    .uint(8, 4)
    .addr((0, int("12" * 32, 16)))
    .coins(0)
    .uint(0, 1)
    .uint(1, 1)
    .ref(from_boc(message).refs[0])
    .boc()
)
for name, kwargs, status in [
    ("result-too-small", {"capacity": 1}, -3),
    ("next-state-too-small", {"state_capacity": 1}, -3),
    ("both-too-small", {"capacity": 1, "state_capacity": 1}, -3),
    ("zero-capacity", {"capacity": 0}, -3),
    ("missing-state", {"s": b""}, -1),
    ("wrong-destination", {"msg": wrong_destination}, -1),
    ("malformed-message", {"msg": b"bad"}, -1),
    ("malformed-request", {"r": b"{"}, -1),
    ("malformed-anchor", {"a": b"{"}, -1),
    ("malformed-state", {"s": b"{"}, -1),
    ("zero-clock", {"now": 0}, -1),
    ("clock-overflow", {"now": 1 << 40}, -1),
    ("stale-proof", {"now": clock + 1000}, -2),
    ("duplicate-account", {"items": parts + [next(p for p in parts if p[0] == 5)]}, -1),
    ("forbidden-params-material", {"items": parts + [(4, b"bad")]}, -1),
    ("forbidden-library-material", {"items": parts + [(7, b"bad")]}, -1),
    ("missing-config", {"items": [p for p in parts if p[0] != 6]}, -2),
    ("missing-account", {"items": [p for p in parts if p[0] != 5]}, -2),
    ("bad-account", {"items": [(k, b"bad" if k == 5 else v) for k, v in parts]}, -2),
    ("bad-config", {"items": [(k, b"bad" if k == 6 else v) for k, v in parts]}, -2),
    ("chain-count-limit", {"items": [(2, b"x")] * 1025}, -5),
    ("descent-count-limit", {"items": [(3, b"x")] * 17}, -5),
    ("message-byte-limit", {"msg": b"x" * ((1 << 20) + 1)}, -5),
    ("config-reply-limit", {"items": [(6, b"x" * ((16 << 20) + 1))]}, -5),
]:
    check(name, call(**kwargs)[0] == status)

# Equal-sized legal individual replies exceed the aggregate once the borrowed
# JSON/state/message are counted. The native entry must refuse before copying.
bulk = b"x" * (16 << 20)
check(
    "aggregate-input-budget",
    call(items=[(1, bulk), (2, bulk), (2, bulk), (6, bulk)], capacity=1, state_capacity=1)[0] == -5,
)
del bulk

for name, change in [
    ("historical-request", {"mode": "historical"}),
    ("getter-request", {"get_methods": [{"method": "seqno"}]}),
    ("selected-params-request", {"config_params": [8]}),
]:
    modified = json.loads(request)
    modified.update(change)
    check(name, call(r=json.dumps(modified).encode())[0] == -1)
other_state = json.loads(state)
other_state["anchor"]["root_hash"] = "00" * 32
check("wrong-state-anchor", call(s=json.dumps(other_state).encode())[0] == -1)
# The old Elector corpus authenticates VM18; profile classification must precede
# version-specific account/context preparation, but follow message validation.
historical = json.loads((old / "historical-request.json").read_text())
old_request = json.dumps(
    {"mode": "live", "max_age_seconds": 300, "account": historical["account"]}
).encode()
wc, address = historical["account"].split(":")
old_message = (
    Cell().uint(8, 4).addr((int(wc), int(address, 16))).coins(0).uint(0, 1).uint(0, 1).boc()
)
old_parts = load(old / "live")
old_parts = [(k, v) for k, v in old_parts if k not in (5, 6)] + [
    (5, (old / "historical/account.tl").read_bytes()),
    (6, (old / "historical/exec-config.tl").read_bytes()),
]
old_arguments = dict(
    a=(old / "anchor.json").read_bytes(),
    r=old_request,
    s=(old / "live-state.json").read_bytes(),
    items=old_parts,
    now=1791200932,
)
code, unsupported, _ = call(msg=old_message, **old_arguments)
check(
    "unsupported-stage-fields",
    code == 0
    and unsupported["status"] == "unsupported"
    and unsupported["reason"] == "unsupported_profile"
    and "context" not in unsupported
    and "seed" not in unsupported
    and "transaction" not in unsupported,
)
check("unsupported-does-not-mask-bad-message", call(msg=b"bad", **old_arguments)[0] == -1)
check("restored-after-refusals", call()[1:] == (good, next_value))

import_anchor = (import_root / "anchor.json").read_bytes()
import_state = json.dumps(
    {"interface": "tos-proof-verify-state/1", "anchor": json.loads(import_anchor)}
).encode()
code, imported, _ = call(
    a=import_anchor,
    r=(import_root / "request.json").read_bytes(),
    s=import_state,
    msg=(import_root / "message.boc").read_bytes(),
    items=load(import_root / "material"),
    now=int((import_root / "clock.txt").read_text()),
)
check(
    "authenticated-import-no-transaction",
    code == 0
    and imported["status"] == "import_rejected"
    and "transaction" not in imported
    and "vm_exit_code" not in imported,
)
check(
    "authenticated-absence-no-invented-hash",
    imported["account"]["exists"] is False
    and imported["account"]["observed_balance"] == "0"
    and "state_hash" not in imported["account"],
)

version_root = ROOT / "test/pq-native/data/self-pay-simulation-v17"
version_anchor = (version_root / "anchor.json").read_bytes()
version_arguments = dict(
    a=version_anchor,
    r=(version_root / "request.json").read_bytes(),
    s=json.dumps(
        {"interface": "tos-proof-verify-state/1", "anchor": json.loads(version_anchor)}
    ).encode(),
    items=load(version_root / "material"),
    now=int((version_root / "clock.txt").read_text()),
)
code, future, _ = call(msg=(version_root / "message.boc").read_bytes(), **version_arguments)
check(
    "future-version-before-context",
    code == 0
    and future["status"] == "unsupported"
    and future["reason"] == "unsupported_profile"
    and "context" not in future
    and "seed" not in future
    and "transaction" not in future,
)
check("future-version-does-not-mask-bad-message", call(msg=b"bad", **version_arguments)[0] == -1)
mixed_arguments = dict(version_arguments)
mixed_arguments["items"] = [
    (k, next(value for kind, value in parts if kind == 6) if k == 6 else v)
    for k, v in version_arguments["items"]
]
check(
    "future-version-still-binds-config",
    call(msg=(version_root / "message.boc").read_bytes(), **mixed_arguments)[0] == -2,
)

if len(sys.argv) == 6:
    import copy

    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(json.loads(Path(sys.argv[5]).read_text()))
    validator.check_schema(validator.schema)
    for value in (good, refused, unsupported, imported, future):
        validator.validate(value)
    mutations = []
    value = copy.deepcopy(good)
    value["vm_log"] = "private"
    mutations.append(value)
    value = copy.deepcopy(refused)
    value["transaction"] = good["transaction"]
    mutations.append(value)
    value = copy.deepcopy(unsupported)
    value["vm_exit_code"] = 0
    mutations.append(value)
    value = copy.deepcopy(good)
    value.pop("transaction")
    mutations.append(value)
    value = copy.deepcopy(good)
    value["transaction"]["codec"]["in_msg"]["body"] = "private"
    mutations.append(value)
    value = copy.deepcopy(good)
    value["context"]["transaction_lt"] = 9007199254740993
    mutations.append(value)
    value = copy.deepcopy(good)
    value["account"]["exists"] = False
    mutations.append(value)
    value = copy.deepcopy(good)
    value["seed"] = "00" * 32
    mutations.append(value)
    for index, value in enumerate(mutations):
        check("schema-refusal-" + str(index), bool(list(validator.iter_errors(value))))
    check("schema-positive-results", True)
