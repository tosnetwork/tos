#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Exercise the real locked simulation/commit boundary with public chain inputs."""

import ctypes as c
import fcntl
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

library = c.CDLL(sys.argv[1])
root = Path(sys.argv[2])
anchor = (root / "anchor.json").read_bytes()
request = (root / "request.json").read_bytes()
message = (root / "message.boc").read_bytes()
clock = int((root / "clock.txt").read_text())
Query = c.CFUNCTYPE(
    c.c_int, c.c_void_p, c.c_void_p, c.c_size_t, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)
)


class Part(c.Structure):
    _fields_ = [("kind", c.c_uint32), ("data", c.c_void_p), ("size", c.c_size_t)]


verify = library.tos_proof_verify_live_persisted
verify.restype = c.c_int
verify.argtypes = [
    c.c_char_p,
    c.c_int,
    c.c_char_p,
    c.c_size_t,
    c.c_char_p,
    c.c_size_t,
    c.c_int64,
    c.POINTER(Part),
    c.c_size_t,
    c.c_void_p,
    c.c_size_t,
    c.POINTER(c.c_size_t),
]
simulate = library.tos_proof_acquire_simulate_self_pay_persisted
simulate.restype = c.c_int
simulate.argtypes = [
    c.c_char_p,
    c.c_char_p,
    c.c_size_t,
    c.c_char_p,
    c.c_size_t,
    c.c_int64,
    Query,
    c.c_void_p,
    c.c_void_p,
    c.c_size_t,
    c.c_void_p,
    c.c_size_t,
    c.POINTER(c.c_size_t),
]


def check(name, condition):
    print("PERSISTED_SIMULATION_CASE", name, "PASS" if condition else "FAIL", flush=True)
    assert condition, name


def enroll(directory):
    files = [(1, "masterchain-info.tl"), (2, "chain-0000.tl"), (5, "account.tl")]
    buffers = [c.create_string_buffer((root / "material" / name).read_bytes()) for _, name in files]
    parts = (Part * len(files))(
        *[
            Part(kind, c.cast(buf, c.c_void_p), len(buf.raw) - 1)
            for (kind, _), buf in zip(files, buffers)
        ]
    )
    output, used = c.create_string_buffer(2 << 20), c.c_size_t()
    rc = verify(
        os.fsencode(directory),
        1,
        anchor,
        len(anchor),
        request,
        len(request),
        clock,
        parts,
        len(parts),
        output,
        len(output),
        c.byref(used),
    )
    assert rc == 0 and json.loads(output.raw[: used.value])["status"] == "verified", rc


def call(
    directory,
    *,
    failure=None,
    now=clock,
    raw_message=message,
    raw_request=request,
    contention=False,
    result_capacity=2 << 20,
):
    asked, errors, competing = [], [], []

    @Query
    def query(context, data, size, output, capacity, used):
        try:
            raw = c.string_at(data, size)
            assert message not in raw
            asked.append(raw)
            if contention and len(asked) == 1:
                competing.append(call(directory)[0])
            # Bare blockIdExt is 80 bytes; these are the complete request sizes.
            name = {
                4: "masterchain-info.tl",
                168: "chain-0000.tl",
                120: "account.tl",
                88: "exec-config.tl",
            }[size]
            if failure == "transport" and name == "exec-config.tl":
                return -1
            value = (
                b"not a proof"
                if failure == "proof" and name == "exec-config.tl"
                else (root / "material" / name).read_bytes()
            )
            assert 0 < len(value) <= capacity
            c.memmove(output, value, len(value))
            used[0] = len(value)
            return 0
        except Exception as error:
            errors.append(str(error))
            return -1

    output, used = c.create_string_buffer(b"x" * (2 << 20)), c.c_size_t(99)
    buf = c.create_string_buffer(raw_message) if raw_message else None
    rc = simulate(
        os.fsencode(directory),
        anchor,
        len(anchor),
        raw_request,
        len(raw_request),
        now,
        query,
        None,
        buf,
        len(raw_message),
        output,
        result_capacity,
        c.byref(used),
    )
    assert not errors, errors
    if rc:
        assert used.value == 0 and not any(output.raw[:result_capacity]), "failure leaked estimate"
    return rc, output.raw[: used.value], asked, competing


with tempfile.TemporaryDirectory(prefix="tos-simulation-persisted-") as name:
    directory = Path(name).resolve()
    check(
        "no-implicit-enrollment",
        call(directory)[0] == -7 and not (directory / "initialized").exists(),
    )
    enroll(directory)
    state = directory / "checkpoint.json"
    before = state.read_bytes()
    rc, _, asked, _ = call(directory, result_capacity=0)
    check(
        "zero-result-capacity-before-acquisition",
        rc == -3 and not asked and state.read_bytes() == before,
    )
    rc, result, _, competing = call(directory, contention=True)
    value = json.loads(result)
    check(
        "exact-message-local-estimate",
        rc == 0
        and value["scope"] == "local_estimate"
        and value["status"] == "executed"
        and value["message_bytes_hash"] == hashlib.sha256(message).hexdigest(),
    )
    check("lock-held-during-acquisition", competing == [-8])
    check(
        "checkpoint-present-before-publication", json.loads(state.read_text())["head"]["seqno"] == 6
    )
    before = state.read_bytes()
    check(
        "transport-failure-no-state-change",
        call(directory, failure="transport")[0] == -2 and state.read_bytes() == before,
    )
    check(
        "proof-failure-no-state-change",
        call(directory, failure="proof")[0] == -2 and state.read_bytes() == before,
    )
    check(
        "stale-proof-no-state-change",
        call(directory, now=clock + 3600)[0] == -2 and state.read_bytes() == before,
    )
    check("empty-message-before-callback", call(directory, raw_message=b"")[0:3:2] == (-1, []))
    with (directory / "checkpoint.lock").open("r+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        check("busy-distinct-from-resource", call(directory)[0] == -8)
    if "--sync-fault" in sys.argv:
        os.environ["PROOF_PERSIST_FAULT_DIR"] = str(directory)
        check("first-checkpoint-sync-succeeds", call(directory)[0] == 0)
        check("directory-sync-failure-no-estimate", call(directory)[0] == -7)
    else:
        (directory / "checkpoint.tmp").mkdir()
        check("commit-failure-no-estimate", call(directory)[0] == -7)
        (directory / "checkpoint.tmp").rmdir()
    state.unlink()
    rc, _, asked, _ = call(directory)
    check("missing-enrolled-state-before-callback", rc == -7 and not asked and not state.exists())
