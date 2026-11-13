# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""crypto harness: one cryptographic or consensus-identity function (schema/harness/crypto-v1.schema.json).

A context names ``scheme`` and ``operation`` and gives that operation's ``inputs``. Variable-length
byte inputs are base64 (so the blob store can hold large ones), fixed 32-byte identifiers are 64
lowercase hex digits, and integers that may exceed 2^53 are decimal strings. Optional ``edits``
change named byte inputs before the call (xor one byte, resize, fill), so a mutation family of
one large signature stores that signature once.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "crypto"
CONTEXT_REQUIRED = frozenset({"scheme", "operation", "inputs"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED | {"edits"}
EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "verdict": frozenset({"outcome", "verdict"}),
    "bytes": frozenset({"outcome", "output"}),
    "integer": frozenset({"outcome", "value"}),
    "boolean": frozenset({"outcome", "value"}),
    "record": frozenset({"outcome", "fields"}),
    "rejected": frozenset({"outcome", "reason"}),
}

VERDICTS = frozenset({"valid", "invalid", "malformed_input", "backend_error"})
B64_RE = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
HEX32_RE = re.compile(r"^[0-9a-f]{64}$")
U64_RE = re.compile(r"^(?:0|[1-9][0-9]{0,19})$")
DECIMAL_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
REASON_RE = re.compile(r"^[a-z0-9_]{1,64}$")
FIELD_RE = re.compile(r"^[a-z0-9_]{1,64}$")
MAX_INPUT_BYTES = 1 << 20
MAX_RESIZE = 1 << 16
MAX_EDITS = 16
MAX_VALIDATORS = 1024
MAX_DESCRIPTORS = 64
I32 = (-(1 << 31), (1 << 31) - 1)
U32 = (0, (1 << 32) - 1)
U16 = (0, (1 << 16) - 1)

SURFACES = ("simplex", "validator_election", "validator_config_vote", "config_admin")

# Input kinds: "bytes", "hex32", "u64", "bool", "decimal", ("int", low, high), ("enum", values...),
# "validators", "validator_set", "block_id", "state8", "descriptors". A key ending in "?" is optional.
Kind = str | tuple[Any, ...]
OPERATIONS: dict[str, dict[str, Kind]] = {
    "ed25519/verify": {"message": "bytes", "signature": "bytes", "public_key": "bytes"},
    "mldsa44/verify": {
        "message": "bytes",
        "context": "bytes",
        "signature": "bytes",
        "public_key": "bytes",
    },
    "mldsa44/verify_consensus": {
        "surface": ("enum", *SURFACES),
        "message": "bytes",
        "signature": "bytes",
        "public_key": "bytes",
    },
    "mldsa44/derive_key_id": {"algorithm_id": ("int", *U16), "public_key": "bytes"},
    "falcon512/verify_padded": {"message": "bytes", "signature": "bytes", "public_key": "bytes"},
    "slhdsa128s/verify": {
        "message": "bytes",
        "context": "bytes",
        "signature": "bytes",
        "public_key": "bytes",
    },
    "lms_fee/verify": {"message": "bytes", "signature": "bytes", "public_key": "bytes"},
    "lms_fee/worst_compressions": {"public_key": "bytes", "message_bytes": "u64"},
    "sha256/digest": {"data": "bytes"},
    "poseidon2/permute": {"state": "state8"},
    "poseidon2/manifest_digest": {},
    "quorum/threshold": {"total_weight": "u64"},
    "quorum/has_quorum": {"signed_weight": "u64", "total_weight": "u64"},
    "validator_session/members": {"validators": "validators"},
    "validator_session/identity": {
        "global_id": ("int", *I32),
        "validator_options_hash": "hex32",
        "simplex_config_cell_hash": "hex32",
        "workchain": ("int", *I32),
        "shard": "u64",
        "catchain_seqno": ("int", *U32),
        "vertical_seqno": ("int", *U32),
        "last_key_block_seqno": ("int", *U32),
        "new_catchain_ids": "bool",
        "validators": "validators",
    },
    "validator_session/config_hash": {
        "global_id": ("int", *I32),
        "validator_options_hash": "hex32",
        "simplex_config_cell_hash": "hex32",
    },
    "validator_session/options_hash": {
        "proto_version": ("int", *U32),
        "idle_timeout": "decimal",
        "max_deps": ("int", *U32),
        "max_serialized_block_size": ("int", *U32),
        "block_hash_covers_data": "bool",
        "max_block_height_coeff": "u64",
        "debug_disable_db": "bool",
        "round_candidates": ("int", *U32),
        "next_candidate_delay": "decimal",
        "round_attempt_duration": ("int", *U32),
        "max_round_attempts": ("int", *U32),
        "max_block_size": ("int", *U32),
        "max_collated_data_size": ("int", *U32),
        "new_catchain_ids": "bool",
    },
    "pq_bytes/pack": {"data": "bytes", "max_bytes": ("int", 0, MAX_INPUT_BYTES)},
    "pq_bytes/unpack": {"boc": "bytes", "max_bytes": ("int", 0, MAX_INPUT_BYTES)},
    "consensus/simplex_data_to_sign": {
        "session_id": "hex32",
        "slot": ("int", *U32),
        "candidate": "bytes",
        "final": "bool",
        "block_id": "block_id",
    },
    "block_signatures/fetch": {"boc": "bytes", "validator_set?": "validator_set"},
    "block_signatures/fetch_tl": {"carrier": ("enum", "node", "lite"), "wire": "bytes"},
    "config43/parse": {"boc": "bytes"},
    "validator_set/unpack": {
        "set?": "bytes",
        "descriptors?": "descriptors",
        "utime_since?": ("int", *U32),
        "utime_until?": ("int", *U32),
        "total?": ("int", *U16),
        "main?": ("int", *U16),
        "total_weight?": "u64",
    },
    "elector/stake_preimage": {
        "global_id": ("int", *I32),
        "stake_at": ("int", *U32),
        "max_factor": ("int", *U32),
        "src_addr": "hex32",
        "adnl_addr": "hex32",
    },
    "elector/config_vote_preimage": {
        "global_id": ("int", *I32),
        "validator_set_id": "hex32",
        "validator_id": "hex32",
        "idx": ("int", *U16),
        "proposal_hash": "hex32",
    },
    "elector/complaint_vote_preimage": {
        "global_id": ("int", *I32),
        "validator_set_id": "hex32",
        "validator_id": "hex32",
        "idx": ("int", *U16),
        "election_id": ("int", *U32),
        "complaint_hash": "hex32",
    },
}

SET_WRAPPER_KEYS = frozenset(
    {"descriptors", "utime_since", "utime_until", "total", "main", "total_weight"}
)


def input_keys(operation: str) -> tuple[set[str], set[str]]:
    """(required, allowed) input keys of an operation."""
    spec = OPERATIONS[operation]
    required = {k for k in spec if not k.endswith("?")}
    allowed = {k.removesuffix("?") for k in spec}
    return required, allowed


def kind_of(operation: str, key: str) -> Kind:
    spec = OPERATIONS[operation]
    return spec[key] if key in spec else spec[f"{key}?"]


def b64_bytes(value: object, where: str) -> None:
    if isinstance(value, dict):
        t.boc(value, where)  # a blob reference
        return
    if not isinstance(value, str) or not B64_RE.match(value):
        raise t.FixtureError(f"{where}: base64 required")
    if len(value) // 4 * 3 > MAX_INPUT_BYTES:
        raise t.FixtureError(f"{where}: too large")


def hex32(value: object, where: str) -> None:
    t.text(value, HEX32_RE, where)


def u64(value: object, where: str) -> None:
    if int(t.text(value, U64_RE, where)) >= 1 << 64:
        raise t.FixtureError(f"{where}: exceeds uint64")


def descriptor(value: object, where: str) -> None:
    item = t.obj(value, where)
    kind = item.get("kind")
    if kind == "classical":
        t.keys(
            item,
            {"kind", "public_key", "weight", "adnl"},
            {"kind", "public_key", "weight", "adnl"},
            where,
        )
        hex32(item["public_key"], f"{where}.public_key")
    elif kind == "pq":
        keys = {"kind", "validator_id", "algorithm_id", "key_id", "public_key", "weight", "adnl"}
        t.keys(item, keys, keys, where)
        hex32(item["validator_id"], f"{where}.validator_id")
        hex32(item["key_id"], f"{where}.key_id")
        t.integer(item["algorithm_id"], f"{where}.algorithm_id", *U16)
        b64_bytes(item["public_key"], f"{where}.public_key")
    else:
        raise t.FixtureError(f"{where}.kind: classical or pq")
    u64(item["weight"], f"{where}.weight")
    hex32(item["adnl"], f"{where}.adnl")


def check_kind(kind: Kind, value: object, where: str) -> None:
    if isinstance(kind, tuple):
        if kind[0] == "int":
            t.integer(value, where, kind[1], kind[2])
        elif value not in kind[1:]:
            raise t.FixtureError(f"{where}: one of {list(kind[1:])}")
    elif kind == "bytes":
        b64_bytes(value, where)
    elif kind == "hex32":
        hex32(value, where)
    elif kind == "u64":
        u64(value, where)
    elif kind == "bool":
        t.boolean(value, where)
    elif kind == "decimal":
        t.text(value, DECIMAL_RE, where)
    elif kind == "validators":
        for i, item in enumerate(t.array(value, where, MAX_VALIDATORS)):
            descriptor(item, f"{where}[{i}]")
    elif kind == "validator_set":
        vset = t.obj(value, where)
        t.keys(vset, {"catchain_seqno", "validators"}, {"catchain_seqno", "validators"}, where)
        t.integer(vset["catchain_seqno"], f"{where}.catchain_seqno", *U32)
        items = t.array(vset["validators"], f"{where}.validators", MAX_VALIDATORS)
        if not items:
            raise t.FixtureError(f"{where}.validators: at least one validator")
        for i, item in enumerate(items):
            descriptor(item, f"{where}.validators[{i}]")
    elif kind == "block_id":
        block = t.obj(value, where)
        keys = {"workchain", "shard", "seqno", "root_hash", "file_hash"}
        t.keys(block, keys, keys, where)
        t.integer(block["workchain"], f"{where}.workchain", *I32)
        u64(block["shard"], f"{where}.shard")
        t.integer(block["seqno"], f"{where}.seqno", *U32)
        hex32(block["root_hash"], f"{where}.root_hash")
        hex32(block["file_hash"], f"{where}.file_hash")
    elif kind == "state8":
        items = t.array(value, where, 8)
        if len(items) != 8:
            raise t.FixtureError(f"{where}: 8 field elements")
        for i, item in enumerate(items):
            hex32(item, f"{where}[{i}]")
    elif kind == "descriptors":
        items = t.array(value, where, MAX_DESCRIPTORS)
        if not items:
            raise t.FixtureError(f"{where}: at least one descriptor")
        for i, item in enumerate(items):
            b64_bytes(item, f"{where}[{i}]")
    else:
        raise t.FixtureError(f"{where}: unknown input kind {kind!r}")


def validate_edit(edit: object, byte_inputs: set[str], where: str) -> None:
    item = t.obj(edit, where)
    op = item.get("op")
    if op == "xor":
        t.keys(item, {"input", "op", "offset", "value"}, {"input", "op", "offset", "value"}, where)
        t.integer(item["offset"], f"{where}.offset", 0, MAX_INPUT_BYTES - 1)
        t.integer(item["value"], f"{where}.value", 1, 255)
    elif op == "resize":
        t.keys(item, {"input", "op", "length", "value"}, {"input", "op", "length", "value"}, where)
        t.integer(item["length"], f"{where}.length", 0, MAX_RESIZE)
        t.integer(item["value"], f"{where}.value", 0, 255)
    elif op == "fill":
        t.keys(item, {"input", "op", "value"}, {"input", "op", "value"}, where)
        t.integer(item["value"], f"{where}.value", 0, 255)
    else:
        raise t.FixtureError(f"{where}.op: xor, resize or fill")
    if item["input"] not in byte_inputs:
        raise t.FixtureError(f"{where}.input: not a byte input of this operation")


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    t.keys(ctx, set(CONTEXT_REQUIRED), set(CONTEXT_ALLOWED), where)
    operation = f"{ctx['scheme']}/{ctx['operation']}"
    if operation not in OPERATIONS:
        raise t.FixtureError(f"{where}: unknown operation {operation!r}")
    inputs = t.obj(ctx["inputs"], f"{where}.inputs")
    required, allowed = input_keys(operation)
    t.keys(inputs, required, allowed, f"{where}.inputs")
    for key, value in inputs.items():
        check_kind(kind_of(operation, key), value, f"{where}.inputs.{key}")
    if operation == "validator_set/unpack":
        wrapped = SET_WRAPPER_KEYS & inputs.keys()
        if ("set" in inputs) == bool(wrapped) or (wrapped and wrapped != SET_WRAPPER_KEYS):
            raise t.FixtureError(
                f"{where}.inputs: either set, or descriptors with every header field"
            )
    if "edits" in ctx:
        byte_inputs = {k for k in inputs if kind_of(operation, k) == "bytes"}
        edits = t.array(ctx["edits"], f"{where}.edits", MAX_EDITS)
        if not edits:
            raise t.FixtureError(f"{where}.edits: at least one edit")
        for i, edit in enumerate(edits):
            validate_edit(edit, byte_inputs, f"{where}.edits[{i}]")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    outcome = t.outcome_shape(eff, EFFECT_SHAPES, where)
    if outcome == "verdict" and eff["verdict"] not in VERDICTS:
        raise t.FixtureError(f"{where}.verdict: one of {sorted(VERDICTS)}")
    if outcome == "bytes":
        t.text(eff["output"], t.HEX_RE, f"{where}.output")
    if outcome == "integer":
        u64(eff["value"], f"{where}.value")
    if outcome == "boolean":
        t.boolean(eff["value"], f"{where}.value")
    if outcome == "rejected":
        t.text(eff["reason"], REASON_RE, f"{where}.reason")
    if outcome == "record":
        fields = t.obj(eff["fields"], f"{where}.fields")
        if not fields:
            raise t.FixtureError(f"{where}.fields: at least one field")
        for key, value in fields.items():
            t.text(key, FIELD_RE, f"{where}.fields key")
            t.any_text(value, f"{where}.fields.{key}")


def decode(value: str) -> bytes:
    """Bytes of a base64 input (used by the migration scripts)."""
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise t.FixtureError(f"not base64: {exc}") from exc
