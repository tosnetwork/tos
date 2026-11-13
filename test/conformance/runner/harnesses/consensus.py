# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""consensus harness: deterministic consensus operations (schema/harness/consensus-v1.schema.json).

The context field "op" selects the operation; each op has its own required keys, and its effect is one
of the outcomes below or {"outcome": "refused", "reason": <class>}.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

import fixture_types as t

NAME = "consensus"

DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")
SHARD_RE = re.compile(r"^[0-9a-f]{16}$")
REASON_RE = re.compile(r"^[a-z0-9_]{1,64}$")
MAX_VALIDATORS = 1024

OP_REQUIRED: dict[str, frozenset[str]] = {
    "quorum": frozenset({"total_weight", "signed_weight"}),
    "weight_total": frozenset({"weights"}),
    "protocol_version": frozenset({"protocol_version"}),
    "session": frozenset(
        {
            "global_id",
            "options",
            "simplex_config_hash",
            "shard",
            "catchain_seqno",
            "vertical_seqno",
            "last_key_block_seqno",
            "validators",
        }
    ),
    "validator_set": frozenset({"validators", "catchain_seqno", "shard"}),
    "vote": frozenset({"session_id", "slot", "candidate", "final", "block"}),
    "finality": frozenset({"validators", "catchain_seqno", "block", "expected_session_id", "role"}),
    "decode_proof": frozenset({"block_proof"}),
    "proof_link": frozenset({"key_block", "block", "is_key", "key_block_proof", "block_proof"}),
    "key_block_context": frozenset({"key_block", "block", "key_block_proof", "block_proof"}),
}
OP_OPTIONAL: dict[str, frozenset[str]] = {
    "vote": frozenset({"public_key", "signature"}),
    "finality": frozenset({"block_proof", "signature_set", "claimed_weight"}),
}

CONTEXT_REQUIRED = frozenset({"op"})
CONTEXT_ALLOWED = CONTEXT_REQUIRED.union(*OP_REQUIRED.values()).union(*OP_OPTIONAL.values())

OPTIONS_KEYS = frozenset(
    {
        "proto_version",
        "new_catchain_ids",
        "idle_timeout",
        "max_deps",
        "max_serialized_block_size",
        "block_hash_covers_data",
        "max_block_height_coeff",
        "debug_disable_db",
        "round_candidates",
        "next_candidate_delay",
        "round_attempt_duration",
        "max_round_attempts",
        "max_block_size",
        "max_collated_data_size",
    }
)
OPTIONS_BOOLS = frozenset({"new_catchain_ids", "block_hash_covers_data", "debug_disable_db"})
OPTIONS_DOUBLES = frozenset({"idle_timeout", "next_candidate_delay"})

EFFECT_SHAPES: dict[str | None, frozenset[str]] = {
    "quorum": frozenset({"outcome", "threshold", "has_quorum"}),
    "weight_total": frozenset({"outcome", "total"}),
    "protocol_version": frozenset(
        {
            "outcome",
            "supported",
            "enable_block_sync",
            "use_new_db_names",
            "observers_in_private_overlay",
            "enable_plumtree_broadcast",
            "max_supported",
        }
    ),
    "session": frozenset({"outcome", "options_hash", "session_config_hash", "session_id"}),
    "validator_set": frozenset({"outcome", "validator_set_hash", "total_weight", "threshold"}),
    "vote": frozenset({"outcome", "candidate_hash", "data_to_sign", "signature_check"}),
    "finalized": frozenset({"outcome", "weight", "total_weight", "threshold"}),
    "proof": frozenset(
        {
            "outcome",
            "seqno",
            "root_hash",
            "file_hash",
            "state_old_hash",
            "state_hash",
            "signature_set",
            "claimed_weight",
        }
    ),
    "linked": frozenset(
        {"outcome", "gen_utime", "expected_session_id", "verified_weight", "total_weight"}
    ),
    "context": frozenset(
        {
            "outcome",
            "global_id",
            "config_global_id",
            "options",
            "simplex_config_hash",
            "protocol_version",
            "gen_utime",
            "catchain_seqno",
            "vertical_seqno",
            "prev_key_block_seqno",
            "is_key",
            "header_validator_set_hash",
            "validator_set_hash",
            "total_weight",
            "validators",
            "session_id",
            "validator_path_session_id",
            "signature_set",
            "claimed_weight",
        }
    ),
    "refused": frozenset({"outcome", "reason"}),
}

U32 = 0xFFFFFFFF


def decimal(value: object, where: str) -> None:
    t.text(value, DECIMAL_RE, where)
    if int(str(value)) >= 1 << 64:
        raise t.FixtureError(f"{where}: above 2^64-1")


def hex_bytes(value: object, where: str) -> None:
    t.text(value, t.HEX_RE, where)


def shard(value: object, where: str) -> None:
    item = t.obj(value, where)
    t.keys(item, {"workchain", "shard"}, {"workchain", "shard"}, where)
    t.integer(item["workchain"], f"{where}.workchain", -(1 << 31), (1 << 31) - 1)
    t.text(item["shard"], SHARD_RE, f"{where}.shard")


def block_id(value: object, where: str) -> None:
    keys = {"workchain", "shard", "seqno", "root_hash", "file_hash"}
    item = t.obj(value, where)
    t.keys(item, keys, keys, where)
    t.integer(item["workchain"], f"{where}.workchain", -(1 << 31), (1 << 31) - 1)
    t.text(item["shard"], SHARD_RE, f"{where}.shard")
    t.integer(item["seqno"], f"{where}.seqno", 0, U32)
    t.cell_hash(item["root_hash"], f"{where}.root_hash")
    t.cell_hash(item["file_hash"], f"{where}.file_hash")


def validators(value: object, where: str) -> None:
    items = t.array(value, where, MAX_VALIDATORS)
    for i, raw in enumerate(items):
        at = f"{where}[{i}]"
        item = t.obj(raw, at)
        if "ed25519" in item:
            t.keys(item, {"ed25519", "weight", "adnl"}, {"ed25519", "weight", "adnl"}, at)
            t.cell_hash(item["ed25519"], f"{at}.ed25519")
        else:
            pq = {"validator_id", "key_id", "algorithm_id", "public_key", "weight", "adnl"}
            t.keys(item, pq, pq, at)
            t.cell_hash(item["validator_id"], f"{at}.validator_id")
            t.cell_hash(item["key_id"], f"{at}.key_id")
            t.integer(item["algorithm_id"], f"{at}.algorithm_id", 0, 0xFFFF)
            hex_bytes(item["public_key"], f"{at}.public_key")
        decimal(item["weight"], f"{at}.weight")
        t.cell_hash(item["adnl"], f"{at}.adnl")


def options(value: object, where: str) -> None:
    item = t.obj(value, where)
    t.keys(item, set(OPTIONS_KEYS), set(OPTIONS_KEYS), where)
    for key in OPTIONS_KEYS:
        if key in OPTIONS_BOOLS:
            t.boolean(item[key], f"{where}.{key}")
        elif key in OPTIONS_DOUBLES:
            if not isinstance(item[key], (int, float)) or isinstance(item[key], bool):
                raise t.FixtureError(f"{where}.{key}: number required")
        else:
            t.integer(item[key], f"{where}.{key}", 0, U32)


def signature_set(value: object, where: str, decoded: bool = False) -> None:
    """An explicit PQ signature set; the decoded form in a context effect also says whether it is final."""
    keys = {"catchain_seqno", "validator_set_hash", "session_id", "slot", "candidate", "signatures"}
    if decoded:
        keys.add("final")
    item = t.obj(value, where)
    t.keys(item, keys, keys, where)
    if decoded:
        t.boolean(item["final"], f"{where}.final")
    for key in ("catchain_seqno", "validator_set_hash", "slot"):
        t.integer(item[key], f"{where}.{key}", 0, U32)
    t.cell_hash(item["session_id"], f"{where}.session_id")
    hex_bytes(item["candidate"], f"{where}.candidate")
    for i, raw in enumerate(t.array(item["signatures"], f"{where}.signatures", MAX_VALIDATORS)):
        at = f"{where}.signatures[{i}]"
        sig = t.obj(raw, at)
        sig_keys = {"validator_id", "algorithm_id", "signature"}
        t.keys(sig, sig_keys, sig_keys, at)
        t.cell_hash(sig["validator_id"], f"{at}.validator_id")
        t.integer(sig["algorithm_id"], f"{at}.algorithm_id", 0, 0xFFFF)
        hex_bytes(sig["signature"], f"{at}.signature")


def validate_context(ctx: Mapping[str, Any], where: str) -> None:
    op = ctx.get("op")
    if not isinstance(op, str) or op not in OP_REQUIRED:
        raise t.FixtureError(f"{where}.op: invalid {op!r}")
    required = {"op"} | set(OP_REQUIRED[op])
    t.keys(ctx, required, required | set(OP_OPTIONAL.get(op, frozenset())), where)
    for key in ("total_weight", "signed_weight", "claimed_weight"):
        if key in ctx:
            decimal(ctx[key], f"{where}.{key}")
    if "weights" in ctx:
        for i, w in enumerate(t.array(ctx["weights"], f"{where}.weights", 4096)):
            decimal(w, f"{where}.weights[{i}]")
    for key in (
        "protocol_version",
        "catchain_seqno",
        "vertical_seqno",
        "last_key_block_seqno",
        "slot",
    ):
        if key in ctx:
            t.integer(ctx[key], f"{where}.{key}", 0, U32)
    if "global_id" in ctx:
        t.integer(ctx["global_id"], f"{where}.global_id", -(1 << 31), (1 << 31) - 1)
    if "options" in ctx:
        options(ctx["options"], f"{where}.options")
    for key in ("simplex_config_hash", "session_id", "expected_session_id"):
        if key in ctx:
            t.cell_hash(ctx[key], f"{where}.{key}")
    if "shard" in ctx:
        shard(ctx["shard"], f"{where}.shard")
    if "validators" in ctx:
        validators(ctx["validators"], f"{where}.validators")
    for key in ("candidate", "public_key", "signature"):
        if key in ctx:
            hex_bytes(ctx[key], f"{where}.{key}")
    for key in ("final", "is_key"):
        if key in ctx:
            t.boolean(ctx[key], f"{where}.{key}")
    for key in ("block", "key_block"):
        if key in ctx:
            block_id(ctx[key], f"{where}.{key}")
    if "role" in ctx and ctx["role"] not in ("final", "approve"):
        raise t.FixtureError(f"{where}.role: final or approve")
    for key in ("key_block_proof", "block_proof"):
        if key in ctx:
            t.boc(ctx[key], f"{where}.{key}")
    if "signature_set" in ctx:
        signature_set(ctx["signature_set"], f"{where}.signature_set")
    if op == "vote" and ("public_key" in ctx) != ("signature" in ctx):
        raise t.FixtureError(f"{where}: public_key and signature go together")
    if op == "finality" and ("block_proof" in ctx) == ("signature_set" in ctx):
        raise t.FixtureError(f"{where}: exactly one of block_proof and signature_set")
    if op == "finality" and "block_proof" in ctx and "claimed_weight" in ctx:
        raise t.FixtureError(f"{where}: a block proof states its own claimed weight")


def validate_effects(eff: Mapping[str, Any], where: str) -> None:
    outcome = t.outcome_shape(eff, EFFECT_SHAPES, where)
    for key in ("threshold", "total", "weight", "total_weight", "verified_weight"):
        if key in eff:
            decimal(eff[key], f"{where}.{key}")
    for key in (
        "has_quorum",
        "supported",
        "enable_block_sync",
        "use_new_db_names",
        "observers_in_private_overlay",
        "enable_plumtree_broadcast",
        "is_key",
    ):
        if key in eff:
            t.boolean(eff[key], f"{where}.{key}")
    for key in (
        "options_hash",
        "session_config_hash",
        "session_id",
        "candidate_hash",
        "expected_session_id",
        "simplex_config_hash",
        "validator_path_session_id",
        "root_hash",
        "file_hash",
        "state_old_hash",
        "state_hash",
    ):
        if key in eff:
            t.cell_hash(eff[key], f"{where}.{key}")
    for key in (
        "max_supported",
        "seqno",
        "gen_utime",
        "protocol_version",
        "catchain_seqno",
        "vertical_seqno",
        "prev_key_block_seqno",
        "header_validator_set_hash",
        "validator_set_hash",
    ):
        if key in eff:
            t.integer(eff[key], f"{where}.{key}", 0, U32)
    if "data_to_sign" in eff:
        hex_bytes(eff["data_to_sign"], f"{where}.data_to_sign")
    if "signature_check" in eff and eff["signature_check"] not in (
        None,
        "valid",
        "invalid",
        "malformed",
    ):
        raise t.FixtureError(f"{where}.signature_check: invalid value")
    if outcome == "refused":
        t.text(eff["reason"], REASON_RE, f"{where}.reason")
    if outcome in ("context", "proof"):
        if eff["signature_set"] is not None:
            signature_set(eff["signature_set"], f"{where}.signature_set", decoded=True)
        if eff["claimed_weight"] is not None:
            decimal(eff["claimed_weight"], f"{where}.claimed_weight")
    if outcome == "context":
        t.integer(eff["global_id"], f"{where}.global_id", -(1 << 31), (1 << 31) - 1)
        if eff["config_global_id"] is not None:
            t.integer(
                eff["config_global_id"], f"{where}.config_global_id", -(1 << 31), (1 << 31) - 1
            )
        options(eff["options"], f"{where}.options")
        validators(eff["validators"], f"{where}.validators")
