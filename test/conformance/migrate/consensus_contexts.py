#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Contexts of the consensus harness, and the cross-checks of its frozen fixtures.

    consensus_contexts.py contexts --reference <conformance-ref-cli> --archive <node package dir>
        --rtos <dir> --out <dir>
    consensus_contexts.py check --reference <conformance-ref-cli> <vectors/consensus>

`contexts` writes one `<family>.contexts.jsonl` per family, for `conformance.py create`:

- real: masterchain block proofs and the governing key-block proofs of an archived network (a validator's
  package directory, read only). The reference derives each block's governing context (validator set,
  session inputs, decoded signatures) with the key_block_context op; that derivation is frozen as its own
  family and feeds the session, vote, finality and proof-link contexts of the same block.
- authored: mutations of the real material (a signature dropped, duplicated or altered, a wrong session,
  weight, block, role or key) and boundary cases of the quorum, weight and session rules.
- converted: the deterministic RTOS vectors (Simplex protocol predicates, PQ finality and live PQ vote
  rows), as contexts only; their recorded values become authored expectations.

An authored expectation is a partial effect stored in `metadata.note` as {"expect": {...}}. The fixtures'
effects come only from the reference; `check` re-reads the frozen families and requires every expectation
to hold and the derivations of one block to agree with each other (the session a block was signed in is
the one the validator path, the lite proof path and the raw derivation compute).
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import struct
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, cast

Json = dict[str, Any]

PACKAGE_MAGIC = 0xAE8FDD01
ENTRY_MAGIC = 0x1E8B
MAX_PACKAGE_BYTES = 256 << 20
MASTER_SHARD = "8000000000000000"
KEY_ID_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
REFERENCE_TIMEOUT_SECONDS = 600

# (block, governing key block): blocks of the REL-02 replay window, a key block and the block after it,
# and the next election's key block and its successor, so the material crosses two validator-set changes.
REAL_TARGETS: tuple[tuple[int, int], ...] = (
    (117750, 88656),
    (117751, 88656),
    (117900, 88656),
    (118200, 88656),
    (119620, 88656),
    (119621, 119620),
    (124028, 119620),
    (124029, 124028),
)

HEX_FAMILIES = frozenset({"vote", "finality", "session", "validator-set"})
NO_BLOBS = 1 << 24
DEFAULT_BLOB_THRESHOLD = 2048

# A family is frozen in one file per context source (metadata.source is per file): the fixture id prefix
# names the source.
SOURCES = {"real": "replay", "authored": "authored", "rtos": "migrated:rtos"}

RTOS_FILES = (
    "pq-finality.json",
    "pq-finality-keys.json",
    "live-pq.json",
    "live-pq-chain.json",
    "simplex-protocol-predicates.tsv",
)


class ConsensusContextError(Exception):
    """Material, a derivation or a frozen family is not what this script requires."""


def fail(message: str) -> None:
    raise ConsensusContextError(message)


def read_jsonl(path: Path) -> list[Json]:
    return [cast(Json, json.loads(line)) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------------------------------------
# Archive packages: magic, then entries (u16 magic, u16 name length, u32 data length, name, data).


def read_package(path: Path) -> dict[str, bytes]:
    data = path.read_bytes()
    if len(data) > MAX_PACKAGE_BYTES or len(data) < 4:
        fail(f"{path}: not a package of bounded size")
    if struct.unpack_from("<I", data, 0)[0] != PACKAGE_MAGIC:
        fail(f"{path}: bad package magic")
    entries: dict[str, bytes] = {}
    offset = 4
    while offset < len(data):
        if offset + 8 > len(data):
            fail(f"{path}: truncated entry header")
        magic, name_len, data_len = cast(
            tuple[int, int, int], struct.unpack_from("<HHI", data, offset)
        )
        if magic != ENTRY_MAGIC:
            fail(f"{path}: bad entry magic at {offset}")
        offset += 8
        end = offset + name_len + data_len
        if end > len(data):
            fail(f"{path}: truncated entry")
        name = data[offset : offset + name_len].decode("ascii")
        entries[name] = data[offset + name_len : end]
        offset = end
    return entries


def proof_entry(entries: dict[str, bytes], seqno: int) -> tuple[Json, bytes] | None:
    prefix = f"proof_(-1,{MASTER_SHARD},{seqno}):"
    for name, data in entries.items():
        if name.startswith(prefix):
            root_hash, file_hash = name[len(prefix) :].split(":")
            block = {
                "workchain": -1,
                "shard": MASTER_SHARD,
                "seqno": seqno,
                "root_hash": root_hash.upper(),
                "file_hash": file_hash.upper(),
            }
            return block, data
    return None


def masterchain_packages(archive: Path) -> list[tuple[int, Path]]:
    found: list[tuple[int, Path]] = []
    for path in archive.glob("arch*/archive.*.pack"):
        parts = path.name.split(".")
        if len(parts) == 3 and parts[1].isdigit():
            found.append((int(parts[1]), path))
    return sorted(found)


def find_proof(archive: Path, seqno: int, key_block: bool) -> tuple[Json, bytes]:
    if key_block:
        for path in sorted(archive.glob("key*/key.archive.*.pack")):
            hit = proof_entry(read_package(path), seqno)
            if hit is not None:
                return hit
        fail(f"key block proof {seqno} not in the key packages of {archive}")
    candidates = [path for first, path in masterchain_packages(archive) if first <= seqno]
    for path in reversed(candidates[-3:]):
        hit = proof_entry(read_package(path), seqno)
        if hit is not None:
            return hit
    fail(f"block proof {seqno} not in the packages of {archive}")
    raise AssertionError("unreachable")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------------------------------------
# Reference calls used to derive contexts (never to fill a fixture: create does that).


def run_reference(reference: str, contexts: Sequence[Json]) -> list[Json]:
    stdin = "".join(json.dumps(ctx, sort_keys=True) + "\n" for ctx in contexts)
    result = subprocess.run(
        [reference, "consensus"],
        input=stdin,
        capture_output=True,
        text=True,
        check=True,
        timeout=REFERENCE_TIMEOUT_SECONDS,
    )
    lines = result.stdout.splitlines()
    if len(lines) != len(contexts):
        fail(f"reference answered {len(lines)} of {len(contexts)} contexts")
    answers = [cast(Json, json.loads(line)) for line in lines]
    for ctx, answer in zip(contexts, answers):
        if "harness_error" in answer:
            fail(f"reference refused a derivation context ({ctx['op']}): {answer['harness_error']}")
    return answers


def key_id(public_key_hex: str, algorithm_id: int = 1) -> str:
    preimage = KEY_ID_DOMAIN + struct.pack("<H", algorithm_id) + bytes.fromhex(public_key_hex)
    return hashlib.sha256(preimage).hexdigest().upper()


def candidate_block(candidate_hex: str) -> Json:
    """The block id at the head of a TL consensus.CandidateHashData (ordinary or empty)."""
    raw = bytes.fromhex(candidate_hex)
    if len(raw) < 4 + 80:
        fail("candidate too short")
    workchain, shard, seqno = cast(tuple[int, int, int], struct.unpack_from("<iqi", raw, 4))
    return {
        "workchain": workchain,
        "shard": f"{shard & 0xFFFFFFFFFFFFFFFF:016x}",
        "seqno": seqno,
        "root_hash": raw[20:52].hex().upper(),
        "file_hash": raw[52:84].hex().upper(),
    }


def flip_hex(text: str, index: int = 0) -> str:
    """The same hex text with the byte at index changed."""
    raw = bytearray(bytes.fromhex(text))
    raw[index] ^= 0x01
    return raw.hex()


def flip_hash(text: str) -> str:
    return flip_hex(text.lower()).upper()


class Family:
    def __init__(self, name: str) -> None:
        self.name = name
        self.rows: list[Json] = []
        self.ids: set[str] = set()

    def add(self, fixture_id: str, context: Json, expect: Json | None = None) -> None:
        if fixture_id in self.ids:
            fail(f"{self.name}: duplicate fixture id {fixture_id}")
        self.ids.add(fixture_id)
        row: Json = {"fixture_id": fixture_id, "context": context}
        if expect is not None:
            row["note"] = json.dumps({"expect": expect}, sort_keys=True)
        self.rows.append(row)


# ---------------------------------------------------------------------------------------------------------
# Real material.


def real_material(reference: str, archive: Path) -> list[Json]:
    material: list[Json] = []
    for seqno, key_seqno in REAL_TARGETS:
        key_block, key_proof = find_proof(archive, key_seqno, key_block=True)
        block, block_proof = find_proof(archive, seqno, key_block=False)
        ctx: Json = {
            "op": "key_block_context",
            "key_block": key_block,
            "block": block,
            "key_block_proof": b64(key_proof),
            "block_proof": b64(block_proof),
        }
        [derived] = run_reference(reference, [ctx])
        if derived.get("outcome") != "context":
            fail(f"block {seqno}: no governing context under key block {key_seqno}: {derived}")
        if derived["prev_key_block_seqno"] != key_seqno:
            fail(f"block {seqno}: governed by key block {derived['prev_key_block_seqno']}")
        if derived["signature_set"] is None:
            fail(f"block {seqno}: proof without PQ signatures")
        material.append({"context": ctx, "derived": derived, "is_key": derived["is_key"]})
    return material


def session_context(derived: Json) -> Json:
    return {
        "op": "session",
        "global_id": derived["global_id"],
        "options": derived["options"],
        "simplex_config_hash": derived["simplex_config_hash"],
        "shard": {"workchain": -1, "shard": MASTER_SHARD},
        "catchain_seqno": derived["catchain_seqno"],
        "vertical_seqno": derived["vertical_seqno"],
        "last_key_block_seqno": derived["prev_key_block_seqno"],
        "validators": derived["validators"],
    }


def explicit_set(derived: Json) -> Json:
    decoded = dict(derived["signature_set"])
    del decoded["final"]
    return decoded


def finality_context(material: Json, **overrides: Any) -> Json:
    derived = material["derived"]
    ctx: Json = {
        "op": "finality",
        "validators": derived["validators"],
        "catchain_seqno": derived["catchain_seqno"],
        "block": material["context"]["block"],
        "expected_session_id": derived["session_id"],
        "role": "final",
        "signature_set": explicit_set(derived),
        "claimed_weight": derived["claimed_weight"],
    }
    ctx.update(overrides)
    return ctx


def add_real(families: dict[str, Family], material: list[Json], reference: str) -> None:
    for item in material:
        ctx, derived = item["context"], item["derived"]
        seqno = ctx["block"]["seqno"]
        tag = f"real/{seqno}"
        families["key-block-context"].add(
            tag, ctx, {"outcome": "context", "prev_key_block_seqno": ctx["key_block"]["seqno"]}
        )
        families["decode-proof"].add(
            tag,
            {"op": "decode_proof", "block_proof": ctx["block_proof"]},
            {"outcome": "proof", "root_hash": ctx["block"]["root_hash"], "seqno": seqno},
        )
        key_tag = f"real/key-{ctx['key_block']['seqno']}"
        if key_tag not in families["decode-proof"].ids:
            families["decode-proof"].add(
                key_tag,
                {"op": "decode_proof", "block_proof": ctx["key_block_proof"]},
                {"outcome": "proof", "root_hash": ctx["key_block"]["root_hash"]},
            )
        families["session"].add(
            tag,
            session_context(derived),
            {"outcome": "session", "session_id": derived["session_id"]},
        )
        families["proof-link"].add(
            tag,
            {
                "op": "proof_link",
                "key_block": ctx["key_block"],
                "block": ctx["block"],
                "is_key": item["is_key"],
                "key_block_proof": ctx["key_block_proof"],
                "block_proof": ctx["block_proof"],
            },
            {"outcome": "linked", "expected_session_id": derived["session_id"]},
        )
        families["finality"].add(
            f"{tag}/proof",
            {
                "op": "finality",
                "validators": derived["validators"],
                "catchain_seqno": derived["catchain_seqno"],
                "block": ctx["block"],
                "expected_session_id": derived["session_id"],
                "role": "final",
                "block_proof": ctx["block_proof"],
            },
            {"outcome": "finalized", "weight": derived["claimed_weight"]},
        )
        families["finality"].add(
            f"{tag}/explicit",
            finality_context(item),
            {"outcome": "finalized", "weight": derived["claimed_weight"]},
        )
        families["validator-set"].add(
            tag,
            {
                "op": "validator_set",
                "validators": derived["validators"],
                "catchain_seqno": derived["catchain_seqno"],
                "shard": {"workchain": -1, "shard": MASTER_SHARD},
            },
            {
                "outcome": "validator_set",
                "validator_set_hash": derived["header_validator_set_hash"],
                "total_weight": derived["total_weight"],
            },
        )
        keys = {v["validator_id"]: v["public_key"] for v in derived["validators"]}
        decoded = derived["signature_set"]
        for sig in decoded["signatures"]:
            families["vote"].add(
                f"{tag}/{sig['validator_id'][:16]}",
                {
                    "op": "vote",
                    "session_id": decoded["session_id"],
                    "slot": decoded["slot"],
                    "candidate": decoded["candidate"],
                    "final": True,
                    "block": ctx["block"],
                    "public_key": keys[sig["validator_id"]],
                    "signature": sig["signature"],
                },
                {"outcome": "vote", "signature_check": "valid"},
            )
    add_real_mutations(families, material, reference)


def add_real_mutations(families: dict[str, Family], material: list[Json], reference: str) -> None:
    first = material[0]
    derived = first["derived"]
    block = first["context"]["block"]
    decoded = derived["signature_set"]
    signatures = decoded["signatures"]
    validators = derived["validators"]
    weight_of = {v["validator_id"]: int(v["weight"]) for v in validators}
    total = int(derived["total_weight"])
    threshold = (2 * total + 2) // 3
    fin = families["finality"]

    def with_signatures(sigs: list[Json], claimed: int | None) -> Json:
        signature_set = explicit_set(derived)
        signature_set["signatures"] = sigs
        ctx = finality_context(first, signature_set=signature_set)
        if claimed is None:
            del ctx["claimed_weight"]
        else:
            ctx["claimed_weight"] = str(claimed)
        return ctx

    # Missing signatures: drop signers one at a time, last first; the set stays final until the
    # remaining weight falls below the threshold.
    remaining = list(signatures)
    while remaining:
        remaining = remaining[:-1]
        weight = sum(weight_of[s["validator_id"]] for s in remaining)
        expect: Json = (
            {"outcome": "finalized", "weight": str(weight)}
            if weight >= threshold
            else {"outcome": "refused", "reason": "insufficient_weight"}
        )
        fin.add(f"authored/signers-{len(remaining)}", with_signatures(remaining, weight), expect)
    fin.add(
        "authored/duplicate-signer",
        with_signatures([*signatures, signatures[0]], None),
        {"outcome": "refused", "reason": "duplicate_signer"},
    )
    fin.add(
        "authored/claimed-weight-plus-one",
        with_signatures(signatures, int(derived["claimed_weight"]) + 1),
        {"outcome": "refused", "reason": "claimed_weight_mismatch"},
    )
    fin.add(
        "authored/no-claimed-weight",
        with_signatures(signatures, None),
        {"outcome": "finalized", "weight": derived["claimed_weight"]},
    )
    tampered = copy.deepcopy(signatures)
    tampered[0]["signature"] = flip_hex(tampered[0]["signature"], 100)
    fin.add(
        "authored/tampered-signature",
        with_signatures(tampered, None),
        {"outcome": "refused", "reason": "invalid_signature"},
    )
    short = copy.deepcopy(signatures)
    short[0]["signature"] = short[0]["signature"][:-2]
    fin.add(
        "authored/short-signature",
        with_signatures(short, None),
        {"outcome": "refused", "reason": "signature_length"},
    )
    unknown = copy.deepcopy(signatures)
    unknown[0]["validator_id"] = flip_hash(unknown[0]["validator_id"])
    fin.add(
        "authored/unknown-signer",
        with_signatures(unknown, None),
        {"outcome": "refused", "reason": "unknown_signer"},
    )
    algorithm = copy.deepcopy(signatures)
    algorithm[0]["algorithm_id"] = 2
    fin.add(
        "authored/unsupported-algorithm",
        with_signatures(algorithm, None),
        {"outcome": "refused", "reason": "unsupported_algorithm"},
    )
    fin.add(
        "authored/empty-set",
        with_signatures([], 0),
        {"outcome": "refused", "reason": "insufficient_weight"},
    )
    fin.add(
        "authored/wrong-expected-session",
        finality_context(first, expected_session_id=flip_hash(derived["session_id"])),
        {"outcome": "refused", "reason": "session_mismatch"},
    )
    # The carried and the expected session agree, but the signatures were made in another session.
    other_session = explicit_set(derived)
    other_session["session_id"] = flip_hash(derived["session_id"])
    fin.add(
        "authored/signed-in-other-session",
        finality_context(
            first,
            signature_set=other_session,
            expected_session_id=other_session["session_id"],
        ),
        {"outcome": "refused", "reason": "invalid_signature"},
    )
    fin.add(
        "authored/wrong-catchain-seqno",
        finality_context(first, catchain_seqno=derived["catchain_seqno"] + 1),
        {"outcome": "refused", "reason": "catchain_seqno_mismatch"},
    )
    wrong_hash = explicit_set(derived)
    wrong_hash["validator_set_hash"] = (wrong_hash["validator_set_hash"] + 1) & 0xFFFFFFFF
    fin.add(
        "authored/wrong-validator-set-hash",
        finality_context(first, signature_set=wrong_hash),
        {"outcome": "refused", "reason": "validator_set_hash_mismatch"},
    )
    # A validator's weight changed in the trusted set: the set commitment no longer matches.
    reweighted = copy.deepcopy(validators)
    reweighted[0]["weight"] = str(int(reweighted[0]["weight"]) + 1)
    fin.add(
        "authored/wrong-validator-weight",
        finality_context(first, validators=reweighted),
        {"outcome": "refused", "reason": "validator_set_hash_mismatch"},
    )
    other_block = dict(block)
    other_block["root_hash"] = flip_hash(block["root_hash"])
    fin.add(
        "authored/wrong-block",
        finality_context(first, block=other_block),
        {"outcome": "refused", "reason": "block_mismatch"},
    )
    fin.add(
        "authored/approve-role-on-final-signatures",
        finality_context(first, role="approve"),
        {"outcome": "refused", "reason": "invalid_signature"},
    )
    proof_ctx = {
        "op": "finality",
        "validators": validators,
        "catchain_seqno": derived["catchain_seqno"],
        "block": block,
        "expected_session_id": derived["session_id"],
        "role": "approve",
        "block_proof": first["context"]["block_proof"],
    }
    fin.add(
        "authored/proof-checked-as-approve",
        proof_ctx,
        {"outcome": "refused", "reason": "role_mismatch"},
    )
    # A real set commits to its keys: any key change shows as a different set (the synthetic set of the
    # RTOS vectors below covers a rotated key under a recomputed commitment).
    rotated = copy.deepcopy(validators)
    rotated[0]["key_id"] = flip_hash(rotated[0]["key_id"])
    fin.add(
        "authored/key-id-changed",
        finality_context(first, validators=rotated),
        {"outcome": "refused", "reason": "validator_set_hash_mismatch"},
    )
    # The signatures of a block verified against the validator set of a later election.
    later = next(
        (m for m in material if m["derived"]["catchain_seqno"] != derived["catchain_seqno"]),
        None,
    )
    if later is not None:
        fin.add(
            "authored/later-validator-set",
            finality_context(
                first,
                validators=later["derived"]["validators"],
                catchain_seqno=later["derived"]["catchain_seqno"],
            ),
            {"outcome": "refused"},
        )
    mixed = copy.deepcopy(validators)
    mixed[0] = {"ed25519": "11" * 32, "weight": mixed[0]["weight"], "adnl": mixed[0]["adnl"]}
    fin.add(
        "authored/mixed-validator-set",
        finality_context(first, validators=mixed),
        {"outcome": "refused", "reason": "carrier_mismatch"},
    )

    # Proof links that must not verify.
    link = families["proof-link"]
    base = first["context"]
    link_ctx: Json = {
        "op": "proof_link",
        "key_block": base["key_block"],
        "block": block,
        "is_key": first["is_key"],
        "key_block_proof": base["key_block_proof"],
        "block_proof": base["block_proof"],
    }
    link.add(
        "authored/key-flag-flipped",
        {**link_ctx, "is_key": not first["is_key"]},
        {"outcome": "refused", "reason": "key_block_flag_mismatch"},
    )
    link.add(
        "authored/wrong-block-hash",
        {**link_ctx, "block": other_block},
        {"outcome": "refused", "reason": "header_mismatch"},
    )
    other_key = dict(base["key_block"])
    other_key["root_hash"] = flip_hash(other_key["root_hash"])
    link.add(
        "authored/wrong-key-block-hash",
        {**link_ctx, "key_block": other_key},
        {"outcome": "refused", "reason": "header_mismatch"},
    )
    second = material[1]
    link.add(
        "authored/proof-of-another-block",
        {**link_ctx, "block_proof": second["context"]["block_proof"]},
        {"outcome": "refused", "reason": "header_mismatch"},
    )
    newer_key = next(m for m in material if m["context"]["key_block"]["seqno"] > block["seqno"])
    link.add(
        "authored/key-block-after-block",
        {
            **link_ctx,
            "key_block": newer_key["context"]["key_block"],
            "key_block_proof": newer_key["context"]["key_block_proof"],
        },
        # The seqnos make it a backward link, which needs a state proof of its source first.
        {"outcome": "refused", "reason": "proof_incomplete"},
    )

    # Votes that must not verify.
    vote = families["vote"]
    keys = {v["validator_id"]: v["public_key"] for v in validators}
    sig = signatures[0]
    vote_ctx: Json = {
        "op": "vote",
        "session_id": decoded["session_id"],
        "slot": decoded["slot"],
        "candidate": decoded["candidate"],
        "final": True,
        "block": block,
        "public_key": keys[sig["validator_id"]],
        "signature": sig["signature"],
    }
    vote.add(
        "authored/notarize-instead-of-finalize",
        {**vote_ctx, "final": False},
        {"outcome": "vote", "signature_check": "invalid"},
    )
    vote.add(
        "authored/other-slot",
        {**vote_ctx, "slot": decoded["slot"] + 1},
        {"outcome": "vote", "signature_check": "invalid"},
    )
    vote.add(
        "authored/other-session",
        {**vote_ctx, "session_id": flip_hash(decoded["session_id"])},
        {"outcome": "vote", "signature_check": "invalid"},
    )
    other_signer = next(s for s in signatures if s["validator_id"] != sig["validator_id"])
    vote.add(
        "authored/other-signers-key",
        {**vote_ctx, "public_key": keys[other_signer["validator_id"]]},
        {"outcome": "vote", "signature_check": "invalid"},
    )
    vote.add(
        "authored/candidate-block-mismatch",
        {**vote_ctx, "block": other_block},
        {"outcome": "refused", "reason": "block_mismatch"},
    )
    vote.add(
        "authored/candidate-truncated",
        {**vote_ctx, "candidate": decoded["candidate"][:-8]},
        {"outcome": "refused", "reason": "candidate_malformed"},
    )
    vote.add(
        "authored/signature-truncated",
        {**vote_ctx, "signature": sig["signature"][:-2]},
        {"outcome": "vote", "signature_check": "malformed"},
    )
    unsigned = dict(vote_ctx)
    del unsigned["public_key"]
    del unsigned["signature"]
    vote.add("authored/data-only", unsigned, {"outcome": "vote", "signature_check": None})


# ---------------------------------------------------------------------------------------------------------
# Authored boundary cases.


def add_rules(families: dict[str, Family]) -> None:
    quorum = families["quorum"]
    cap = (1 << 64) // 3  # UINT64_MAX / 3, the protocol cap on a set's total weight
    totals = [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 100, 101, 102, cap - 1, cap, (1 << 64) - 1]
    for total in totals:
        threshold = (2 * total + 2) // 3
        for signed in sorted({0, max(threshold - 1, 0), threshold, total}):
            expect: Json = {
                "outcome": "quorum",
                "threshold": str(threshold),
                "has_quorum": 3 * signed >= 2 * total,
            }
            quorum.add(
                f"authored/total-{total}/signed-{signed}",
                {"op": "quorum", "total_weight": str(total), "signed_weight": str(signed)},
                expect,
            )
    quorum.add(
        "authored/signed-above-total",
        {"op": "quorum", "total_weight": "4", "signed_weight": "18446744073709551615"},
        {"outcome": "quorum", "has_quorum": True},
    )

    weights = families["weight-total"]
    cases: list[tuple[str, list[int], Json]] = [
        ("empty", [], {"outcome": "weight_total", "total": "0"}),
        ("one", [1], {"outcome": "weight_total", "total": "1"}),
        ("four-equal", [10, 10, 10, 10], {"outcome": "weight_total", "total": "40"}),
        ("zero-weight", [5, 0, 5], {"outcome": "refused", "reason": "weight_refused"}),
        ("exactly-cap", [cap - 1, 1], {"outcome": "weight_total", "total": str(cap)}),
        ("above-cap", [cap, 1], {"outcome": "refused", "reason": "weight_refused"}),
        ("max-single", [(1 << 64) - 1], {"outcome": "refused", "reason": "weight_refused"}),
    ]
    for name, values, expect in cases:
        weights.add(
            f"authored/{name}", {"op": "weight_total", "weights": [str(w) for w in values]}, expect
        )


def add_session_variants(families: dict[str, Family], material: list[Json]) -> None:
    """The constructor and options-hash branches of the session derivation, around a real context."""
    session = families["session"]
    base = session_context(material[0]["derived"])
    classical = [
        {"ed25519": f"{i:02X}" * 32, "weight": str(10 + i), "adnl": f"{0x40 + i:02X}" * 32}
        for i in range(1, 5)
    ]
    variants: list[tuple[str, Json]] = []
    for proto in (0, 1, 2, 3):
        for new_ids in (False, True):
            options = {**base["options"], "proto_version": proto, "new_catchain_ids": new_ids}
            variants.append((f"proto-{proto}/new-ids-{int(new_ids)}", {**base, "options": options}))
    old_ids = {**base["options"], "new_catchain_ids": False}
    variants.append(("vertical-0-old-ids", {**base, "options": old_ids, "vertical_seqno": 0}))
    variants.append(("vertical-1-old-ids", {**base, "options": old_ids, "vertical_seqno": 1}))
    variants.append(("vertical-1", {**base, "vertical_seqno": 1}))
    variants.append(("basechain", {**base, "shard": {"workchain": 0, "shard": MASTER_SHARD}}))
    variants.append(("other-network", {**base, "global_id": base["global_id"] + 1}))
    variants.append(("other-simplex-config", {**base, "simplex_config_hash": "00" * 32}))
    variants.append(
        ("other-catchain-seqno", {**base, "catchain_seqno": base["catchain_seqno"] + 1})
    )
    variants.append(
        ("other-key-block", {**base, "last_key_block_seqno": base["last_key_block_seqno"] + 1})
    )
    variants.append(("reordered-validators", {**base, "validators": base["validators"][::-1]}))
    variants.append(("classical-validators", {**base, "validators": classical}))
    variants.append(
        (
            "fractional-delay",
            {**base, "options": {**base["options"], "next_candidate_delay": 0.125}},
        )
    )
    seen = {json.dumps(base, sort_keys=True)}
    for name, ctx in variants:
        # A variant equal to the real context or to an earlier variant adds nothing.
        key = json.dumps(ctx, sort_keys=True)
        if key not in seen:
            seen.add(key)
            session.add(f"authored/{name}", ctx)


# ---------------------------------------------------------------------------------------------------------
# RTOS vectors (contexts only; recorded values become expectations).


def add_rtos(families: dict[str, Family], rtos: Path, reference: str, other_key: str) -> None:
    proto = families["protocol-version"]
    lines = (rtos / "simplex-protocol-predicates.tsv").read_text().splitlines()
    header = lines[0].split("\t")
    for line in lines[1:]:
        cells = line.split("\t")
        if cells[0] == "max_supported":
            continue
        row = dict(zip(header, cells))
        version = int(row["version"])
        expect: Json = {"outcome": "protocol_version"}
        for key in header[1:]:
            expect[key] = row[key] == "1"
        proto.add(
            f"rtos/{version}", {"op": "protocol_version", "protocol_version": version}, expect
        )
    max_supported = next(
        int(line.split("\t")[1]) for line in lines if line.startswith("max_supported")
    )
    proto.add(
        "authored/u32-max",
        {"op": "protocol_version", "protocol_version": 0xFFFFFFFF},
        {"outcome": "protocol_version", "supported": False, "max_supported": max_supported},
    )

    vote = families["vote"]
    simplex_context = "TOS-CONSENSUS-SIMPLEX-v1"
    finality = cast(Json, json.loads((rtos / "pq-finality.json").read_text()))
    session_id = cast(str, finality["session"]).upper()
    slot = cast(int, finality["slot"])
    candidate = cast(str, finality["candidate"])
    block = candidate_block(candidate)
    for sig in cast(list[Json], finality["signatures"]):
        final = sig["role"] == "finalize"
        valid = sig["context"] == simplex_context
        expect = {"outcome": "vote", "signature_check": "valid" if valid else "invalid"}
        if valid:
            expect["data_to_sign"] = sig["preimage"]
        vote.add(
            f"rtos/pq-finality/{sig['role']}-{sig['index']}-{sig['context']}",
            {
                "op": "vote",
                "session_id": session_id,
                "slot": slot,
                "candidate": candidate,
                "final": final,
                "block": block,
                "public_key": sig["public_key"],
                "signature": sig["signature"],
            },
            expect,
        )
    for extra in cast(list[Json], finality["additional_candidates"]):
        vote.add(
            f"rtos/pq-finality/{extra['name']}",
            {
                "op": "vote",
                "session_id": session_id,
                "slot": slot,
                "candidate": extra["candidate"],
                "final": True,
                "block": candidate_block(extra["candidate"]),
                "public_key": cast(list[Json], finality["signatures"])[0]["public_key"],
                "signature": extra["signature"],
            },
            {"outcome": "vote", "data_to_sign": extra["preimage"]},
        )

    # The two-validator finality certificate of the same vectors: Simplex-context finalize signatures.
    keys = cast(list[str], json.loads((rtos / "pq-finality-keys.json").read_text()))
    validators = [
        {
            "validator_id": key_id(pk),
            "key_id": key_id(pk),
            "algorithm_id": 1,
            "public_key": pk,
            "weight": "1",
            "adnl": hashlib.sha256(bytes.fromhex(pk)).hexdigest().upper(),
        }
        for pk in keys
    ]
    shard = {"workchain": block["workchain"], "shard": block["shard"]}
    by_key = {v["public_key"]: v["validator_id"] for v in validators}
    final_sigs = [
        {"validator_id": by_key[s["public_key"]], "algorithm_id": 1, "signature": s["signature"]}
        for s in cast(list[Json], finality["signatures"])
        if s["role"] == "finalize" and s["context"] == simplex_context
    ]
    approve_sigs = [
        {"validator_id": by_key[s["public_key"]], "algorithm_id": 1, "signature": s["signature"]}
        for s in cast(list[Json], finality["signatures"])
        if s["role"] == "notarize" and s["context"] == simplex_context
    ]
    fin = families["finality"]

    def synthetic(role: str, sigs: list[Json], vals: list[Json]) -> Json:
        [answer] = run_reference(
            reference,
            [{"op": "validator_set", "validators": vals, "catchain_seqno": 0, "shard": shard}],
        )
        return {
            "op": "finality",
            "validators": vals,
            "catchain_seqno": 0,
            "block": block,
            "expected_session_id": session_id,
            "role": role,
            "signature_set": {
                "catchain_seqno": 0,
                "validator_set_hash": answer["validator_set_hash"],
                "session_id": session_id,
                "slot": slot,
                "candidate": candidate,
                "signatures": sigs,
            },
        }

    for role, sigs in (("final", final_sigs), ("approve", approve_sigs)):
        fin.add(
            f"rtos/pq-finality/{role}",
            synthetic(role, sigs, validators),
            {"outcome": "finalized", "weight": "2"},
        )
        fin.add(
            f"rtos/pq-finality/{role}-one-of-two",
            synthetic(role, sigs[:1], validators),
            {"outcome": "refused", "reason": "insufficient_weight"},
        )
    # A rotated (expired) key: the set now lists another key for the first signer, with its derived key
    # id and a matching set commitment, so only the old signature can fail.
    rotated = copy.deepcopy(validators)
    rotated[0]["public_key"] = other_key
    rotated[0]["key_id"] = key_id(other_key)
    fin.add(
        "rtos/pq-finality/rotated-key",
        synthetic("final", final_sigs, rotated),
        {"outcome": "refused", "reason": "invalid_signature"},
    )
    underived = copy.deepcopy(validators)
    underived[0]["key_id"] = flip_hash(cast(str, underived[0]["key_id"]))
    fin.add(
        "rtos/pq-finality/key-id-not-derived",
        synthetic("final", final_sigs, underived),
        {"outcome": "refused", "reason": "key_id_mismatch"},
    )
    # Unequal weights under a recomputed commitment: total 4, threshold 3.
    weighted = copy.deepcopy(validators)
    weighted[0]["weight"] = "3"
    v0, v1 = (v["validator_id"] for v in weighted)
    for name, chosen, expect in (
        ("heavy-and-light", [v0, v1], {"outcome": "finalized", "weight": "4", "threshold": "3"}),
        ("heavy-only", [v0], {"outcome": "finalized", "weight": "3"}),
        ("light-only", [v1], {"outcome": "refused", "reason": "insufficient_weight"}),
    ):
        picked = [s for s in final_sigs if s["validator_id"] in chosen]
        fin.add(f"rtos/pq-finality/weighted-{name}", synthetic("final", picked, weighted), expect)

    for name in ("live-pq.json", "live-pq-chain.json"):
        data = cast(Json, json.loads((rtos / name).read_text()))
        for i, row in enumerate(cast(list[Json], data["rows"])):
            if row["role"] not in ("notarize", "finalize"):
                continue
            preimage = cast(str, row["preimage"])
            # dataToSign = constructor, session (32 bytes), vote; the session is the row's input.
            row_session = cast(str, data.get("session", preimage[8:72])).upper()
            public_key = row.get("public_key", keys[cast(int, row["index"])])
            row_ctx = {
                "op": "vote",
                "session_id": row_session,
                "slot": cast(int, row.get("slot", data.get("slot"))),
                "candidate": row["candidate"],
                "final": row["role"] == "finalize",
                "block": candidate_block(cast(str, row["candidate"])),
                "public_key": public_key,
                "signature": row["signature"],
            }
            ok = row.get("context", simplex_context) == simplex_context
            expect = {"outcome": "vote", "signature_check": "valid" if ok else "invalid"}
            if ok:
                expect["data_to_sign"] = preimage
            vote.add(
                f"rtos/{name.removesuffix('.json')}/{i}-{row['kind']}-{row['role']}",
                row_ctx,
                expect,
            )


# ---------------------------------------------------------------------------------------------------------
# Commands.


FAMILIES = (
    "quorum",
    "weight-total",
    "protocol-version",
    "validator-set",
    "session",
    "vote",
    "finality",
    "proof-link",
    "key-block-context",
    "decode-proof",
)


def command_contexts(reference: str, archive: Path, rtos: Path, out: Path) -> dict[str, int]:
    for name in RTOS_FILES:
        if not (rtos / name).is_file():
            fail(f"{rtos}: missing {name}")
    families = {name: Family(name) for name in FAMILIES}
    material = real_material(reference, archive)
    add_rules(families)
    add_real(families, material, reference)
    add_session_variants(families, material)
    add_rtos(families, rtos, reference, material[0]["derived"]["validators"][0]["public_key"])
    out.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for name, family in families.items():
        for kind, source in SOURCES.items():
            rows = [r for r in family.rows if cast(str, r["fixture_id"]).startswith(f"{kind}/")]
            if not rows:
                continue
            path = out / f"{name}-{kind}.contexts.jsonl"
            path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
            counts[f"{name}-{kind} ({source})"] = len(rows)
        if sum(1 for r in family.rows if str(r["fixture_id"]).split("/")[0] not in SOURCES):
            fail(f"{name}: a fixture id without a source prefix")
    return counts


def subset_holds(effects: Json, expect: Json) -> list[str]:
    return [
        f"{key}: expected {value!r}, found {effects.get(key)!r}"
        for key, value in expect.items()
        if effects.get(key) != value
    ]


def load_family(directory: Path, name: str) -> list[Json]:
    """Every frozen file of one family (one file per source)."""
    paths = [directory / "fixtures" / f"{name}-{kind}.jsonl" for kind in SOURCES]
    records = [r for path in paths if path.is_file() for r in read_jsonl(path)]
    if not records:
        fail(f"missing family {name} in {directory}")
    return records


def command_check(directory: Path) -> list[str]:
    problems: list[str] = []
    by_family = {name: load_family(directory, name) for name in FAMILIES}
    for name, records in by_family.items():
        for record in records:
            meta = cast(Json, record["metadata"])
            where = f"{name}/{meta['fixture_id']}"
            if "note" in meta:
                expect = cast(Json, json.loads(cast(str, meta["note"]))).get("expect", {})
                problems += [f"{where}: {p}" for p in subset_holds(record["effects"], expect)]
    contexts = {
        cast(str, r["metadata"]["fixture_id"]): cast(Json, r["effects"])
        for r in by_family["key-block-context"]
    }
    if len(contexts) < 2:
        problems.append("key-block-context: fewer than two real blocks")
    for fixture_id, eff in contexts.items():
        if eff.get("outcome") != "context":
            problems.append(f"key-block-context/{fixture_id}: no context")
            continue
        if eff["session_id"] != eff["validator_path_session_id"]:
            problems.append(f"{fixture_id}: lite and validator session derivations differ")
        if eff["header_validator_set_hash"] != eff["validator_set_hash"]:
            problems.append(f"{fixture_id}: computed validator set differs from the header's")
        if eff["global_id"] != eff["config_global_id"]:
            problems.append(f"{fixture_id}: header global id differs from ConfigParam 19")
        sig_set = cast(Json, eff["signature_set"])
        if sig_set["session_id"] != eff["session_id"]:
            problems.append(f"{fixture_id}: the chain's carried session is not the derived one")
        if sig_set["catchain_seqno"] != eff["catchain_seqno"]:
            problems.append(f"{fixture_id}: carrier catchain seqno differs from the header's")
    proofs = {
        cast(str, r["metadata"]["fixture_id"]): cast(Json, r["effects"])
        for r in by_family["decode-proof"]
    }
    for fixture_id, eff in contexts.items():
        decoded = proofs.get(fixture_id)
        if decoded is None or decoded.get("signature_set") != eff.get("signature_set"):
            problems.append(f"{fixture_id}: decode_proof and key_block_context decode differently")
    sessions = {cast(str, r["metadata"]["fixture_id"]): r for r in by_family["session"]}
    # Distinct session inputs must derive distinct sessions (each variant changes one committed input).
    by_id: dict[str, set[str]] = {}
    for record in sessions.values():
        context = json.dumps(record["context"], sort_keys=True)
        by_id.setdefault(cast(str, record["effects"].get("session_id")), set()).add(context)
    for session_id, distinct in by_id.items():
        if len(distinct) > 1:
            problems.append(f"session: {len(distinct)} different contexts derive {session_id}")
    return problems


def command_create(reference: str, contexts: Path, vectors: Path) -> None:
    """Fill every contexts file through runner/conformance.py create, with its family and source."""
    runner = Path(__file__).resolve().parent.parent / "runner" / "conformance.py"
    files = sorted(contexts.glob("*.contexts.jsonl"))
    if not files:
        fail(f"{contexts}: no contexts files")
    for path in files:
        family = path.name.removesuffix(".contexts.jsonl")
        kind = family.rsplit("-", 1)[1]
        source = SOURCES[kind]
        if kind == "rtos":
            source = f"{source}/{family.removesuffix('-rtos')}"
        out = vectors / "fixtures" / f"{family}.jsonl"
        # create moves long base64 strings into the blob store, and a long hex string (a key or a
        # signature) looks like one; families with hex fields therefore keep every value inline.
        base = family.rsplit("-", 1)[0]
        threshold = NO_BLOBS if base in HEX_FAMILIES else DEFAULT_BLOB_THRESHOLD
        subprocess.run(
            [
                sys.executable,
                "-B",
                str(runner),
                "create",
                "--reference",
                reference,
                "--harness",
                "consensus",
                "--family",
                family,
                "--source",
                source,
                "--blob-threshold",
                str(threshold),
                str(path),
                str(out),
            ],
            check=True,
            timeout=REFERENCE_TIMEOUT_SECONDS,
        )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    make = sub.add_parser("contexts")
    make.add_argument("--reference", required=True)
    make.add_argument("--archive", required=True, type=Path)
    make.add_argument("--rtos", required=True, type=Path)
    make.add_argument("--out", required=True, type=Path)
    create = sub.add_parser("create")
    create.add_argument("--reference", required=True)
    create.add_argument("--contexts", required=True, type=Path)
    create.add_argument("vectors", type=Path)
    check = sub.add_parser("check")
    check.add_argument("--reference", help="unused; accepted so the ctest line names the build")
    check.add_argument("directory", type=Path)
    args = parser.parse_args(None if argv is None else list(argv))
    if args.command == "contexts":
        counts = command_contexts(args.reference, args.archive, args.rtos, args.out)
        print(json.dumps(counts, sort_keys=True))
        return 0
    if args.command == "create":
        command_create(args.reference, args.contexts, args.vectors)
        return 0
    problems = command_check(args.directory)
    for problem in problems:
        print(problem)
    families = len(FAMILIES)
    print(f"consensus cross-check: {families} families, {len(problems)} problems")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
