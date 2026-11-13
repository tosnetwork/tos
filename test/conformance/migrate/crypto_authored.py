#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Third-party known answers and authored negative cases for the crypto harness.

    crypto_authored.py contexts <source-dir> <out-dir>
        Write <family>.contexts.jsonl for the families below.
    crypto_authored.py check <source-dir> <fixtures-dir>
        Hold the C++ fill to the stated answers: the third-party verdict or output for known-answer
        families, the authored expectation for the negative cases. A disagreement is a finding about
        the C++ (or about the expectation), never a reason to edit a fixture by hand.

Families (inputs from files in the source tree):

    wycheproof-ed25519   third-party/openssl/wycheproof/testvectors/eddsa_test.json
    poseidon2-kat        crypto/vm/poseidon2-kat.h (perm8, generated from the pinned upstream)
                         and the manifest digest recorded in crypto/poseidon2/PROVENANCE.md
    mldsa44-openssl      test/pq-mldsa44/fixtures.json (OpenSSL-produced signatures)
    falcon512-vectors    test/pq-falcon512/vectors.json
    crypto-negatives     authored: wrong key, signature or message, truncated and over-long
                         inputs, wrong signing domain, size boundaries, quorum and bound edges
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

# Run as a script from its own directory, next to the shared helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from crypto_common import (  # noqa: E402
    Checker,
    Json,
    b64,
    ctx,
    derive_key_id,
    entry,
    hexb,
    load_fixtures,
    rows,
    sha256_hex,
    write_contexts,
)

WYCHEPROOF = "third-party/openssl/wycheproof/testvectors/eddsa_test.json"
POSEIDON2_KAT = "crypto/vm/poseidon2-kat.h"
POSEIDON2_PROVENANCE = "crypto/poseidon2/PROVENANCE.md"
MLDSA_FIXTURES = "test/pq-mldsa44/fixtures.json"
FALCON_VECTORS = "test/pq-falcon512/vectors.json"
PQ_BYTES = "test/pq-mldsa44/pq-bytes-vectors.txt"
SIGNATURE_TL = "test/pq-native/pq-signature-tl-vectors.txt"
DERIVATION = "test/pq-native/validator-session-derivation-vectors.tsv"

U64_MAX = (1 << 64) - 1
SURFACES = ("simplex", "validator_election", "validator_config_vote", "config_admin")

# Expectations: an effects object, a set of acceptable verdicts, or None (fill only).
Expect = Json | frozenset[str] | None


def verdict(name: str) -> Json:
    return {"outcome": "verdict", "verdict": name}


def out_bytes(data: bytes) -> Json:
    return {"outcome": "bytes", "output": data.hex()}


def integer(value: int) -> Json:
    return {"outcome": "integer", "value": str(value)}


def boolean(value: bool) -> Json:
    return {"outcome": "boolean", "value": value}


def rejected(reason: str) -> Json:
    return {"outcome": "rejected", "reason": reason}


VALID = verdict("valid")
INVALID = verdict("invalid")
MALFORMED = verdict("malformed_input")
NOT_VALID = frozenset({"invalid", "malformed_input"})


def xor(field: str, offset: int, value: int = 1) -> Json:
    return {"input": field, "op": "xor", "offset": offset, "value": value}


def resize(field: str, length: int, value: int = 0) -> Json:
    return {"input": field, "op": "resize", "length": length, "value": value}


def fill_edit(field: str, value: int) -> Json:
    return {"input": field, "op": "fill", "value": value}


Case = tuple[str, Json, Expect]


# ---------------------------------------------------------------------------------------------
# Third-party known answers


def wycheproof(src: Path) -> list[Case]:
    doc = cast(Json, json.loads((src / WYCHEPROOF).read_text()))
    out: list[Case] = []
    for group in cast(list[Json], doc["testGroups"]):
        key = hexb(group["key"]["pk"])
        for test in cast(list[Json], group["tests"]):
            inputs = {
                "message": hexb(test["msg"]),
                "signature": hexb(test["sig"]),
                "public_key": key,
            }
            expected = VALID if test["result"] == "valid" else INVALID
            out.append((f"tc{test['tcId']}", ctx("ed25519", "verify", inputs), expected))
    return out


def poseidon2_vectors(src: Path) -> list[tuple[str, list[str], list[str]]]:
    text = (src / POSEIDON2_KAT).read_text()
    start = text.index("perm8[")
    block = text[start : text.index("hash7[", start)]
    vectors: list[tuple[str, list[str], list[str]]] = []
    for match in re.finditer(r'\{"([^"]+)",(.*?)\}\}\}', block, re.S):
        values = [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", match.group(2))]
        if len(values) != 16 * 32:
            raise SystemExit(f"{POSEIDON2_KAT}: vector {match.group(1)} has {len(values)} bytes")
        elements = [bytes(values[i * 32 : (i + 1) * 32]).hex() for i in range(16)]
        vectors.append((match.group(1), elements[:8], elements[8:]))
    if not vectors:
        raise SystemExit(f"{POSEIDON2_KAT}: no perm8 vectors")
    return vectors


def poseidon2(src: Path) -> list[Case]:
    out: list[Case] = [
        (
            name,
            ctx("poseidon2", "permute", {"state": state}),
            out_bytes(bytes.fromhex("".join(expected))),
        )
        for name, state, expected in poseidon2_vectors(src)
    ]
    found = re.search(r"sha256\s+([0-9a-f]{64})", (src / POSEIDON2_PROVENANCE).read_text())
    if found is None:
        raise SystemExit(f"{POSEIDON2_PROVENANCE}: no manifest sha256")
    out.append(
        (
            "manifest",
            ctx("poseidon2", "manifest_digest", {}),
            out_bytes(bytes.fromhex(found.group(1))),
        )
    )
    return out


def repeat_or_hex(case: Json, name: str) -> bytes:
    if f"{name}Repeat" in case:
        spec = cast(Json, case[f"{name}Repeat"])
        return bytes([spec["byte"]]) * spec["count"]
    return bytes.fromhex(case[f"{name}Hex"])


def mldsa_openssl(src: Path) -> list[Case]:
    doc = cast(Json, json.loads((src / MLDSA_FIXTURES).read_text()))
    key = hexb(doc["publicKeyHex"])
    out: list[Case] = []
    for case in cast(list[Json], doc["cases"]):
        inputs = {
            "message": b64(repeat_or_hex(case, "message")),
            "context": b64(repeat_or_hex(case, "context")),
            "signature": hexb(case["signatureHex"]),
            "public_key": key,
        }
        out.append((case["id"], ctx("mldsa44", "verify", inputs), VALID))
    return out


def falcon_vectors(src: Path) -> list[Case]:
    doc = cast(Json, json.loads((src / FALCON_VECTORS).read_text()))
    letters = {"V": VALID, "I": INVALID, "M": MALFORMED}
    return [
        (
            v["id"],
            ctx(
                "falcon512",
                "verify_padded",
                {
                    "message": hexb(v["message"]),
                    "signature": hexb(v["signature"]),
                    "public_key": hexb(v["public_key"]),
                },
            ),
            letters[v["expected"]],
        )
        for v in cast(list[Json], doc["vectors"])
    ]


# ---------------------------------------------------------------------------------------------
# Authored negative and boundary cases


def negatives(src: Path) -> list[Case]:
    out: list[Case] = []

    # Ed25519, around Wycheproof tcId 1 (a valid signature of the empty message).
    doc = cast(Json, json.loads((src / WYCHEPROOF).read_text()))
    group = cast(list[Json], doc["testGroups"])[0]
    test = cast(list[Json], group["tests"])[0]
    ed = {
        "message": hexb(test["msg"]),
        "signature": hexb(test["sig"]),
        "public_key": hexb(group["key"]["pk"]),
    }
    out.append(("ed25519/base", ctx("ed25519", "verify", ed), VALID))
    for name, edits in [
        ("wrong-key", [xor("public_key", 0)]),
        ("wrong-signature-r", [xor("signature", 0)]),
        ("wrong-signature-s", [xor("signature", 40)]),
        ("wrong-message", [resize("message", 1)]),
        ("truncated-signature", [resize("signature", 63)]),
        ("long-signature", [resize("signature", 65)]),
        ("empty-signature", [resize("signature", 0)]),
        ("truncated-key", [resize("public_key", 31)]),
        ("long-key", [resize("public_key", 33)]),
        ("zero-key", [fill_edit("public_key", 0)]),
        ("zero-signature", [fill_edit("signature", 0)]),
    ]:
        out.append((f"ed25519/{name}", ctx("ed25519", "verify", ed, edits), INVALID))

    # ML-DSA-44, around an OpenSSL signature under the wallet authorisation context.
    mldsa = cast(Json, json.loads((src / MLDSA_FIXTURES).read_text()))
    case = cast(list[Json], mldsa["cases"])[0]
    ml = {
        "message": hexb(case["messageHex"]),
        "context": hexb(case["contextHex"]),
        "signature": hexb(case["signatureHex"]),
        "public_key": hexb(mldsa["publicKeyHex"]),
    }
    out.append(("mldsa44/base", ctx("mldsa44", "verify", ml), VALID))
    for name, edits, expected in [
        ("wrong-key", [xor("public_key", 0)], INVALID),
        ("wrong-key-tail", [xor("public_key", 1311)], INVALID),
        ("wrong-signature-head", [xor("signature", 0)], NOT_VALID),
        ("wrong-signature-tail", [xor("signature", 2419)], NOT_VALID),
        ("wrong-message", [xor("message", 0)], INVALID),
        ("wrong-context", [xor("context", 0)], INVALID),
        ("empty-context", [resize("context", 0)], INVALID),
        ("context-255", [resize("context", 255, 0x42)], INVALID),
        ("context-256", [resize("context", 256, 0x42)], MALFORMED),
        ("message-8192", [resize("message", 8192, 0x41)], INVALID),
        ("message-8193", [resize("message", 8193, 0x41)], MALFORMED),
        ("signature-2419", [resize("signature", 2419)], MALFORMED),
        ("signature-2421", [resize("signature", 2421)], MALFORMED),
        ("empty-signature", [resize("signature", 0)], MALFORMED),
        ("key-1311", [resize("public_key", 1311)], MALFORMED),
        ("key-1313", [resize("public_key", 1313)], MALFORMED),
        ("empty-key", [resize("public_key", 0)], MALFORMED),
        ("zero-signature", [fill_edit("signature", 0)], NOT_VALID),
    ]:
        out.append((f"mldsa44/{name}", ctx("mldsa44", "verify", ml, edits), expected))
    # A wallet signature is not a consensus signature under any of the frozen surfaces.
    consensus = {k: ml[k] for k in ("message", "signature", "public_key")}
    for surface in SURFACES:
        inputs = {"surface": surface, **consensus}
        out.append(
            (f"mldsa44/wallet-under-{surface}", ctx("mldsa44", "verify_consensus", inputs), INVALID)
        )
    inputs = {"surface": "simplex", **consensus}
    out.append(
        (
            "mldsa44/consensus-short-key",
            ctx("mldsa44", "verify_consensus", inputs, [resize("public_key", 1311)]),
            MALFORMED,
        )
    )
    key = bytes.fromhex(mldsa["publicKeyHex"])
    key_input = {"public_key": hexb(mldsa["publicKeyHex"])}
    out.append(
        (
            "mldsa44/key-id",
            ctx("mldsa44", "derive_key_id", {"algorithm_id": 1, **key_input}),
            out_bytes(bytes.fromhex(derive_key_id(1, key))),
        )
    )
    for name, algorithm, edits in [
        ("key-id-unknown-algorithm", 0, []),
        ("key-id-unadmitted-algorithm", 2, []),
        ("key-id-max-algorithm", 0xFFFF, []),
        ("key-id-short-key", 1, [resize("public_key", 1311)]),
        ("key-id-long-key", 1, [resize("public_key", 1313)]),
    ]:
        inputs = {"algorithm_id": algorithm, **key_input}
        out.append(
            (
                f"mldsa44/{name}",
                ctx("mldsa44", "derive_key_id", inputs, edits or None),
                rejected("refused"),
            )
        )

    # Falcon-512 (padded), around the "auth" vector.
    falcon = next(
        v
        for v in cast(list[Json], json.loads((src / FALCON_VECTORS).read_text())["vectors"])
        if v["id"] == "auth"
    )
    fa = {
        "message": hexb(falcon["message"]),
        "signature": hexb(falcon["signature"]),
        "public_key": hexb(falcon["public_key"]),
    }
    out.append(("falcon512/base", ctx("falcon512", "verify_padded", fa), VALID))
    for name, edits, expected in [
        ("wrong-key", [xor("public_key", 1)], NOT_VALID),
        # Only lengths are refused as malformed; a key whose header byte does not decode is invalid.
        ("wrong-key-header", [xor("public_key", 0)], NOT_VALID),
        ("wrong-signature", [xor("signature", 100)], NOT_VALID),
        ("wrong-message", [xor("message", 0)], INVALID),
        ("message-8193", [resize("message", 8193)], MALFORMED),
        ("empty-signature", [resize("signature", 0)], MALFORMED),
        ("empty-key", [resize("public_key", 0)], MALFORMED),
    ]:
        out.append((f"falcon512/{name}", ctx("falcon512", "verify_padded", fa, edits), expected))

    # LMS fee bound, on the admitted profile header (pq-crypto lms_fee_cost_bounds): 60 bytes,
    # type LMS_SHA256_M32_H20 (8) and LMOTS_SHA256_N32_W4 (3) after L = 1.
    lms_key = bytearray(60)
    lms_key[3], lms_key[7], lms_key[11] = 1, 8, 3
    lk = b64(bytes(lms_key))
    for size, expected in [
        (0, None),
        (32, integer(1067)),
        (8192, None),
        (8193, rejected("unsupported")),
        (U64_MAX, rejected("unsupported")),
    ]:
        inputs = {"public_key": lk, "message_bytes": str(size)}
        out.append((f"lms-fee/cost-{size}", ctx("lms_fee", "worst_compressions", inputs), expected))
    for name, edits in [
        ("cost-short-key", [resize("public_key", 59)]),
        ("cost-long-key", [resize("public_key", 61)]),
        ("cost-wrong-levels", [xor("public_key", 3, 3)]),
        ("cost-wrong-lms-type", [xor("public_key", 7, 1)]),
        ("cost-wrong-ots-type", [xor("public_key", 11, 1)]),
    ]:
        inputs = {"public_key": lk, "message_bytes": "32"}
        out.append(
            (
                f"lms-fee/{name}",
                ctx("lms_fee", "worst_compressions", inputs, edits),
                rejected("unsupported"),
            )
        )
    empty = {"message": "", "signature": "", "public_key": lk}
    out.append(("lms-fee/empty-signature", ctx("lms_fee", "verify", empty), NOT_VALID))

    # SHA-256 around block boundaries, held to hashlib.
    for size in (0, 1, 55, 56, 63, 64, 65, 1000):
        data = bytes((i * 7 + 3) & 0xFF for i in range(size))
        out.append(
            (
                f"sha256/len-{size}",
                ctx("sha256", "digest", {"data": b64(data)}),
                out_bytes(hashlib.sha256(data).digest()),
            )
        )

    # Quorum: the documented equal-weight thresholds and the edges of has_quorum.
    for total, threshold in [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 2),
        (4, 3),
        (5, 4),
        (6, 4),
        (7, 5),
        (9, 6),
        (10, 7),
        (100, 67),
    ]:
        out.append(
            (
                f"quorum/threshold-{total}",
                ctx("quorum", "threshold", {"total_weight": str(total)}),
                integer(threshold),
            )
        )
    third = U64_MAX // 3
    for signed, total, expected in [
        (0, 0, True),
        (1, 3, False),
        (2, 3, True),
        (2, 4, False),
        (3, 4, True),
        (66, 100, False),
        (67, 100, True),
        (101, 100, True),
        (0, 1, False),
        # U64_MAX is a multiple of 3, so two thirds of it is exact and passes (>=, not >).
        (2 * third - 1, U64_MAX, False),
        (2 * third, U64_MAX, True),
        (U64_MAX, U64_MAX, True),
    ]:
        inputs = {"signed_weight": str(signed), "total_weight": str(total)}
        out.append(
            (
                f"quorum/has-{signed}-of-{total}",
                ctx("quorum", "has_quorum", inputs),
                boolean(expected),
            )
        )

    # PQBytes bounds: the caller limit and the absolute 8 KiB ceiling.
    last = rows(src / PQ_BYTES, " ")[-1]
    data2420, boc2420 = hexb(last[0]), hexb(last[2])
    for name, inputs, edits, expected in [
        ("pack-empty", {"data": "", "max_bytes": 0}, None, None),
        (
            "pack-over-caller-limit",
            {"data": data2420, "max_bytes": 2419},
            None,
            rejected("refused"),
        ),
        (
            "pack-hard-max",
            {"data": data2420, "max_bytes": 8192},
            [resize("data", 8192, 0x5A)],
            None,
        ),
        (
            "pack-over-hard-max",
            {"data": data2420, "max_bytes": 9000},
            [resize("data", 8193, 0x5A)],
            rejected("refused"),
        ),
    ]:
        out.append((f"pq-bytes/{name}", ctx("pq_bytes", "pack", inputs, edits), expected))
    out.append(
        (
            "pq-bytes/unpack-limit",
            ctx("pq_bytes", "unpack", {"boc": boc2420, "max_bytes": 2420}),
            out_bytes(bytes.fromhex(last[0])),
        )
    )
    out.append(
        (
            "pq-bytes/unpack-over-limit",
            ctx("pq_bytes", "unpack", {"boc": boc2420, "max_bytes": 2419}),
            rejected("refused"),
        )
    )

    # The Simplex signing preimage for the carrier vectors' candidate.
    tl = next(r for r in rows(src / SIGNATURE_TL) if r[0] == "node-final")
    block_id = {
        "workchain": -1,
        "shard": str(1 << 63),
        "seqno": 42,
        "root_hash": sha256_hex(b"carrier-root"),
        "file_hash": sha256_hex(b"carrier-file"),
    }
    sign = {
        "session_id": tl[10].lower(),
        "slot": int(tl[11]),
        "candidate": hexb(tl[12]),
        "final": True,
        "block_id": block_id,
    }
    out.append(("consensus/finalize", ctx("consensus", "simplex_data_to_sign", sign), None))
    out.append(
        (
            "consensus/notarize",
            ctx("consensus", "simplex_data_to_sign", {**sign, "final": False}),
            None,
        )
    )
    out.append(
        (
            "consensus/other-slot",
            ctx("consensus", "simplex_data_to_sign", {**sign, "slot": int(tl[11]) + 1}),
            None,
        )
    )
    other = {**block_id, "seqno": 43}
    out.append(
        (
            "consensus/block-id-mismatch",
            ctx("consensus", "simplex_data_to_sign", {**sign, "block_id": other}),
            rejected("block_id_mismatch"),
        )
    )
    out.append(
        (
            "consensus/candidate-truncated",
            ctx("consensus", "simplex_data_to_sign", sign, [resize("candidate", 8)]),
            rejected("candidate_tl"),
        )
    )

    # Session identity: constructor selection and member order on the frozen derivation inputs.
    lines = (src / DERIVATION).read_text().splitlines()
    v = dict(zip(lines[0].split("\t"), lines[1].split("\t"), strict=True))

    def member(validator_id: str, key_id: str, adnl: str, weight: str) -> Json:
        return {
            "kind": "pq",
            "validator_id": validator_id,
            "algorithm_id": 1,
            "key_id": key_id,
            "public_key": b64(b"\x5c" * 1312),
            "weight": weight,
            "adnl": adnl,
        }

    a = member(v["validator_id"].lower(), v["key_id"].lower(), v["adnl"].lower(), v["weight"])
    b = member("d4" * 32, "e5" * 32, "f6" * 32, "7")
    identity: Json = {
        "global_id": int(v["global_id"]),
        "validator_options_hash": v["param29_hash"].lower(),
        "simplex_config_cell_hash": v["selected_param30_cell_hash"].lower(),
        "workchain": int(v["workchain"]),
        "shard": v["shard"],
        "catchain_seqno": int(v["catchain_seqno"]),
        "vertical_seqno": int(v["vertical_seqno"]),
        "last_key_block_seqno": int(v["last_key_block_seqno"]),
        "new_catchain_ids": True,
        "validators": [a],
    }
    for name, change in [
        ("group", {"new_catchain_ids": False, "vertical_seqno": 0}),
        ("group-ex", {"new_catchain_ids": False}),
        ("two-members", {"validators": [a, b]}),
        ("two-members-swapped", {"validators": [b, a]}),
        ("other-global-id", {"global_id": -1}),
        ("other-weight", {"validators": [{**a, "weight": "24"}]}),
        ("basechain", {"workchain": 0}),
    ]:
        out.append(
            (f"session/{name}", ctx("validator_session", "identity", {**identity, **change}), None)
        )
    classical = {"kind": "classical", "public_key": "11" * 32, "weight": "5", "adnl": "c0" * 32}
    out.append(
        (
            "session/members-mixed",
            ctx("validator_session", "members", {"validators": [classical, a]}),
            None,
        )
    )
    out.append(
        ("session/members-empty", ctx("validator_session", "members", {"validators": []}), None)
    )
    return out


FAMILIES: dict[str, Callable[[Path], list[Case]]] = {
    "wycheproof-ed25519": wycheproof,
    "poseidon2-kat": poseidon2,
    "mldsa44-openssl": mldsa_openssl,
    "falcon512-vectors": falcon_vectors,
    "crypto-negatives": negatives,
}


def check(src: Path, fixtures_dir: Path) -> int:
    differences = 0
    for family, fn in FAMILIES.items():
        c = Checker(family)
        fixtures = load_fixtures(fixtures_dir / f"{family}.jsonl")
        cases = fn(src)
        for name, _context, expected in cases:
            fixture = fixtures.get(name)
            if fixture is None:
                c.missing(name)
                continue
            effects = cast(Json, fixture["effects"])
            if expected is None:
                continue
            if isinstance(expected, frozenset):
                c.expect(
                    name,
                    sorted(expected),
                    sorted(expected) if effects.get("verdict") in expected else effects,
                )
            else:
                c.expect(name, expected, effects)
        extra = set(fixtures) - {name for name, _c, _e in cases}
        for name in sorted(extra):
            c.missing(name)
        differences += c.done()
    print(f"total differences {differences}")
    return 1 if differences else 0


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[0] == "contexts":
        src, out = Path(argv[1]), Path(argv[2])
        for family, fn in FAMILIES.items():
            cases = fn(src)
            entries = [entry(name, context) for name, context, _expected in cases]
            print(f"{family}: {write_contexts(out / f'{family}.contexts.jsonl', entries)} contexts")
        return 0
    if len(argv) == 3 and argv[0] == "check":
        return check(Path(argv[1]), Path(argv[2]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
