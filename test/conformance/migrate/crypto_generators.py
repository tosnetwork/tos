#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Migrate the C++ crypto and consensus-identity vector generators to crypto-harness contexts.

    crypto_generators.py contexts <source-dir> <out-dir>
        Write <family>.contexts.jsonl for every family below, from the frozen generator files.
    crypto_generators.py check --source-dir DIR --vectors DIR [--<generator> PATH ...]
        Require every fixture's effects to agree with the frozen generator file it came from, row
        for row, and (when the generator binaries are given) every frozen file to still be what its
        generator prints, so the migration is shown not to change what is compared.

Families and the files they come from (paths relative to the source tree):

    pq-bytes                      test/pq-mldsa44/pq-bytes-vectors.txt (pq-bytes-vectors-gen)
    config43                      test/pq-native/config43-vectors.tsv (config43-vectors-gen)
    authorisation-preimage        test/pq-native/authorisation-preimage-vectors.tsv
    descriptor-verdict            test/pq-native/descriptor-verdict-vectors.tsv
    validator-session-members     test/pq-native/validator-session-vectors.txt
    validator-session-derivation  test/pq-native/validator-session-derivation-vectors.tsv
    pq-block-signatures           test/pq-native/pq-block-signature-vectors.txt
    pq-signature-tl               test/pq-native/pq-signature-tl-vectors.txt
    slhdsa128s-openssl            test/pq-slhdsa/slh-verify-vectors.txt

The generators fix some inputs in code rather than in their output (the authorisation preimage
fields, the descriptor set header, the session validators' keys); those are restated here exactly
as the generator sources state them.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

# Run as a script from its own directory, next to the shared helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from crypto_common import (  # noqa: E402
    MLDSA44_PUBLIC_KEY_BYTES,
    Checker,
    Json,
    b64,
    ctx,
    derive_key_id,
    effects_of,
    entry,
    fill,
    hexb,
    load_fixtures,
    require_all_used,
    rows,
    sha256_hex,
    write_contexts,
)

PQ_BYTES = "test/pq-mldsa44/pq-bytes-vectors.txt"
CONFIG43 = "test/pq-native/config43-vectors.tsv"
PREIMAGE = "test/pq-native/authorisation-preimage-vectors.tsv"
DESCRIPTOR = "test/pq-native/descriptor-verdict-vectors.tsv"
SESSION = "test/pq-native/validator-session-vectors.txt"
DERIVATION = "test/pq-native/validator-session-derivation-vectors.tsv"
BLOCK_SIGNATURES = "test/pq-native/pq-block-signature-vectors.txt"
SIGNATURE_TL = "test/pq-native/pq-signature-tl-vectors.txt"
SLHDSA = "test/pq-slhdsa/slh-verify-vectors.txt"

PQ_BYTES_MAX = 2420
CONFIG43_FIELDS = (
    "max_msg_bits,max_msg_cells,max_library_cells,max_vm_data_depth,max_ext_msg_size,"
    "max_ext_msg_depth,max_acc_state_cells,max_mc_acc_state_cells,max_acc_public_libraries,"
    "defer_out_queue_size_limit,max_msg_extra_currencies,max_acc_fixed_prefix_length,"
    "acc_state_cells_for_storage_dict,max_transaction_library_loads,max_total_msg_bits,"
    "max_total_msg_cells,out_msg_queue_size_hard_limit,out_msg_queue_size_soft_limit"
).split(",")

# authorisation-preimage-vectors-gen.cpp main(): (operation, inputs) per emitted name.
PREIMAGE_INPUTS: dict[str, tuple[str, Json]] = {}


def _stake(global_id: int, factor: int, src: int, adnl: int) -> tuple[str, Json]:
    return "stake_preimage", {
        "global_id": global_id,
        "stake_at": 1789434000,
        "max_factor": factor,
        "src_addr": fill(src),
        "adnl_addr": fill(adnl),
    }


def _config(set_id: int, idx: int) -> tuple[str, Json]:
    return "config_vote_preimage", {
        "global_id": -239,
        "validator_set_id": fill(set_id),
        "validator_id": fill(0xA1),
        "idx": idx,
        "proposal_hash": fill(0xE5),
    }


def _complaint(election: int) -> tuple[str, Json]:
    return "complaint_vote_preimage", {
        "global_id": -239,
        "validator_set_id": fill(0xD4),
        "validator_id": fill(0xA1),
        "idx": 7,
        "election_id": election,
        "complaint_hash": fill(0xF6),
    }


PREIMAGE_INPUTS.update(
    {
        "stake": _stake(-239, 0x10000, 0xA1, 0xC3),
        "config-vote": _config(0xD4, 7),
        "complaint-vote": _complaint(1789434000),
        "stake-other-sender": _stake(-239, 0x10000, 0xA2, 0xC3),
        "stake-other-address": _stake(-239, 0x10000, 0xA1, 0xC4),
        "stake-other-factor": _stake(-239, 0x10001, 0xA1, 0xC3),
        "stake-other-network": _stake(-1, 0x10000, 0xA1, 0xC3),
        "config-vote-other-set": _config(0xD5, 7),
        "config-vote-other-index": _config(0xD4, 8),
        "complaint-vote-other-election": _complaint(1789434001),
    }
)

# descriptor-verdict-vectors-gen.cpp: single_set(descr, total_weight) with this header.
DESCRIPTOR_TOTAL_WEIGHT = {"valid-max-weight": 0x3FFFFFFFFFFFFFFF, "zero-weight": 0}

# pq-block-signature-vectors-test.cpp: cases decoded against a trusted set, and which of them
# derive the key id from the key (trusted_validator_set) rather than patterning it.
VSET_CASES = {
    "claimed-weight-mismatch",
    "unknown-validator-id",
    "validator-algorithm-mismatch",
    "old-11-under-pq-vset",
    "old-12-under-pq-vset",
}
TRUSTED_VSET_CASES = {"claimed-weight-mismatch", "unknown-validator-id"}
CARRIER_CATCHAIN_SEQNO = 1789434

# validator-session-derivation-vectors-gen.cpp make_vector(): the one validator's public key and
# the default ValidatorSessionConfig whose options hash is the param29_hash column.
DERIVATION_PUBLIC_KEY = b"\x5c" * MLDSA44_PUBLIC_KEY_BYTES
DEFAULT_SESSION_OPTIONS: Json = {
    "proto_version": 0,
    "idle_timeout": "16.0",
    "max_deps": 4,
    "max_serialized_block_size": 16 * 1024,
    "block_hash_covers_data": False,
    "max_block_height_coeff": "0",
    "debug_disable_db": False,
    "round_candidates": 3,
    "next_candidate_delay": "2.0",
    "round_attempt_duration": 16,
    "max_round_attempts": 4,
    "max_block_size": 4 << 20,
    "max_collated_data_size": 4 << 20,
    "new_catchain_ids": False,
}


def session_validator(name: str) -> Json:
    """validator-session-vectors-gen.cpp main(): the descriptor behind each emitted name."""
    adnl = fill(0xC0)
    if name == "classical":
        return {"kind": "classical", "public_key": fill(0x11), "weight": "5", "adnl": adnl}
    key_ids = {"pq-a-key1": 0xB0, "pq-a-key2": 0xB1}
    return {
        "kind": "pq",
        "validator_id": fill(0xA0),
        "algorithm_id": 1,
        "key_id": fill(key_ids[name]),
        "public_key": b64(b"\x01" * MLDSA44_PUBLIC_KEY_BYTES),
        "weight": "5",
        "adnl": adnl,
    }


def carrier_vset(name: str, ids: list[str], algorithms: list[int]) -> Json:
    validators: list[Json] = []
    for i, (validator_id, algorithm) in enumerate(zip(ids, algorithms, strict=True)):
        key = bytes([i + 1]) * MLDSA44_PUBLIC_KEY_BYTES
        key_id = (
            derive_key_id(algorithm, key)
            if name in TRUSTED_VSET_CASES
            else sha256_hex(f"fixture-key-{i}".encode())
        )
        validators.append(
            {
                "kind": "pq",
                "validator_id": validator_id.lower(),
                "algorithm_id": algorithm,
                "key_id": key_id,
                "public_key": b64(key),
                "weight": "1",
                "adnl": sha256_hex(f"fixture-adnl-{i}".encode()),
            }
        )
    return {"catchain_seqno": CARRIER_CATCHAIN_SEQNO, "validators": validators}


def split_list(text: str) -> list[str]:
    return [] if text == "-" else text.split(",")


# ---------------------------------------------------------------------------------------------
# contexts


def contexts_pq_bytes(src: Path) -> list[Json]:
    out: list[Json] = []
    for i, row in enumerate(rows(src / PQ_BYTES, " ")):
        data, _root, boc = row
        size = len(data) // 2
        out.append(
            entry(
                f"pack-{i}-len{size}",
                ctx("pq_bytes", "pack", {"data": hexb(data), "max_bytes": PQ_BYTES_MAX}),
            )
        )
        out.append(
            entry(
                f"unpack-{i}-len{size}",
                ctx("pq_bytes", "unpack", {"boc": hexb(boc), "max_bytes": PQ_BYTES_MAX}),
            )
        )
    return out


def contexts_config43(src: Path) -> list[Json]:
    return [
        entry(
            row[0], ctx("config43", "parse", {"boc": hexb(row[2])}), f"generator verdict {row[1]}"
        )
        for row in rows(src / CONFIG43)
    ]


def contexts_preimage(src: Path) -> list[Json]:
    out: list[Json] = []
    for row in rows(src / PREIMAGE):
        operation, inputs = PREIMAGE_INPUTS[row[0]]
        out.append(entry(row[0], ctx("elector", operation, inputs)))
    return out


def contexts_descriptor(src: Path) -> list[Json]:
    out: list[Json] = []
    for row in rows(src / DESCRIPTOR):
        weight = DESCRIPTOR_TOTAL_WEIGHT.get(row[0], 5)
        inputs: Json = {
            "descriptors": [hexb(row[2])],
            "utime_since": 100,
            "utime_until": 200,
            "total": 1,
            "main": 1,
            "total_weight": str(weight),
        }
        out.append(
            entry(row[0], ctx("validator_set", "unpack", inputs), f"generator verdict {row[1]}")
        )
    return out


def contexts_session(src: Path) -> list[Json]:
    return [
        entry(
            row[0], ctx("validator_session", "members", {"validators": [session_validator(row[0])]})
        )
        for row in rows(src / SESSION, " ")
    ]


def derivation_row(src: Path) -> dict[str, str]:
    lines = (src / DERIVATION).read_text().splitlines()
    if len(lines) != 2:
        raise SystemExit(f"{DERIVATION}: header and one row expected")
    return dict(zip(lines[0].split("\t"), lines[1].split("\t"), strict=True))


def contexts_derivation(src: Path) -> list[Json]:
    v = derivation_row(src)
    validator = {
        "kind": "pq",
        "validator_id": v["validator_id"].lower(),
        "algorithm_id": 1,
        "key_id": v["key_id"].lower(),
        "public_key": b64(DERIVATION_PUBLIC_KEY),
        "weight": v["weight"],
        "adnl": v["adnl"].lower(),
    }
    identity = {
        "global_id": int(v["global_id"]),
        "validator_options_hash": v["param29_hash"].lower(),
        "simplex_config_cell_hash": v["selected_param30_cell_hash"].lower(),
        "workchain": int(v["workchain"]),
        "shard": v["shard"],
        "catchain_seqno": int(v["catchain_seqno"]),
        "vertical_seqno": int(v["vertical_seqno"]),
        "last_key_block_seqno": int(v["last_key_block_seqno"]),
        "new_catchain_ids": True,
        "validators": [validator],
    }
    config_hash = {
        k: identity[k] for k in ("global_id", "validator_options_hash", "simplex_config_cell_hash")
    }
    return [
        entry("identity", ctx("validator_session", "identity", identity)),
        entry("config-hash", ctx("validator_session", "config_hash", config_hash)),
        entry(
            "default-options-hash",
            ctx("validator_session", "options_hash", DEFAULT_SESSION_OPTIONS),
        ),
    ]


def contexts_block_signatures(src: Path) -> list[Json]:
    out: list[Json] = []
    for row in rows(src / BLOCK_SIGNATURES):
        name = row[0]
        inputs: Json = {"boc": hexb(row[4])}
        if name in VSET_CASES:
            ids = split_list(row[9])
            algorithms = [int(a) for a in split_list(row[10])]
            inputs["validator_set"] = carrier_vset(name, ids, algorithms)
        out.append(
            entry(name, ctx("block_signatures", "fetch", inputs), f"generator outcome {row[1]}")
        )
    return out


def contexts_signature_tl(src: Path) -> list[Json]:
    return [
        entry(
            row[0], ctx("block_signatures", "fetch_tl", {"carrier": row[3], "wire": hexb(row[13])})
        )
        for row in rows(src / SIGNATURE_TL)
    ]


def contexts_slhdsa(src: Path) -> list[Json]:
    out: list[Json] = []
    for i, (key, context, message, signature) in enumerate(rows(src / SLHDSA, " ")):
        inputs = {
            "message": hexb(message),
            "context": hexb(context),
            "signature": hexb(signature),
            "public_key": hexb(key),
        }
        out.append(entry(f"openssl-{i}", ctx("slhdsa128s", "verify", inputs)))
    return out


FAMILIES: dict[str, Callable[[Path], list[Json]]] = {
    "pq-bytes": contexts_pq_bytes,
    "config43": contexts_config43,
    "authorisation-preimage": contexts_preimage,
    "descriptor-verdict": contexts_descriptor,
    "validator-session-members": contexts_session,
    "validator-session-derivation": contexts_derivation,
    "pq-block-signatures": contexts_block_signatures,
    "pq-signature-tl": contexts_signature_tl,
    "slhdsa128s-openssl": contexts_slhdsa,
}

SOURCES = {
    "pq-bytes": PQ_BYTES,
    "config43": CONFIG43,
    "authorisation-preimage": PREIMAGE,
    "descriptor-verdict": DESCRIPTOR,
    "validator-session-members": SESSION,
    "validator-session-derivation": DERIVATION,
    "pq-block-signatures": BLOCK_SIGNATURES,
    "pq-signature-tl": SIGNATURE_TL,
    "slhdsa128s-openssl": SLHDSA,
}


# ---------------------------------------------------------------------------------------------
# check


def fields_of(effects: Json | None) -> dict[str, str] | None:
    if effects is None or effects.get("outcome") != "record":
        return None
    return cast(dict[str, str], effects["fields"])


def outcome(effects: Json | None) -> str:
    if effects is None:
        return "<none>"
    if effects["outcome"] == "rejected":
        return f"rejected:{effects['reason']}"
    return cast(str, effects["outcome"])


def check_pq_bytes(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("pq-bytes")
    used: set[str] = set()
    for i, (data, root, boc) in enumerate(rows(src / PQ_BYTES, " ")):
        size = len(data) // 2
        pack, unpack = f"pack-{i}-len{size}", f"unpack-{i}-len{size}"
        used |= {pack, unpack}
        fields = fields_of(effects_of(fx, pack, c))
        c.expect(pack, {"root_hash": root, "boc": boc}, fields)
        c.expect(unpack, {"outcome": "bytes", "output": data}, effects_of(fx, unpack, c))
    require_all_used(fx, used, c)
    return c.done()


def check_config43(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("config43")
    used: set[str] = set()
    for row in rows(src / CONFIG43):
        used.add(row[0])
        effects = effects_of(fx, row[0], c)
        if row[1] == "reject":
            c.expect(row[0], "rejected:refused", outcome(effects))
            continue
        fields = fields_of(effects)
        c.expect(
            row[0],
            row[3],
            ",".join(fields[k] for k in CONFIG43_FIELDS) if fields else outcome(effects),
        )
    require_all_used(fx, used, c)
    return c.done()


def check_preimage(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("authorisation-preimage")
    used: set[str] = set()
    for name, size, data in rows(src / PREIMAGE):
        used.add(name)
        effects = effects_of(fx, name, c)
        c.expect(name, {"outcome": "bytes", "output": data}, effects)
        c.expect(f"{name}.length", int(size), len(data) // 2)
    require_all_used(fx, used, c)
    return c.done()


def check_descriptor(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("descriptor-verdict")
    used: set[str] = set()
    for name, verdict, _boc in rows(src / DESCRIPTOR):
        used.add(name)
        effects = effects_of(fx, name, c)
        c.expect(name, "record" if verdict == "accept" else "rejected:refused", outcome(effects))
    require_all_used(fx, used, c)
    return c.done()


def check_session(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("validator-session-members")
    used: set[str] = set()
    for name, constructor, member, group, session_id in rows(src / SESSION, " "):
        used.add(name)
        fields = fields_of(effects_of(fx, name, c))
        c.expect(name, {"constructor_ids": constructor, "members": member}, fields)
        # The group and its id are built by the generator itself from the member, not by a
        # node function; check only that the frozen columns are consistent with the member.
        c.expect(f"{name}.group-embeds-member", True, member in group)
        c.expect(
            f"{name}.session-id-is-group-hash",
            session_id,
            hashlib.sha256(bytes.fromhex(group)).hexdigest(),
        )
    require_all_used(fx, used, c)
    return c.done()


def check_derivation(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("validator-session-derivation")
    v = derivation_row(src)
    identity = fields_of(effects_of(fx, "identity", c))
    c.expect(
        "identity",
        {
            "session_config_hash": v["session_config_hash"].lower(),
            "session_id": v["validator_session_id"].lower(),
        },
        identity,
    )
    c.expect(
        "config-hash",
        {"outcome": "bytes", "output": v["session_config_hash"].lower()},
        effects_of(fx, "config-hash", c),
    )
    c.expect(
        "default-options-hash",
        {"outcome": "bytes", "output": v["param29_hash"].lower()},
        effects_of(fx, "default-options-hash", c),
    )
    require_all_used(fx, {"identity", "config-hash", "default-options-hash"}, c)
    return c.done()


def check_block_signatures(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("pq-block-signatures")
    used: set[str] = set()
    for row in rows(src / BLOCK_SIGNATURES):
        name = row[0]
        used.add(name)
        effects = effects_of(fx, name, c)
        if row[1] == "reject":
            c.expect(name, f"rejected:{row[2]}", outcome(effects))
            continue
        fields = fields_of(effects)
        expected = {
            "is_pq": "true",
            "is_final": "true",
            "size": row[8],
            "validator_set_hash": row[6],
            "catchain_seqno": row[7],
            "validator_ids": row[9].lower(),
            "algorithm_ids": row[10],
            "session_id": row[11].lower(),
            "slot": row[12],
            "candidate_sha256": row[13].lower(),
            "reserialized_equal": "true",
        }
        actual = {k: (fields or {}).get(k) for k in expected}
        c.expect(name, expected, actual)
    require_all_used(fx, used, c)
    return c.done()


def check_signature_tl(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("pq-signature-tl")
    used: set[str] = set()
    for row in rows(src / SIGNATURE_TL):
        name = row[0]
        used.add(name)
        effects = effects_of(fx, name, c)
        if row[1] == "reject":
            # A lite carrier that is not a lite constructor fails TL decoding before any check.
            reason = "tl_parse" if row[2] == "wrong_constructor" else row[2]
            c.expect(name, f"rejected:{reason}", outcome(effects))
            continue
        fields = fields_of(effects)
        expected = {
            "is_pq": "true",
            "is_final": "true" if row[4] == "final" else "false",
            "size": "1",
            "catchain_seqno": row[5],
            "validator_set_hash": row[6],
            "validator_ids": row[7].lower(),
            "algorithm_ids": row[8],
            "signature_sha256": sha256_hex(bytes.fromhex(row[9])),
            "session_id": row[10].lower(),
            "slot": row[11],
            "candidate_sha256": sha256_hex(bytes.fromhex(row[12])),
            "reserialized_equal": "true",
        }
        actual = {k: (fields or {}).get(k) for k in expected}
        c.expect(name, expected, actual)
    require_all_used(fx, used, c)
    return c.done()


def check_slhdsa(src: Path, fx: dict[str, Json]) -> int:
    c = Checker("slhdsa128s-openssl")
    used: set[str] = set()
    for i, _row in enumerate(rows(src / SLHDSA, " ")):
        name = f"openssl-{i}"
        used.add(name)
        # The file states that every signature must verify.
        c.expect(name, {"outcome": "verdict", "verdict": "valid"}, effects_of(fx, name, c))
    require_all_used(fx, used, c)
    return c.done()


CHECKS: dict[str, Callable[[Path, dict[str, Json]], int]] = {
    "pq-bytes": check_pq_bytes,
    "config43": check_config43,
    "authorisation-preimage": check_preimage,
    "descriptor-verdict": check_descriptor,
    "validator-session-members": check_session,
    "validator-session-derivation": check_derivation,
    "pq-block-signatures": check_block_signatures,
    "pq-signature-tl": check_signature_tl,
    "slhdsa128s-openssl": check_slhdsa,
}

GENERATORS = {
    "pq_bytes_gen": PQ_BYTES,
    "config43_gen": CONFIG43,
    "preimage_gen": PREIMAGE,
    "descriptor_gen": DESCRIPTOR,
    "session_gen": SESSION,
}


def check(args: argparse.Namespace) -> int:
    src = cast(Path, args.source_dir)
    vectors = cast(Path, args.vectors)
    differences = 0
    for family, fn in CHECKS.items():
        path = vectors / f"{family}.jsonl"
        if not path.exists():
            print(f"DIFF {family}: fixture file {path} missing")
            differences += 1
            continue
        differences += fn(src, load_fixtures(path))
    for option, frozen in GENERATORS.items():
        program = cast(str | None, getattr(args, option))
        if program is None:
            continue
        done = subprocess.run([program], capture_output=True, text=True, timeout=300, check=False)
        if done.returncode != 0 or done.stdout != (src / frozen).read_text():
            print(f"DIFF {frozen}: no longer what {Path(program).name} prints")
            differences += 1
    print(f"total differences {differences}")
    return 1 if differences else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    contexts = sub.add_parser("contexts")
    contexts.add_argument("source_dir", type=Path)
    contexts.add_argument("out_dir", type=Path)
    checker = sub.add_parser("check")
    checker.add_argument("--source-dir", type=Path, required=True)
    checker.add_argument("--vectors", type=Path, required=True)
    for option in GENERATORS:
        checker.add_argument("--" + option.replace("_", "-"), dest=option)
    args = parser.parse_args(argv)
    if args.command == "contexts":
        for family, fn in FAMILIES.items():
            count = write_contexts(args.out_dir / f"{family}.contexts.jsonl", fn(args.source_dir))
            print(f"{family}: {count} contexts from {SOURCES[family]}")
        return 0
    return check(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
