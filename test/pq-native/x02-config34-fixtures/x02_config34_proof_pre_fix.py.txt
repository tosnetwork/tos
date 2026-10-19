#!/usr/bin/env python3
"""Same-block Config34 proof for X02 Stage A, from retained lite bytes only.

A Config34 claim counts only if it is proven, layer by layer, from one exact
masterchain full block ID:
  [optional block BOC: file hash, root hash] -> state proof (Merkle proof of the
  full ID's block root, yielding its state hash) -> config proof (Merkle proof of that state) ->
  ConfigParams dictionary -> parameter cell,
and the separately retained parameter BOC is that same cell. The Config34 cell is
then decoded field by field (validator_id, algorithm_id, key_id, public key, ADNL),
every key_id is re-derived from its public key, and the set must equal the four rows
frozen before the first fault and belong to the election being checked.

The proof starts at the full block ID, and nothing here authenticates that ID: it is
what the frozen local nodes reported, matched by a retained block BOC or by four
nodes' headers. No validator signature and no proof chain from the zerostate is
checked, so a verdict shows the bundle is consistent with that ID, not that the ID is
a finalized block of the network. On the Stage A network the operator runs every node
and holds every validator key, so checking signatures would add no assurance against
whoever produced the bundle; independence would have to come from outside it. The
verdict states this trust root so it is not read as more.

Runs under the pinned Stage A interpreter with the repository's pytosiq_core;
the stdlib-only coordinator calls it as a separate process and reads its verdict.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

KEY_ID_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
ML_DSA_44 = 1
ML_DSA_44_PUBLIC_KEY_BYTES = 1312
PQ_BYTES_CHUNK = 127
PQ_BYTES_HARD_MAX = 8192
MC_STATE_EXTRA_TAG = 0xCC26
BOC_MAX_BYTES = {
    "block": 1 << 20,
    "state_proof": 64 << 10,
    "config_proof": 256 << 10,
    "param": 64 << 10,
}
VERDICT = "X02_CONFIG34_SAME_BLOCK_PROOF_OK"
TRUST_ROOT = {
    "block BOC": "full block ID as captured from the frozen node, matched by its block BOC;"
    " no validator signature or proof chain from the zerostate is checked",
    "four nodes' headers": "full block ID as reported by the four frozen local nodes;"
    " no validator signature or proof chain from the zerostate is checked",
}


class ProofRefused(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ProofRefused(reason)


def read_bounded(path: Path, max_bytes: int, expected_sha256: str | None = None) -> bytes:
    """One regular file, one O_NOFOLLOW descriptor, bounded, hashed on the bytes used."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode) and 0 < info.st_size <= max_bytes,
            f"{path}: not a bounded regular file",
        )
        raw = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    require(len(raw) == info.st_size, f"{path}: size changed while read")
    if expected_sha256 is not None:
        require(hashlib.sha256(raw).hexdigest() == expected_sha256, f"{path}: digest differs")
    return raw


def open_contained(
    root: Path, relative: str, max_bytes: int, expected_sha256: str | None = None
) -> bytes:
    """Read root/relative only if every component is a real entry inside root.

    The root must be a canonical absolute directory; the relative path must be plain
    (no absolute path, empty, "." or ".." component). Each directory is opened from its
    parent descriptor with O_NOFOLLOW, so no ancestor may be a symbolic link either.
    """
    require(
        isinstance(relative, str) and relative and not relative.startswith("/"),
        f"{relative!r}: not a plain relative path",
    )
    parts = relative.split("/")
    require(
        all(part not in ("", ".", "..") for part in parts),
        f"{relative!r}: not a plain relative path",
    )
    root = Path(root)
    require(
        root.is_absolute() and os.path.realpath(root) == str(root),
        f"{root}: artifact root is not a canonical real directory",
    )
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in parts[:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
            )
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        info = os.fstat(fd)
        require(
            stat.S_ISREG(info.st_mode) and 0 < info.st_size <= max_bytes,
            f"{relative}: not a bounded regular file",
        )
        raw = os.read(fd, max_bytes + 1)
    finally:
        os.close(fd)
    require(len(raw) == info.st_size, f"{relative}: size changed while read")
    if expected_sha256 is not None:
        require(hashlib.sha256(raw).hexdigest() == expected_sha256, f"{relative}: digest differs")
    return raw


def bundle_paths(election_id: int) -> dict:
    """The only file names a Config34 bundle for this election may use."""
    prefix = f"election-{election_id}-config34-proof/"
    names = {
        name: prefix + f"{name}.boc" for name in ("block", "state_proof", "config_proof", "param")
    }
    names["headers"] = [prefix + f"header-node{index}.json" for index in range(1, 5)]
    return names


def derive_key_id(algorithm_id: int, public_key: bytes) -> bytes:
    """key_id = SHA-256(key_id_domain || u16_le(algorithm_id) || public_key) (crypto/pq/pq-consensus.h)."""
    require(
        algorithm_id == ML_DSA_44 and len(public_key) == ML_DSA_44_PUBLIC_KEY_BYTES,
        "only an ML-DSA-44 public key of 1312 bytes has a key_id",
    )
    return hashlib.sha256(KEY_ID_DOMAIN + algorithm_id.to_bytes(2, "little") + public_key).digest()


def _pytosiq():
    from pytosiq_core.boc.cell import Cell
    from pytosiq_core.proof.check_proof import ProofError, check_block_header_proof, check_proof

    return Cell, ProofError, check_block_header_proof, check_proof


def proven_config_param(
    block_id: dict, block_boc: bytes | None, state_proof: bytes, config_proof: bytes, index: int
):
    """Return the parameter cell `index` proven from exactly this full block ID.

    The state proof alone binds the block root, as a lite client does. A retained block
    BOC additionally binds the file hash; without one, the caller must bind the full ID's
    file hash to the node's own finalized record.
    """
    Cell, ProofError, check_block_header_proof, check_proof = _pytosiq()
    require(block_id.get("workchain") == -1, "Config34 is proven from a masterchain block only")
    root, file = bytes.fromhex(block_id["root_hash"]), bytes.fromhex(block_id["file_hash"])
    require(len(root) == len(file) == 32, "full block ID digests are not 256-bit")
    if block_boc is not None:
        require(
            hashlib.sha256(block_boc).digest() == file,
            "block BOC file hash differs from the full block ID",
        )
    try:
        if block_boc is not None:
            require(
                Cell.one_from_boc(block_boc).hash == root,
                "block BOC root hash differs from the full block ID",
            )
        state_cell = Cell.one_from_boc(state_proof)
        check_proof(state_cell, root)
        state_hash = check_block_header_proof(state_cell[0], root, True)
        config_cell = Cell.one_from_boc(config_proof)
        check_proof(config_cell, state_hash)
    except ProofError as error:
        raise ProofRefused(
            f"state/config proof does not match the full block ID: {error}"
        ) from error
    state_root = config_cell[0]
    # shard_state refs: out_msg_queue_info, accounts, the ^[...] cell, then Maybe ^McStateExtra.
    require(len(state_root.refs) == 4, "proven state carries no masterchain extra")
    extra = state_root.refs[3].begin_parse()
    require(extra.load_uint(16) == MC_STATE_EXTRA_TAG, "masterchain state extra has the wrong tag")
    if extra.load_bit():  # shard_hashes:ShardHashes (HashmapE)
        extra.load_ref()
    extra.load_bytes(32)  # config_addr
    from pytosiq_core.boc.builder import Builder
    from pytosiq_core.boc.exotic import CellTypes

    try:
        # Same key and value shape as ConfigParams, but keep each value as its cell.
        params = (
            extra.load_ref()
            .begin_parse()
            .load_hashmap(
                32,
                key_deserializer=lambda src: Builder().store_bits(src).to_slice().load_int(32),
                value_deserializer=lambda src: src.load_ref(),
            )
        )
    except (ProofRefused, ProofError):
        raise
    except Exception as error:  # a pruned path inside the dictionary cannot be walked
        raise ProofRefused(
            f"ConfigParams dictionary is not walkable in this proof: {error!r}"
        ) from error
    require(index in params, f"ConfigParam{index} is not proven by this state proof")
    cell = params[index]
    require(cell.type_ == CellTypes.ordinary, f"ConfigParam{index} is pruned in this proof")
    return cell


def unpack_pq_bytes(cell) -> bytes:
    source = cell.begin_parse()
    length = source.load_uint(32)
    require(
        0 < length <= PQ_BYTES_HARD_MAX
        and source.remaining_bits == 0
        and source.remaining_refs == 1,
        "PQ bytes root is malformed",
    )
    current, result = source.load_ref().begin_parse(), bytearray()
    while len(result) < length:
        count = min(PQ_BYTES_CHUNK, length - len(result))
        require(current.remaining_bits == count * 8, "PQ bytes chunk length differs")
        result.extend(current.load_bytes(count))
        if len(result) < length:
            require(current.remaining_refs == 1, "PQ bytes chain ends early")
            current = current.load_ref().begin_parse()
        else:
            require(current.remaining_refs == 0, "PQ bytes chain continues past its length")
    return bytes(result)


def decode_validator_set(cell) -> dict:
    """validators#11 or validators_ext#12 of validator_pq#b3 entries, re-deriving every key_id."""
    source = cell.begin_parse()
    tag = source.load_uint(8)
    require(tag in (0x11, 0x12), "Config34 is not a validator set")
    since, until = source.load_uint(32), source.load_uint(32)
    total, main = source.load_uint(16), source.load_uint(16)
    total_weight = source.load_uint(64) if tag == 0x12 else None
    entries = source.load_dict(16)
    require(
        source.remaining_bits == 0 and source.remaining_refs == 0, "validator set has trailing data"
    )
    require(
        0 < main <= total and len(entries) == total and sorted(entries) == list(range(total)),
        "validator indices are not contiguous",
    )
    rows, weight_sum = [], 0
    for index, entry in sorted(entries.items()):
        require(entry.load_uint(8) == 0xB3, f"validator {index} is not validator_pq#b3")
        validator_id, algorithm_id = entry.load_bytes(32), entry.load_uint(16)
        key_id, weight, adnl = entry.load_bytes(32), entry.load_uint(64), entry.load_bytes(32)
        require(
            entry.remaining_bits == 0 and entry.remaining_refs == 1,
            f"validator {index} is malformed",
        )
        public_key = unpack_pq_bytes(entry.load_ref())
        require(
            key_id == derive_key_id(algorithm_id, public_key),
            f"validator {index} key_id does not derive from its public key",
        )
        require(
            weight > 0 and bytes(32) not in (validator_id, key_id, adnl),
            f"validator {index} is empty",
        )
        weight_sum += weight
        rows.append(
            {
                "index": index,
                "controller_id_hex": validator_id.hex(),
                "algorithm_id": algorithm_id,
                "consensus_key_id_hex": key_id.hex(),
                "adnl_id_hex": adnl.hex(),
                "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
                "weight": weight,
            }
        )
    for field in ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex"):
        require(len({row[field] for row in rows}) == len(rows), f"validator set repeats a {field}")
    require(
        since < until and (total_weight is None or weight_sum == total_weight),
        "validator set totals differ",
    )
    return {
        "tag": tag,
        "utime_since": since,
        "utime_until": until,
        "total": total,
        "main": main,
        "cell_hash": cell.hash.hex(),
        "validators": rows,
    }


def compare_frozen_rows(decoded: dict, frozen_rows: list[dict], election_id: int) -> None:
    require(decoded["utime_since"] == election_id, "Config34 belongs to another election")
    require(
        len(frozen_rows) == decoded["total"] == decoded["main"] == 4,
        "four elected rows are required",
    )
    fields = ("controller_id_hex", "consensus_key_id_hex", "adnl_id_hex")
    actual = {tuple(row[f].lower() for f in fields) for row in decoded["validators"]}
    expected = {tuple(row[f].lower() for f in fields) for row in frozen_rows}
    require(
        actual == expected, "proven Config34 controller/key/ADNL rows differ from the frozen rows"
    )


def require_four_node_headers(
    bundle: dict, base: Path, expected_rpcs: list[str], paths: list[str]
) -> None:
    import base64

    headers = bundle.get("headers") or []
    require(
        len(expected_rpcs) == 4 and len(set(expected_rpcs)) == 4,
        "four distinct frozen node endpoints are required",
    )
    # Exact bijection, in node order, with the frozen endpoints; the reply came from node 1.
    require(
        [item.get("rpc") for item in headers] == list(expected_rpcs)
        and bundle.get("source_rpc") == expected_rpcs[0],
        "header endpoints are not exactly the four frozen node endpoints",
    )
    require([item.get("path") for item in headers] == paths, "header files are not this election's")
    expected = bundle["block_id"]
    for item in headers:
        reply = json.loads(open_contained(base, item["path"], 64 << 10, item["sha256"]))
        full = reply["result"]["id"]
        require(
            full.get("workchain") == expected["workchain"]
            and str(full.get("shard")) == str(expected["shard"])
            and full.get("seqno") == expected["seqno"]
            and base64.b64decode(full["root_hash"], validate=True).hex()
            == expected["root_hash"].lower()
            and base64.b64decode(full["file_hash"], validate=True).hex()
            == expected["file_hash"].lower(),
            f"node header from {item['rpc']} differs from the proven full block ID",
        )


def verify_bundle(
    bundle: dict,
    base: Path,
    frozen_rows: list[dict],
    election_id: int,
    expected_rpcs: list[str],
    index: int = 34,
) -> dict:
    """Verify one retained capture bundle; every file is this election's, contained and bounded."""
    paths = bundle_paths(election_id)
    for name in ("block", "state_proof", "config_proof", "param"):
        if name in bundle:
            require(bundle[name].get("path") == paths[name], f"{name} file is not this election's")
    raw = {
        name: open_contained(base, paths[name], BOC_MAX_BYTES[name], bundle[name]["sha256"])
        for name in ("block", "state_proof", "config_proof", "param")
        if name in bundle
    }
    if "block" not in raw:
        # Without a block BOC the file hash is bound by four nodes' headers for this height.
        require_four_node_headers(bundle, base, expected_rpcs, paths["headers"])
    require(
        {"state_proof", "config_proof", "param"} <= set(raw), "Config34 proof bundle is incomplete"
    )
    proven = proven_config_param(
        bundle["block_id"], raw.get("block"), raw["state_proof"], raw["config_proof"], index
    )
    Cell = _pytosiq()[0]
    require(
        Cell.one_from_boc(raw["param"]).hash == proven.hash,
        "retained Config34 BOC differs from the proven parameter cell",
    )
    decoded = decode_validator_set(proven)
    compare_frozen_rows(decoded, frozen_rows, election_id)
    bound_by = "block BOC" if "block" in raw else "four nodes' headers"
    return {
        "verdict": VERDICT,
        "election_id": election_id,
        "block_id": bundle["block_id"],
        "block_id_trust_root": TRUST_ROOT[bound_by],
        "file_hash_bound_by": bound_by,
        "config34_cell_hash": decoded["cell_hash"],
        "validators": decoded["validators"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--request", type=Path, required=True, help="JSON: {base, election_id, bundle, frozen_rows}"
    )
    parser.add_argument(
        "--dependency-root",
        action="append",
        default=[],
        help="package root to import from; the isolated base interpreter loads no site",
    )
    args = parser.parse_args()
    sys.path[:0] = [str(args.source_root / "test/tostester/src"), *args.dependency_root]
    request = json.loads(read_bounded(args.request, 1 << 20))
    try:
        result = verify_bundle(
            request["bundle"],
            Path(request["base"]),
            request["frozen_rows"],
            request["election_id"],
            request["expected_rpcs"],
        )
    except ProofRefused as error:
        print(json.dumps({"verdict": "REFUSED", "reason": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
