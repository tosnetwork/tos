#!/usr/bin/env python3
"""Config34 for X02 Stage A, proven from the network's own zerostate.

A Config34 claim counts only if the compiled anchored verifier (tos-proof-verify)
authenticates the exact masterchain block from a locally provisioned anchor -- the
network's masterchain zerostate identity, supplied by the caller and never by the
bundle -- through a continuous chain of post-quantum finality proofs, and then proves
ConfigParam 34 from that block's state. This module only drives that verifier and
reads its bound result; it does not check a proof itself.

After the verifier accepts, the proven Config34 cell must be the separately retained
parameter BOC, is decoded field by field (validator_id, algorithm_id, key_id, public
key, ADNL), every key_id is re-derived from its public key, and the set must equal the
four rows frozen before the first fault and belong to the election being checked.
Those comparisons are consistency checks; the authentication is the verifier's.

Runs under the pinned Stage A interpreter with the repository's pytosiq_core; the
stdlib-only coordinator calls it as a separate process and reads its verdict.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

KEY_ID_DOMAIN = b"TOS-PQ-CONSENSUS-KEY-v1"
ML_DSA_44 = 1
ML_DSA_44_PUBLIC_KEY_BYTES = 1312
PQ_BYTES_CHUNK = 127
PQ_BYTES_HARD_MAX = 8192
VERDICT = "X02_CONFIG34_SAME_BLOCK_PROOF_OK"
VERIFIER_INTERFACE = "tos-proof-verify/1"
VERIFIER_RELATIVE = "lite-client/proof-verify/tos-proof-verify"
VERIFIER_TIMEOUT_SECONDS = 90
VERIFIER_OUTPUT_MAX_BYTES = 4 << 20
MATERIAL_MAX_BYTES = 8 << 20
PARAM_MAX_BYTES = 64 << 10
MAX_CHAIN_FILES = 64
CHAIN_NAME = re.compile(r"chain-([0-9]{4})\.tl")
HEX256 = re.compile(r"[0-9a-fA-F]{64}")


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


def derive_key_id(algorithm_id: int, public_key: bytes) -> bytes:
    """key_id = SHA-256(key_id_domain || u16_le(algorithm_id) || public_key) (crypto/pq/pq-consensus.h)."""
    require(
        algorithm_id == ML_DSA_44 and len(public_key) == ML_DSA_44_PUBLIC_KEY_BYTES,
        "only an ML-DSA-44 public key of 1312 bytes has a key_id",
    )
    return hashlib.sha256(KEY_ID_DOMAIN + algorithm_id.to_bytes(2, "little") + public_key).digest()


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


def bundle_paths(election_id: int) -> dict:
    """The only file names a Config34 bundle for this election may use."""
    prefix = f"election-{election_id}-config34-proof/"
    return {"material": prefix + "material/", "param": prefix + "param.boc"}


def check_anchor(anchor: dict) -> dict:
    """The caller's anchor: the network's masterchain zerostate identity."""
    require(isinstance(anchor, dict), "anchor is not an object")
    require(
        set(anchor) == {"kind", "workchain", "shard", "seqno", "root_hash", "file_hash"}
        and anchor["kind"] == "zerostate"
        and anchor["workchain"] == -1
        and anchor["shard"] == "8000000000000000"
        and anchor["seqno"] == 0
        and all(
            isinstance(anchor[k], str) and HEX256.fullmatch(anchor[k])
            for k in ("root_hash", "file_hash")
        ),
        "anchor is not a full masterchain zerostate identity",
    )
    return {
        **anchor,
        "root_hash": anchor["root_hash"].lower(),
        "file_hash": anchor["file_hash"].lower(),
    }


def check_target(block_id: dict) -> dict:
    require(isinstance(block_id, dict), "bundle block_id is not an object")
    require(block_id.get("workchain") == -1, "Config34 is proven from a masterchain block only")
    require(
        str(block_id.get("shard")) in (str(-(1 << 63)), "8000000000000000"),
        "bundle block_id is not the masterchain shard",
    )
    seqno = block_id.get("seqno")
    require(type(seqno) is int and 0 < seqno < 1 << 32, "bundle block_id seqno is invalid")
    for key in ("root_hash", "file_hash"):
        value = block_id.get(key)
        require(
            isinstance(value, str) and HEX256.fullmatch(value) is not None,
            "full block ID digests are not 256-bit",
        )
    return {
        "workchain": -1,
        "shard": "8000000000000000",
        "seqno": seqno,
        "root_hash": block_id["root_hash"].lower(),
        "file_hash": block_id["file_hash"].lower(),
    }


def check_verifier(verifier: Path) -> Path:
    """The verifier is trusted local software named by the caller, never by the bundle."""
    verifier = Path(verifier)
    require(verifier.is_absolute(), "verifier path is not absolute")
    info = os.stat(verifier, follow_symlinks=False)
    require(
        stat.S_ISREG(info.st_mode) and os.access(verifier, os.X_OK),
        "verifier is not an executable regular file",
    )
    return verifier


def material_files(bundle: dict, base: Path, prefix: str) -> dict[str, bytes]:
    """Every retained lite answer, contained, bounded and digest-checked; fixed names only."""
    material = bundle.get("material")
    require(isinstance(material, dict) and material, "Config34 proof bundle has no material")
    chain = sorted(name for name in material if CHAIN_NAME.fullmatch(name))
    require(
        set(material) == {*chain, "config.tl"}
        and 0 < len(chain) <= MAX_CHAIN_FILES
        and chain == [f"chain-{index:04d}.tl" for index in range(len(chain))],
        "Config34 proof material is not a contiguous chain plus one configuration proof",
    )
    files = {}
    for name in [*chain, "config.tl"]:
        entry = material[name]
        require(
            isinstance(entry, dict) and entry.get("path") == prefix + name,
            f"{name} file is not this election's",
        )
        require(
            isinstance(entry.get("sha256"), str) and HEX256.fullmatch(entry["sha256"]) is not None,
            f"{name} has no retained digest",
        )
        files[name] = open_contained(
            base, entry["path"], MATERIAL_MAX_BYTES, entry["sha256"].lower()
        )
    return files


def run_verifier(verifier: Path, anchor: dict, target: dict, files: dict[str, bytes]) -> dict:
    """Run the compiled verifier once on exactly these bytes and bind its result."""
    request = json.dumps(
        {"mode": "historical", "target": target, "config_params": [34]}, sort_keys=True
    ).encode()
    with tempfile.TemporaryDirectory(prefix="x02-config34-") as work:
        work = Path(work)
        (work / "anchor.json").write_text(json.dumps(anchor, sort_keys=True))
        (work / "request.json").write_bytes(request)
        (work / "material").mkdir()
        for name, raw in files.items():
            (work / "material" / name).write_bytes(raw)
        try:
            completed = subprocess.run(
                [
                    str(verifier),
                    "verify",
                    "--anchor",
                    str(work / "anchor.json"),
                    "--request",
                    str(work / "request.json"),
                    "--material",
                    str(work / "material"),
                ],
                capture_output=True,
                timeout=VERIFIER_TIMEOUT_SECONDS,
                env={},
            )
        except subprocess.TimeoutExpired as error:
            raise ProofRefused("anchored verifier did not finish in its bound") from error
    require(len(completed.stdout) <= VERIFIER_OUTPUT_MAX_BYTES, "verifier output exceeds bound")
    try:
        result = json.loads(completed.stdout)
    except ValueError as error:
        raise ProofRefused("verifier output is not one JSON object") from error
    require(isinstance(result, dict), "verifier output is not one JSON object")
    if completed.returncode != 0 or result.get("status") != "verified":
        reason = result.get("reason") if isinstance(result.get("reason"), str) else "no reason"
        raise ProofRefused(
            f"anchored verifier refused (exit {completed.returncode}): {reason[:300]}"
        )
    proven_target = result.get("target") or {}
    require(
        result.get("interface") == VERIFIER_INTERFACE
        and result.get("mode") == "historical"
        and result.get("anchor") == anchor
        and {k: proven_target.get(k) for k in target} == target
        and result.get("request_sha256") == hashlib.sha256(request).hexdigest(),
        "verifier result is not bound to this anchor, target and request",
    )
    params = result.get("config_params")
    require(
        isinstance(params, list) and len(params) == 1 and params[0].get("index") == 34,
        "verifier result does not carry exactly ConfigParam 34",
    )
    return result


def verify_bundle(
    bundle: dict, base: Path, frozen_rows: list[dict], election_id: int, anchor: dict, verifier
) -> dict:
    """Authenticate the bundle's block from the anchor, then check its Config34 and rows."""
    require(isinstance(bundle, dict), "Config34 proof bundle is not an object")
    require(
        {"block_id", "material", "param"} <= set(bundle),
        "Config34 proof bundle is incomplete",
    )
    anchor = check_anchor(anchor)
    target = check_target(bundle["block_id"])
    verifier = check_verifier(verifier)
    paths = bundle_paths(election_id)
    files = material_files(bundle, base, paths["material"])
    param = bundle["param"]
    require(
        isinstance(param, dict) and param.get("path") == paths["param"],
        "param file is not this election's",
    )
    require(
        isinstance(param.get("sha256"), str) and HEX256.fullmatch(param["sha256"]) is not None,
        "param has no retained digest",
    )
    retained_param = open_contained(base, paths["param"], PARAM_MAX_BYTES, param["sha256"].lower())
    result = run_verifier(verifier, anchor, target, files)
    Cell = _pytosiq_cell()
    proven = result["config_params"][0]
    try:
        cell = Cell.one_from_boc(base64.b64decode(proven["boc"], validate=True))
        retained = Cell.one_from_boc(retained_param)
    except Exception as error:  # a malformed BOC is a refusal, never a pass
        raise ProofRefused(f"Config34 BOC cannot be decoded: {error!r}") from error
    require(
        cell.hash.hex() == proven.get("cell_hash"), "verifier Config34 BOC differs from its hash"
    )
    require(
        retained.hash == cell.hash, "retained Config34 BOC differs from the proven parameter cell"
    )
    decoded = decode_validator_set(cell)
    compare_frozen_rows(decoded, frozen_rows, election_id)
    return {
        "verdict": VERDICT,
        "election_id": election_id,
        "anchor": anchor,
        "block_id": target,
        "block_gen_utime": result["target"].get("gen_utime"),
        "chain_links": result["chain"]["links"],
        "chain_key_blocks": [block["seqno"] for block in result["chain"]["key_blocks"]],
        "verifier_request_sha256": result["request_sha256"],
        "config34_cell_hash": decoded["cell_hash"],
        "validators": decoded["validators"],
    }


def _pytosiq_cell():
    from pytosiq_core.boc.cell import Cell

    return Cell


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument(
        "--request",
        type=Path,
        required=True,
        help="JSON: {base, election_id, bundle, frozen_rows, anchor}",
    )
    parser.add_argument("--verifier", type=Path, required=True)
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
            request["anchor"],
            args.verifier,
        )
    except (ProofRefused, OSError) as error:
        print(json.dumps({"verdict": "REFUSED", "reason": str(error)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
