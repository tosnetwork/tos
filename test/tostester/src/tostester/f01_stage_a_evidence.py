"""Stage A only: bind raw per-node finalization logs to Config34 changes."""

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Awaitable, Callable

from pytosiq_core import Cell


FINALIZED = re.compile(
    r"BlockFinalizedInMasterchain.*?"
    r"\{block=\(-1,8000000000000000,(?P<height>\d+)\):"
    r"(?P<root>[0-9A-Fa-f]{64}):(?P<file>[0-9A-Fa-f]{64})\}"
)
STAMP = re.compile(r"\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\]")


def config34_hash(response: dict[str, Any]) -> str:
    if response.get("error") is not None:
        raise ValueError("ConfigParam 34 RPC returned an error")
    try:
        encoded = response["result"]["config"]["bytes"]
        cell = Cell.one_from_boc(base64.b64decode(encoded, validate=True))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("ConfigParam 34 response has no valid BOC") from error
    return cell.hash.hex()


async def locate_transition(
    read_at: Callable[[int], Awaitable[dict[str, Any]]],
    lower: int, upper: int, before_hash: str, after_hash: str,
) -> int:
    """Find the first post-change MC height, with both neighbors rechecked."""
    if lower < 0 or upper <= lower or before_hash == after_hash:
        raise ValueError("transition bounds or cell hashes are invalid")
    if config34_hash(await read_at(lower)) != before_hash:
        raise ValueError("lower bound is not the previous ConfigParam 34")
    if config34_hash(await read_at(upper)) != after_hash:
        raise ValueError("upper bound is not the activated ConfigParam 34")
    first_new = None
    for height in range(lower + 1, upper + 1):
        observed = config34_hash(await read_at(height))
        if first_new is None and observed == before_hash:
            continue
        if observed != after_hash:
            raise ValueError("an intervening ConfigParam 34 set prevents one-change binding")
        if first_new is None:
            first_new = height
    if first_new is None:
        raise ValueError("ConfigParam 34 activation height was not found")
    return first_new


def extract_finalized_log(path: Path) -> dict[str, Any]:
    """Require the native INFO bus marker and preserve exact raw-file provenance."""
    digest = hashlib.sha256()
    first = last = None
    count = 0
    with path.open("rb") as source:
        for number, line in enumerate(source, 1):
            digest.update(line)
            match = FINALIZED.search(line.decode(errors="replace"))
            if match is None:
                continue
            stamp = STAMP.search(line.decode(errors="replace"))
            if stamp is None:
                raise ValueError(f"{path}:{number}: finalization marker lacks a host timestamp")
            record = {
                "height": int(match["height"]), "root_hash": match["root"].lower(),
                "file_hash": match["file"].lower(), "line": number,
                "at": stamp.group(1),
            }
            first = record if first is None else first
            last = record
            count += 1
    if not count:
        raise ValueError(f"{path}: no native BlockFinalizedInMasterchain marker")
    return {"path": str(path), "sha256": digest.hexdigest(), "markers": count,
            "first": first, "last": last}


def write_manifest(path: Path, *, source: dict, nodes: list[dict],
                   transitions: list[dict]) -> None:
    if len(nodes) != 4 or len({node["node_name"] for node in nodes}) != 4:
        raise ValueError("F01 capture requires four distinct validator node identities")
    for field in ("node_data_dir", "controller_id_hex", "pq_validator_id_hex",
                  "pq_key_id_hex", "adnl_id_hex", "rpc_address"):
        values = [node.get(field) for node in nodes]
        if any(not isinstance(value, str) or not value for value in values):
            raise ValueError(f"F01 capture lacks per-node {field}")
        if len(set(values)) != 4:
            raise ValueError(f"F01 capture aliases per-node {field}")
    if len({Path(node["node_data_dir"]).resolve(strict=True) for node in nodes}) != 4:
        raise ValueError("F01 capture aliases per-node data directories")
    log_paths = set()
    log_hashes = set()
    process_ids = set()
    cwd_owners = {}
    for node in nodes:
        combined = node.get("combined_log")
        segments = node.get("log_segments")
        if not isinstance(combined, dict) or not isinstance(segments, list) or not segments:
            raise ValueError("F01 capture lacks per-node raw logs")
        generations = node.get("process_generations")
        if not isinstance(generations, list) or len(generations) != len(segments):
            raise ValueError("F01 capture lacks one process identity per raw log segment")
        for index, (generation, segment) in enumerate(zip(generations, segments)):
            if (not isinstance(generation, dict)
                    or generation.get("node_name") != node["node_name"]
                    or generation.get("node_data_dir") != node["node_data_dir"]
                    or generation.get("generation") != index
                    or not all(type(generation.get(field)) is int and generation[field] > 0
                               for field in ("pid", "proc_start_ticks", "exe_device", "exe_inode"))
                    or not isinstance(generation.get("exe_path"), str)
                    or not generation["exe_path"]
                    or segment.get("process") != generation):
                raise ValueError("F01 capture raw log is not bound to its process generation")
            identity = (generation["pid"], generation["proc_start_ticks"])
            if identity in process_ids:
                raise ValueError("F01 capture aliases a validator process identity")
            process_ids.add(identity)
            node_dir = Path(node["node_data_dir"]).resolve(strict=True)
            node_dir_stat = node_dir.stat()
            cwd_identity = (generation.get("proc_cwd_device"),
                            generation.get("proc_cwd_inode"))
            if (not isinstance(generation.get("proc_cwd_link"), str)
                    or not generation["proc_cwd_link"]
                    or not Path(generation["proc_cwd_link"]).is_absolute()
                    or Path(generation["proc_cwd_link"]).resolve(strict=True) != node_dir
                    or generation.get("proc_cwd_realpath") != str(node_dir)
                    or any(type(value) is not int or value <= 0 for value in cwd_identity)
                    or cwd_identity != (node_dir_stat.st_dev, node_dir_stat.st_ino)):
                raise ValueError("F01 process cwd differs from its node DB directory")
            if (cwd_identity in cwd_owners
                    and cwd_owners[cwd_identity] != node["node_name"]):
                raise ValueError("F01 capture aliases a validator process cwd")
            cwd_owners[cwd_identity] = node["node_name"]
        for log in [combined, *segments]:
            if (not isinstance(log, dict) or not log.get("path")
                    or not isinstance(log.get("sha256"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", log["sha256"]) is None):
                raise ValueError("F01 capture has malformed raw log provenance")
            resolved = Path(log["path"]).resolve(strict=True)
            if resolved in log_paths:
                raise ValueError("F01 capture aliases raw log paths")
            if hashlib.sha256(resolved.read_bytes()).hexdigest() != log["sha256"]:
                raise ValueError("F01 capture raw log SHA-256 differs from bytes")
            log_paths.add(resolved)
        digest = combined["sha256"]
        if digest in log_hashes:
            raise ValueError("F01 capture duplicates combined raw log SHA-256")
        log_hashes.add(digest)
    if len(transitions) < 1:
        raise ValueError("F01 capture has no ConfigParam 34 transition")
    report = {"schema": "tos.f01.stage-a-capture.v1", "source": source,
              "validators": nodes, "transitions": transitions}
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
