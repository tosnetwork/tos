#!/usr/bin/env python3
"""Fetch Z01 originals for one exact masterchain block through lite-client.

Two production lite-client commands are used, each against one node's own
liteserver and one exact full BlockIdExt:

* ``getblock <id>`` sends ``liteServer.getBlock id:tosNode.blockIdExt`` and,
  with ``-D <dir>``, saves the raw ``liteServer.blockData.data`` bytes only
  after checking their SHA-256 equals the requested file hash.
* ``saveconfig <file> <id>`` sends ``liteServer.getConfigAll mode:0 id:...``,
  verifies the returned state/config proof against that exact ID
  (``block::check_extract_state_proof``) and writes the proven configuration
  dictionary BOC.

The raw state/config proof bytes themselves come from the node JSON-RPC
``getConfigParam`` with ``with_proof=true`` (``liteServer.getConfigParams``);
lite-client does not persist them. This module is an independent second
route to the same block and parameter cells, not a replacement for them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Sequence

MASTERCHAIN_SHARD_HEX = "8000000000000000"
HEX64 = re.compile(r"[0-9a-f]{64}")
SAVED_CONFIG = re.compile(rb"saved configuration dictionary into file `([^`]+)` \((\d+) bytes written\)")


class LiteError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise LiteError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def block_id_text(exact: Sequence[Any]) -> str:
    """Render an exact masterchain full ID in lite-client's parse_block_id_ext form."""
    require(len(exact) == 5, "full BlockIdExt must have five fields")
    wc, shard, seqno, root, file = exact
    require(wc == -1 and shard in (-(1 << 63), 1 << 63), "not a masterchain full ID")
    require(type(seqno) is int and seqno > 0, "masterchain seqno is invalid")
    require(isinstance(root, str) and isinstance(file, str)
            and HEX64.fullmatch(root) is not None and HEX64.fullmatch(file) is not None
            and int(root, 16) != 0 and int(file, 16) != 0, "full ID digests are invalid")
    return f"(-1,{MASTERCHAIN_SHARD_HEX},{seqno}):{root.upper()}:{file.upper()}"


def db_block_path(db_dir: Path, file_hash: str) -> Path:
    """Mirror block::compute_db_filename(db_root + '/', file_hash) with depth 4."""
    upper = file_hash.upper()
    return db_dir / upper[0:2] / upper[2:4] / upper[4:6] / upper[6:8] / f"{upper}.boc"


def run_lite(lite_client: Path, lite_config: Path, commands: list[str], out: Path, label: str,
             db_dir: Path | None = None, timeout: float = 30.0,
             runner: list[str] | None = None) -> dict[str, Any]:
    """Run one batch lite-client invocation and retain its complete originals."""
    argv = [str(lite_client), "-C", str(lite_config), "-r", "-t", str(int(timeout))]
    if db_dir is not None:
        argv += ["-D", str(db_dir)]
    for command in commands:
        argv += ["-c", command]
    argv = (runner or []) + argv
    at = time.monotonic_ns()
    try:
        completed = subprocess.run(argv, capture_output=True, check=False, timeout=timeout + 15)
        exit_code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        exit_code = None
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
    finished = time.monotonic_ns()
    receipt = {"label": label, "argv": argv, "exit": exit_code,
               "at_monotonic_ns": at, "completed_monotonic_ns": finished,
               "stdout_sha256": sha(stdout), "stderr_sha256": sha(stderr)}
    (out / f"{label}.command.json").write_text(json.dumps(argv) + "\n")
    (out / f"{label}.stdout.raw").write_bytes(stdout)
    (out / f"{label}.stderr.raw").write_bytes(stderr)
    (out / f"{label}.exit.raw").write_text(f"{exit_code}\n")
    receipt["stdout"] = stdout
    receipt["stderr"] = stderr
    return receipt


def fetch_block(lite_client: Path, lite_config: Path, exact: Sequence[Any], out: Path,
                label: str, runner: list[str] | None = None) -> dict[str, Any]:
    """Fetch one raw block BOC by exact full ID; reject any byte/hash mismatch."""
    text = block_id_text(exact)
    db_dir = out / f"{label}-lite-db"
    db_dir.mkdir(parents=False, exist_ok=False)
    receipt = run_lite(lite_client, lite_config, [f"getblock {text}"], out, label, db_dir,
                       runner=runner)
    require(receipt["exit"] == 0, f"{label}: lite-client getblock did not exit 0")
    saved = db_block_path(db_dir, exact[4])
    require(saved.is_file(), f"{label}: lite-client did not save the requested block")
    raw = saved.read_bytes()
    require(sha(raw) == exact[4], f"{label}: saved block bytes differ from the full-ID file hash")
    retained = out / f"{label}.block.boc"
    shutil.copyfile(saved, retained)
    require(sha(retained.read_bytes()) == exact[4], f"{label}: retained block copy differs")
    return {"path": str(retained), "sha256": exact[4], "lite_db_path": str(saved),
            "command": receipt["argv"], "exit": receipt["exit"],
            "stdout_sha256": receipt["stdout_sha256"], "stderr_sha256": receipt["stderr_sha256"]}


def config_param_hashes(dictionary_boc: bytes, params: Sequence[int]) -> dict[str, str]:
    """Decode a saved configuration dictionary BOC and hash selected parameter cells."""
    from pytosiq_core import Builder
    from pytosiq_core.boc.deserialize import Boc

    roots = Boc(dictionary_boc).deserialize()
    require(len(roots) == 1, "configuration dictionary BOC must have exactly one root")
    config = roots[0].begin_parse().load_hashmap(
        32, key_deserializer=lambda src: Builder().store_bits(src).to_slice().load_int(32),
        value_deserializer=lambda src: src.load_ref())
    require(isinstance(config, dict), "configuration dictionary is malformed")
    result = {}
    for param in params:
        require(param in config, f"ConfigParam{param} is absent from the proven dictionary")
        result[str(param)] = config[param].hash.hex()
    return result


def fetch_proven_config(lite_client: Path, lite_config: Path, exact: Sequence[Any], out: Path,
                        label: str, expected: dict[str, str],
                        runner: list[str] | None = None) -> dict[str, Any]:
    """Have lite-client verify getConfigAll for the exact ID, then bind parameter cells."""
    require(bool(expected) and all(HEX64.fullmatch(value) for value in expected.values()),
            "expected parameter cell hashes are missing")
    text = block_id_text(exact)
    target = out / f"{label}.config-dict.boc"
    require(not target.exists(), f"{label}: saved config target already exists")
    receipt = run_lite(lite_client, lite_config, [f"saveconfig {target} {text}"], out, label,
                       runner=runner)
    require(receipt["exit"] == 0, f"{label}: lite-client saveconfig did not exit 0")
    match = SAVED_CONFIG.search(receipt["stdout"])
    require(match is not None and os.fsdecode(match[1]) == str(target),
            f"{label}: lite-client did not report the proven dictionary save")
    raw = target.read_bytes()
    require(len(raw) == int(match[2]), f"{label}: saved dictionary length differs from its report")
    actual = config_param_hashes(raw, [int(key) for key in expected])
    require(actual == expected, f"{label}: proven parameter cells differ: {actual} != {expected}")
    return {"path": str(target), "sha256": sha(raw), "param_cell_hashes": actual,
            "command": receipt["argv"], "exit": receipt["exit"],
            "stdout_sha256": receipt["stdout_sha256"], "stderr_sha256": receipt["stderr_sha256"]}
