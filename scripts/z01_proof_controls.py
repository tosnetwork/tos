#!/usr/bin/env python3
"""Run the Z01 Config30 proof-checker control matrix on one retained quartet.

A quartet is one exact masterchain full BlockIdExt plus four original byte
files captured from a live node: the block BOC, the liteServer.configInfo
state proof and config proof, and the ConfigParam30 cell BOC. The matrix runs
one valid positive and single-input negatives. Every negative must be refused
with the exact message of the check it targets, so a checker that refuses
everything, or refuses at an earlier check, does not pass.

This tool never contacts a node. It only reads retained originals and writes
command/exit/stdout/stderr/SHA receipts under a new output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REJECT_PREFIX = b"Z01_CONFIG_PROOF_REJECT: "
FILE_REJECT = b"block BOC file hash differs from full BlockIdExt"
ROOT_REJECT = b"block BOC root hash differs from full BlockIdExt"
PROOF_REJECT = b"state/config proof does not match the block ID"
PARAM_REJECT = b"ConfigParam30 cell differs from proven state"
MASTERCHAIN_SHARD = 1 << 63
HEX64 = re.compile(r"[0-9a-f]{64}")

# Control name -> exact stderr the checker must print (None: must pass).
EXPECTED = {
    "positive": None,
    "wrong_root_hash": ROOT_REJECT,
    "wrong_file_hash": FILE_REJECT,
    "mutated_block_byte": FILE_REJECT,
    "mutated_block_byte_consistent_file_hash": ROOT_REJECT,
    "wrong_param30_cell": PARAM_REJECT,
    "state_proof_from_other_block": PROOF_REJECT,
}


class ControlError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ControlError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_once(path: Path, raw: bytes) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
    return sha(raw)


def flip_hex(value: str) -> str:
    """Change exactly the last nibble of a 64-hex digest."""
    require(HEX64.fullmatch(value) is not None, "digest must be 64 lowercase hex characters")
    last = "0" if value[-1] != "0" else "1"
    return value[:-1] + last


def mutate_middle_byte(raw: bytes) -> bytes:
    """Flip every bit of one byte in the middle of the BOC (never a no-op)."""
    require(len(raw) >= 32, "block BOC is too short to mutate")
    index = len(raw) // 2
    return raw[:index] + bytes([raw[index] ^ 0xFF]) + raw[index + 1:]


def positive_output_matches(stdout: bytes, seqno: int, root: str, file: str, param30: str) -> bool:
    """Bind the native checker's hex output to the exact block and cell.

    The native checker prints digests with td's uppercase to_hex(); quartet
    digests are lowercase. Letter case alone may differ, every digit must not.
    """
    match = re.fullmatch(
        rb"Z01_CONFIG_PROOF_OK seqno=(\d+) root=([0-9A-Fa-f]{64}) "
        rb"file=([0-9A-Fa-f]{64}) param30=([0-9A-Fa-f]{64})\n", stdout)
    return (match is not None and int(match[1]) == seqno
            and match[2].decode().lower() == root
            and match[3].decode().lower() == file
            and match[4].decode().lower() == param30)


def load_quartet(manifest: dict[str, Any]) -> dict[str, Any]:
    """Validate a quartet manifest and read its originals with SHA binding."""
    require(manifest.get("schema") == "tos.z01.config30-quartet.v1", "wrong quartet schema")
    block = manifest.get("block_id")
    require(isinstance(block, dict), "quartet lacks full BlockIdExt")
    require(block.get("workchain") == -1 and block.get("shard") == MASTERCHAIN_SHARD,
            "quartet is not a masterchain block")
    require(type(block.get("seqno")) is int and block["seqno"] > 0, "quartet seqno is invalid")
    for key in ("root_hash", "file_hash"):
        require(isinstance(block.get(key), str) and HEX64.fullmatch(block[key]) is not None
                and int(block[key], 16) != 0, f"quartet {key} is not a nonzero 64-hex digest")
    expected = manifest.get("expected_param30_cell_hash")
    require(isinstance(expected, str) and HEX64.fullmatch(expected) is not None,
            "quartet lacks the precommitted Param30 cell hash")
    files: dict[str, bytes] = {}
    for key in ("block_boc", "state_proof", "config_proof", "param30_boc",
                "wrong_param30_boc", "other_block_state_proof"):
        entry = manifest.get(key)
        require(isinstance(entry, dict) and isinstance(entry.get("path"), str)
                and isinstance(entry.get("sha256"), str), f"quartet lacks {key}")
        raw = Path(entry["path"]).read_bytes()
        require(raw != b"", f"quartet {key} is empty")
        require(sha(raw) == entry["sha256"], f"quartet {key} differs from its recorded SHA-256")
        files[key] = raw
    require(sha(files["block_boc"]) == block["file_hash"],
            "quartet block BOC SHA-256 is not the full-ID file hash")
    require(files["wrong_param30_boc"] != files["param30_boc"],
            "wrong Param30 control is byte-identical to the genuine Param30 BOC")
    require(files["other_block_state_proof"] != files["state_proof"],
            "other-block state proof is byte-identical to the genuine state proof")
    return {"block": block, "expected": expected, "files": files}


def control_inputs(quartet: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build each control as exactly one changed input over the genuine quartet."""
    block = quartet["block"]
    files = quartet["files"]
    genuine = {"root": block["root_hash"], "file": block["file_hash"],
               "block_boc": files["block_boc"], "state_proof": files["state_proof"],
               "config_proof": files["config_proof"], "param30_boc": files["param30_boc"]}
    mutated = mutate_middle_byte(files["block_boc"])
    controls = {
        "positive": {},
        "wrong_root_hash": {"root": flip_hex(block["root_hash"])},
        "wrong_file_hash": {"file": flip_hex(block["file_hash"])},
        "mutated_block_byte": {"block_boc": mutated},
        # The same mutated bytes with a file hash recomputed from them: the file
        # guard now passes, so only the independent root-hash guard can refuse.
        "mutated_block_byte_consistent_file_hash": {"block_boc": mutated, "file": sha(mutated)},
        "wrong_param30_cell": {"param30_boc": files["wrong_param30_boc"]},
        "state_proof_from_other_block": {"state_proof": files["other_block_state_proof"]},
    }
    require(set(controls) == set(EXPECTED), "control matrix and expectations diverge")
    result = {}
    for name, change in controls.items():
        changed = [key for key in change if change[key] != genuine[key]]
        if name == "mutated_block_byte_consistent_file_hash":
            require(sorted(changed) == ["block_boc", "file"], f"{name} must change exactly block bytes and file")
        elif name == "positive":
            require(changed == [], "positive control changed an input")
        else:
            require(len(changed) == 1, f"{name} must change exactly one input")
        result[name] = {**genuine, **change}
    return result


def run_matrix(checker: Path, checker_sha256: str, quartet_manifest: Path,
               manifest_sha256: str, out: Path,
               runner: list[str] | None = None) -> dict[str, Any]:
    """Run all controls; return a verdict and retain every original."""
    manifest_raw = quartet_manifest.read_bytes()
    require(sha(manifest_raw) == manifest_sha256, "quartet manifest differs from its precommitted SHA-256")
    require(sha(checker.read_bytes()) == checker_sha256, "proof checker differs from its precommitted SHA-256")
    quartet = load_quartet(json.loads(manifest_raw))
    out.mkdir(parents=True, exist_ok=False)
    write_once(out / "quartet-manifest.json", manifest_raw)
    block = quartet["block"]
    rows: dict[str, Any] = {}
    failures: list[str] = []
    for name, inputs in control_inputs(quartet).items():
        directory = out / name
        directory.mkdir()
        paths = {}
        for key in ("block_boc", "state_proof", "config_proof", "param30_boc"):
            paths[key] = directory / f"{key}.boc"
            write_once(paths[key], inputs[key])
        argv = [str(checker), "-1", str(MASTERCHAIN_SHARD), str(block["seqno"]),
                inputs["root"], inputs["file"], str(paths["block_boc"]),
                str(paths["state_proof"]), str(paths["config_proof"]), str(paths["param30_boc"])]
        command = (runner or []) + argv
        completed = subprocess.run(command, capture_output=True, check=False)
        write_once(directory / "command.json", (json.dumps(command) + "\n").encode())
        write_once(directory / "exit.raw", f"{completed.returncode}\n".encode())
        write_once(directory / "stdout.raw", completed.stdout)
        write_once(directory / "stderr.raw", completed.stderr)
        expected = EXPECTED[name]
        if expected is None:
            passed = (completed.returncode == 0 and completed.stderr == b""
                      and positive_output_matches(completed.stdout, block["seqno"], block["root_hash"],
                                                  block["file_hash"], quartet["expected"]))
        else:
            passed = (completed.returncode == 1 and completed.stdout == b""
                      and completed.stderr == REJECT_PREFIX + expected + b"\n")
        if not passed:
            failures.append(name)
        rows[name] = {"exit": completed.returncode, "passed": passed,
                      "expected_stderr": None if expected is None else expected.decode(),
                      "stdout_sha256": sha(completed.stdout), "stderr_sha256": sha(completed.stderr),
                      "inputs_sha256": {key: sha(inputs[key]) for key in paths},
                      "root": inputs["root"], "file": inputs["file"]}
    verdict = {"schema": "tos.z01.config30-proof-controls.v1", "passed": not failures,
               "failures": failures, "checker_sha256": checker_sha256,
               "quartet_manifest_sha256": manifest_sha256, "block_id": block,
               "expected_param30_cell_hash": quartet["expected"], "controls": rows}
    write_once(out / "verdict.json", (json.dumps(verdict, sort_keys=True, indent=2) + "\n").encode())
    return verdict


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checker", type=Path, required=True)
    parser.add_argument("--checker-sha256", required=True)
    parser.add_argument("--quartet", type=Path, required=True)
    parser.add_argument("--quartet-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--runner-json", default="[]",
                        help="optional JSON argv prefix, e.g. a docker run wrapper")
    args = parser.parse_args()
    runner = json.loads(args.runner_json)
    require(isinstance(runner, list) and all(isinstance(part, str) for part in runner),
            "runner prefix must be a JSON string list")
    try:
        verdict = run_matrix(args.checker, args.checker_sha256, args.quartet, args.quartet_sha256,
                             args.output_dir, runner)
    except ControlError as exc:
        print(f"Z01_PROOF_CONTROLS_REFUSED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"passed": verdict["passed"], "failures": verdict["failures"]}, sort_keys=True))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
