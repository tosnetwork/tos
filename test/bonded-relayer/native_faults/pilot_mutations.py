#!/usr/bin/env python3
"""Reproduce refusal-guard failures in a NEW disposable detached worktree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RECEIPT = ROOT / "test/bonded-relayer/evidence/testnet-pilot-guards-20261101.json"


def run(command, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=1800)
    output = result.stdout + result.stderr
    if len(output) > 4 * 1024 * 1024:
        raise RuntimeError("bounded mutation output exceeded")
    return result.returncode, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.scratch.is_absolute() or args.scratch.exists():
        parser.error("scratch must be a new absolute path; never pass an existing/live checkout")
    if not args.out.is_absolute() or args.out.exists():
        parser.error("out must be a new private absolute directory outside the checkout")
    if args.out.is_relative_to(ROOT) or args.out.is_relative_to(args.scratch):
        parser.error("raw output belongs outside source checkouts")
    if not args.target_dir.is_absolute():
        parser.error("target-dir must be an absolute build-cache path")
    os.umask(0o077)
    args.out.mkdir(mode=0o700)
    receipt = json.loads(RECEIPT.read_bytes())
    env = {
        **os.environ,
        "CARGO_TARGET_DIR": str(args.target_dir),
        "RAYON_NUM_THREADS": "2",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    core = receipt["core_commit"]
    if len(core) != 40 or any(character not in "0123456789abcdef" for character in core):
        raise RuntimeError("invalid frozen core commit")
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(args.scratch), core], cwd=ROOT, check=True
    )
    results = []
    try:
        for case in receipt["mutations"]:
            path = args.scratch / case["file"]
            original = path.read_text()
            if original.count(case["replace_from"]) != 1:
                raise RuntimeError("mutation anchor drift: " + case["guard"])
            try:
                path.write_text(original.replace(case["replace_from"], case["replace_to"], 1))
                code, output = run(case["command"], args.scratch, env)
                (args.out / (case["guard"] + ".log")).write_bytes(output)
                if code == 0 or case["expected_failure_marker"].encode() not in output:
                    raise RuntimeError("mutation did not fail at runtime: " + case["guard"])
                results.append({"guard": case["guard"], "exit_code": code, "result": "RED"})
                print(case["guard"], "RED", flush=True)
            finally:
                path.write_text(original)
        for number, command in enumerate(receipt["restored_commands"]):
            code, output = run(command, args.scratch, env)
            (args.out / f"restored-{number}.log").write_bytes(output)
            marker = b"27 passed; 0 failed" if number < 2 else b"\nOK\n"
            if code != 0 or marker not in output:
                raise RuntimeError("restored complete guard inventory failed")
        (args.out / "VERDICT.json").write_text(
            json.dumps(
                {
                    "result": "PASS",
                    "receipt_sha256": hashlib.sha256(RECEIPT.read_bytes()).hexdigest(),
                    "mutations": results,
                    "restored_native_default_and_pilot": 27,
                },
                indent=2,
            )
            + "\n"
        )
    finally:
        # Only remove the worktree created above; never force-remove dirty work.
        subprocess.run(["git", "worktree", "remove", str(args.scratch)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
