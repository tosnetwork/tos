#!/usr/bin/env python3
"""Run real Rust guard removals in a new disposable checkout; never alter a live source."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run(command, cwd, env):
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, timeout=1800)
    output = result.stdout + result.stderr
    if len(output) > 4 * 1024 * 1024:
        raise RuntimeError("mutation output byte bound")
    return result.returncode, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    args = parser.parse_args()
    if not args.scratch.is_absolute() or args.scratch.exists():
        parser.error("scratch must be a new absolute worktree")
    if (
        not args.out.is_absolute()
        or args.out.exists()
        or args.out.is_relative_to(ROOT)
        or args.out.is_relative_to(args.scratch)
    ):
        parser.error("out must be a new external artifact directory")
    if not args.target_dir.is_absolute():
        parser.error("absolute build-cache path required")
    os.umask(0o077)
    args.out.mkdir()
    receipt = json.loads((Path(__file__).with_name("registration-controls.json")).read_bytes())
    core = receipt["core_commit"]
    if len(core) != 40 or any(c not in "0123456789abcdef" for c in core):
        raise RuntimeError("invalid frozen core")
    subprocess.run(
        ["git", "worktree", "add", "--detach", str(args.scratch), core], cwd=ROOT, check=True
    )
    env = {
        **os.environ,
        "CARGO_TARGET_DIR": str(args.target_dir),
        "CARGO_BUILD_JOBS": "2",
        "RAYON_NUM_THREADS": "2",
        "TOKIO_WORKER_THREADS": "2",
    }
    command = [
        "cargo",
        "+1.97.1",
        "test",
        "--manifest-path",
        "tosctl/src/Cargo.toml",
        "-p",
        "elections",
        "--release",
        "--locked",
    ]
    rows = []
    try:
        for case in receipt["mutations"]:
            path = args.scratch / case["file"]
            original = path.read_text()
            if original.count(case["replace_from"]) != case["expected_count"]:
                raise RuntimeError("mutation anchor drift: " + case["name"])
            try:
                path.write_text(original.replace(case["replace_from"], case["replace_to"]))
                code, output = run(
                    command + ["--", case["test"], "--exact", "--nocapture"], args.scratch, env
                )
                (args.out / (case["name"] + ".log")).write_bytes(output)
                markers = [
                    b"running 1 test",
                    ("test " + case["test"] + " ... FAILED").encode(),
                    b"test result: FAILED",
                ]
                red = code == 101 and all(marker in output for marker in markers)
                if not red:
                    raise RuntimeError("not the intended test-body failure: " + case["name"])
                rows.append(
                    dict(
                        name=case["name"],
                        test=case["test"],
                        returncode=code,
                        red=True,
                        sha256=hashlib.sha256(output).hexdigest(),
                    )
                )
                print("RED", case["name"], flush=True)
            finally:
                path.write_text(original)
        code, output = run(command + ["--", "--test-threads=2"], args.scratch, env)
        (args.out / "restored.log").write_bytes(output)
        if code != 0 or b"66 passed; 0 failed" not in output:
            raise RuntimeError("restored suite did not pass all66 tests")
        report = dict(
            core_commit=core,
            mutations=rows,
            restored_exit=code,
            restored_sha256=hashlib.sha256(output).hexdigest(),
        )
        (args.out / "REPORT.json").write_text(json.dumps(report, indent=2) + "\n")
        print("RESTORED66GREEN", flush=True)
    finally:
        subprocess.run(["git", "worktree", "remove", str(args.scratch)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
