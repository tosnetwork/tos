#!/usr/bin/env python3
"""Prove the two process-only M scan filters with compiled assertion failures.

Run only in a disposable, clean checkout. Every source edit is restored in
finally; raw baseline/mutant/restored logs and a hash receipt are retained.
"""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "crates/health-services/src/manager_query_source.rs"
TEST = "unsupported_diagnostic_population_does_not_consume_process_scan_or_quarantine_cap"
CASES = (
    (
        "observation-source-filter",
        "FROM observations WHERE store_seq<=?1 AND source='process'",
        "FROM observations WHERE store_seq<=?1",
        "M projection scan bound exceeded",
    ),
    (
        "quarantine-source-filter",
        "WHERE o.store_seq<=?1 AND o.source='process'",
        "WHERE o.store_seq<=?1",
        "M quarantine scan bound exceeded",
    ),
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(label: str, phase: str, source_sha: str, log_dir: Path, target_dir: Path, timeout: int):
    cmd = [
        "cargo",
        "test",
        "-p",
        "tos-health-services",
        "--test",
        "manager_query_source",
        "--locked",
        "-j2",
        TEST,
        "--",
        "--exact",
        "--nocapture",
    ]
    env = dict(os.environ, CARGO_TARGET_DIR=str(target_dir), CARGO_INCREMENTAL="0")
    try:
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        output, code = result.stdout, result.returncode
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"") + b"\nTIMEOUT\n"
        code = 124
    raw = (
        (f"$ {' '.join(cmd)}\nsource_sha256={source_sha}\ntimeout_seconds={timeout}\n").encode()
        + output
        + f"\nEXIT={code}\n".encode()
    )
    path = log_dir / f"{label}.{phase}.log"
    path.write_bytes(raw)
    return code, output.decode(errors="replace"), {"path": str(path), "sha256": sha(raw)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    if args.timeout < 1:
        parser.error("timeout must be positive")
    if subprocess.run(["git", "diff", "--quiet", "--", str(SOURCE)], cwd=ROOT).returncode:
        parser.error("source is dirty")
    args.log_dir.mkdir(parents=True, exist_ok=True)
    original = SOURCE.read_bytes()
    before = sha(original)
    base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    receipt = {
        "base_head": base,
        "source_path": str(SOURCE.relative_to(ROOT)),
        "restored_sha256": before,
        "test": TEST,
        "cases": [],
    }
    try:
        for label, old, new, intended_error in CASES:
            old_bytes, new_bytes = old.encode(), new.encode()
            if original.count(old_bytes) != 1:
                raise RuntimeError(f"{label}: target not unique")
            baseline_code, baseline_text, baseline_log = run(
                label, "baseline", before, args.log_dir, args.target_dir, args.timeout
            )
            if baseline_code != 0 or "1 passed; 0 failed" not in baseline_text:
                raise RuntimeError(f"{label}: baseline failed")
            mutant = original.replace(old_bytes, new_bytes, 1)
            SOURCE.write_bytes(mutant)
            try:
                mutant_code, mutant_text, mutant_log = run(
                    label, "mutant", sha(mutant), args.log_dir, args.target_dir, args.timeout
                )
                if (
                    mutant_code != 101
                    or intended_error not in mutant_text
                    or "0 passed; 1 failed" not in mutant_text
                ):
                    raise RuntimeError(f"{label}: no intended compiled assertion failure")
            finally:
                SOURCE.write_bytes(original)
            restored_code, restored_text, restored_log = run(
                label, "restored", before, args.log_dir, args.target_dir, args.timeout
            )
            if restored_code != 0 or "1 passed; 0 failed" not in restored_text:
                raise RuntimeError(f"{label}: restored control failed")
            receipt["cases"].append(
                {
                    "label": label,
                    "replacement_old": old,
                    "replacement_new": new,
                    "patch_sha256": sha(old_bytes + b"\0" + new_bytes),
                    "mutant_source_sha256": sha(mutant),
                    "baseline_exit": baseline_code,
                    "mutant_exit": mutant_code,
                    "restored_exit": restored_code,
                    "intended_error": intended_error,
                    "baseline_log": baseline_log,
                    "mutant_log": mutant_log,
                    "restored_log": restored_log,
                }
            )
    finally:
        SOURCE.write_bytes(original)
        if sha(SOURCE.read_bytes()) != before:
            raise RuntimeError("source restoration failed")
    path = args.log_dir / "receipt.json"
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"receipt": str(path), "receipt_sha256": sha(path.read_bytes())}))


if __name__ == "__main__":
    main()
