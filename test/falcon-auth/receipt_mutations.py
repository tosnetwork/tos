#!/usr/bin/env python3
"""Compile receipt guard bypasses and require targeted assertions, then restore."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    source = ROOT / "tools/falcon/receipts.py"
    original = source.read_text()
    wallet = [
        sys.executable,
        str(ROOT / "test/falcon-auth/test_wallet.py"),
        "--library",
        str(args.library.resolve()),
        "--artifacts",
        str(args.artifacts.resolve()),
    ]
    native = [
        sys.executable,
        str(ROOT / "test/falcon-auth/receipt_e2e.py"),
        "--build",
        str(args.build.resolve()),
        "--library",
        str(args.library.resolve()),
    ]
    patterns = [
        (
            "legacy-completion",
            'return cls(identity, "target outcome incomplete", consumed, "not observed")',
            'return cls(identity, "actions completed", consumed, "not observed")',
            wallet,
            "test_multihop_receipts_require_final_state",
        ),
        (
            "skipped-completion",
            "            if action.skipped_actions:",
            '            if action.skipped_actions:\n                return receipt("actions completed")',
            native + ["--case", "ignored", "--out", str((args.out / "ignored").resolve())],
            "target actions skipped",
        ),
        (
            "unconfirmed-delivery",
            "            if delivered != expected_count:",
            "            if False:",
            native + ["--case", "normal", "--out", str((args.out / "normal").resolve())],
            "actions emitted; delivery pending",
        ),
    ]
    config = re.findall(
        r"            if \(\n                new.auth is None[\s\S]*?\n            \):", original
    )
    if len(config) != 1:
        raise ValueError("missing or ambiguous configuration result guard")
    patterns.append(
        (
            "configuration-result",
            config[0],
            "            if False:",
            native + ["--case", "configure", "--out", str((args.out / "configure").resolve())],
            "configuration result guard",
        )
    )
    reports = []
    for name, guard, bypass, command, assertion in patterns:
        if original.count(guard) != 1:
            raise ValueError("missing or ambiguous receipt mutation target: " + name)
        baseline = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if baseline.returncode:
            raise RuntimeError(
                "receipt positive baseline failed: " + name + baseline.stderr[-3000:]
            )
        mutated = original.replace(guard, bypass)
        compile(mutated, str(source), "exec")
        try:
            source.write_text(mutated)
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            killed = (
                result.returncode == 1
                and "AssertionError" in result.stderr
                and assertion in result.stderr
            )
            if not killed:
                raise RuntimeError(
                    "receipt bypass did not reach its targeted assertion: "
                    + name
                    + result.stderr[-3000:]
                )
            reports.append(
                dict(
                    guard=name,
                    compiled=True,
                    killed=True,
                    exit_code=result.returncode,
                    assertion=assertion,
                    restored_baseline_passed=True,
                )
            )
            (args.out / (name + ".log")).write_text(result.stderr[-3000:])
        finally:
            source.write_text(original)
        restored = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if restored.returncode:
            raise RuntimeError(
                "restored receipt baseline failed: " + name + restored.stderr[-3000:]
            )
    report = dict(success=True, controls=reports, scope="compiled client receipt guard sensitivity")
    (args.out / "receipt-mutations.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(dict(success=True, compiled=len(reports), killed=len(reports))))


if __name__ == "__main__":
    main()
