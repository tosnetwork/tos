#!/usr/bin/env python3
"""Target changed C00 runtime contracts; compile failure never kills a mutant."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_BUILD_PIPELINING="false")
TIMEOUT_SECONDS = 120
CASES = [
    (
        "derived-lineage",
        "health-core/src/query_output.rs",
        'if kind == "derived" {',
        "if false {",
        "runtime_output_reflects_unknown_quality_and_rejects_conflicts",
    ),
    (
        "metric-metadata",
        "health-core/src/query_output.rs",
        'record.record.payload.get("metric") != Some(&metric_meta)',
        "false",
        "runtime_output_reflects_unknown_quality_and_rejects_conflicts",
    ),
    (
        "coverage-gap-union",
        "health-core/src/query_output.rs",
        "merge_unique_bounded(&mut known.gaps, item_coverage.gaps, 32)?;",
        "known.gaps = item_coverage.gaps;",
        "runtime_output_reflects_unknown_quality_and_rejects_conflicts",
    ),
    (
        "payload-unknown-field",
        '#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]',
        '#[serde(tag = "kind", rename_all = "snake_case")]',
        "runtime_output_reflects_unknown_quality_and_rejects_conflicts",
    ),
    (
        "payload-content-hash",
        "health-core/src/query_output.rs",
        'Sha256::digest(serde_json::to_vec(payload_value).map_err(|_| "SCHEMA_MISMATCH")?)',
        'Sha256::digest(b"mutated")',
        "all_six_success_handlers_emit_runtime_dtos",
    ),
    (
        "network-genesis-shape",
        "health-services/src/lib.rs",
        "if self.network_id.len() != 64",
        "if false",
        "inventory_and_secret_domains_are_enforced",
    ),
]


def run(test: str, log_path: Path):
    command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "tos-health-services",
        "--test",
        "http",
        test,
        "--",
        "--exact",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=ENV,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        log_path.write_text(
            f"command: {' '.join(command)}\ntimeout_seconds: {TIMEOUT_SECONDS}\n"
        f"result: TIMEOUT\n\n{output.rstrip()}\n"
        )
        raise RuntimeError(f"{test}: timed out after {TIMEOUT_SECONDS}s; see {log_path}") from error
    log_path.write_text(
        f"command: {' '.join(command)}\ntimeout_seconds: {TIMEOUT_SECONDS}\n"
        f"exit_code: {result.returncode}\n\n{result.stdout.rstrip()}\n"
    )
    return result


parser = argparse.ArgumentParser()
parser.add_argument(
    "--log-dir",
    type=Path,
    default=ROOT / "evidence" / "c00-closure" / "mutation-logs",
)
args = parser.parse_args()
args.log_dir.mkdir(parents=True, exist_ok=True)

for case in CASES:
    label = case[0]
    if label == "payload-unknown-field":
        file = "health-core/src/query_output.rs"
        old, new, test = case[1:]
    else:
        file, old, new, test = case[1:]
    path = ROOT / "crates" / file
    original = path.read_text()
    baseline = run(test, args.log_dir / f"{label}.baseline.log")
    if baseline.returncode or "1 passed; 0 failed" not in baseline.stdout:
        raise RuntimeError(f"{label} baseline failed\n{baseline.stdout}")
    if original.count(old) != 1:
        raise RuntimeError(f"{label}: target count {original.count(old)}")
    try:
        path.write_text(original.replace(old, new, 1))
        mutant = run(test, args.log_dir / f"{label}.mutant.log")
        if (
            mutant.returncode == 0
            or f"test {test} ... FAILED" not in mutant.stdout
            or "0 passed; 1 failed" not in mutant.stdout
        ):
            raise RuntimeError(f"{label}: no compiled assertion failure\n{mutant.stdout}")
        print(f"{label}: compiled mutant killed", flush=True)
    finally:
        path.write_text(original)

print("all C00 closure mutation sources restored")
