#!/usr/bin/env python3
"""Changed C03 properties: baseline green and compiled assertion-red only."""

import argparse
import hashlib
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = [
    (
        "replay-cannot-renew",
        "crates/health-core/src/observer.rs",
        "if self.sequence.is_some_and(|s| sequence <= s) {",
        "if self.sequence.is_some_and(|s| sequence < s) {",
        "watchdog",
        "pipeline_requires_own_firing_new_evaluation",
    ),
    (
        "outbox-full-rolls-back-round",
        "crates/health-services/src/durable.rs",
        "if n >= self.max_outbox {",
        "if false && n >= self.max_outbox {",
        "durable",
        "outbox_capacity_failure_cannot_advance_recovery_or_sequence",
    ),
    (
        "duplicate-keeps-original-time",
        "crates/health-services/src/durable.rs",
        "canonical.record.received_at_ms = 0;",
        "canonical.record.received_at_ms = value.record.received_at_ms;",
        "durable",
        "immutable_sequence_survives_restart_and_late_arrival",
    ),
    (
        "retry-due-is-persisted",
        "crates/health-services/src/durable.rs",
        "1 => 15_000,",
        "1 => 0,",
        "durable",
        "legacy_pending_outbox_migrates_without_ack_and_retry_metadata_is_durable",
    ),
    (
        "wrong-receipt-retains-outbox",
        "crates/health-services/src/manager.rs",
        "if !receipt.accepted || receipt.idempotency_key != key || receipt.payload_hash != hash {",
        "if false && (!receipt.accepted || receipt.idempotency_key != key || receipt.payload_hash != hash) {",
        "manager",
        "conflict_quarantines_live_rule_and_receipt_controls_outbox",
    ),
]

parser = argparse.ArgumentParser()
parser.add_argument(
    "--log-dir", type=Path, default=ROOT / "evidence/c03-state-rules-notification/raw/mutations"
)
parser.add_argument("--timeout", type=int, default=180)
parser.add_argument("--case", action="append", dest="selected")
args = parser.parse_args()
if args.timeout <= 0:
    parser.error("--timeout must be positive")
args.log_dir.mkdir(parents=True, exist_ok=True)
env = dict(
    os.environ,
    CARGO_BUILD_JOBS="2",
    CARGO_TARGET_DIR=str(Path.home() / "nhm-c03-build"),
    CARGO_INCREMENTAL="0",
    CARGO_BUILD_PIPELINING="false",
)


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def run(label, phase, target, test, source_sha):
    cmd = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "tos-health-services",
        "--test",
        target,
        test,
        "--",
        "--exact",
    ]
    try:
        result = subprocess.run(
            cmd,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=args.timeout,
        )
        output = result.stdout
        code = result.returncode
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        output += "\nTIMEOUT\n"
        code = 124
    (args.log_dir / f"{label}.{phase}.log").write_text(
        f"$ {' '.join(cmd)}\nsource_sha256={source_sha}\ntimeout_seconds={args.timeout}\n{output}\nEXIT={code}\n"
    )
    return code, output


for label, relative, old, new, target, test in CASES:
    if args.selected and label not in args.selected:
        continue
    path = ROOT / relative
    original = path.read_text()
    if original.count(old) != 1:
        raise RuntimeError(f"{label}: expected one target, found {original.count(old)}")
    before = digest(original)
    code, output = run(label, "baseline", target, test, before)
    if code or "1 passed; 0 failed" not in output:
        raise RuntimeError(f"{label}: baseline failed")
    try:
        changed = original.replace(old, new, 1)
        path.write_text(changed)
        code, output = run(label, "mutant", target, test, digest(changed))
        if (
            code == 0
            or f"test {test} ... FAILED" not in output
            or "0 passed; 1 failed" not in output
        ):
            raise RuntimeError(f"{label}: no compiled assertion red")
        print(f"{label}: compiled assertion red", flush=True)
    finally:
        path.write_text(original)
        if digest(path.read_text()) != before:
            raise RuntimeError(f"{label}: source not restored")

print("C03 mutation sources restored", flush=True)
