#!/usr/bin/env python3
"""Kill changed C02 edge invariants; compile failures never count as kills."""
import argparse
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ENV = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_BUILD_PIPELINING="false")
CASES = [
    ("cgroup-root-unconstrained", "crates/health-services/src/edge.rs",
     "for level in levels.into_iter().skip(1) {", "for level in levels.into_iter().skip(0) {",
     "tos-health-services", "cgroup", "effective_quota_uses_tightest_ancestor_and_keeps_pressure_sample"),
    ("cgroup-pressure-truth", "crates/health-services/src/edge.rs",
     "memory_current_bytes: U64(memory_current),", "memory_current_bytes: U64(memory_current.min(memory_max)),",
     "tos-health-services", "cgroup", "effective_quota_uses_tightest_ancestor_and_keeps_pressure_sample"),
    ("mixed-process-epoch", "crates/health-core/src/edge_snapshot.rs",
     "if process_epoch.is_some_and(|expected| expected != epoch) {", "if false && process_epoch.is_some_and(|expected| expected != epoch) {",
     "tos-health-core", "native_contract", "edge_wire_requires_bound_process_native_and_cgroup_epochs"),
    ("router-heartbeat-reserve", "crates/health-services/src/edge.rs",
     "if self.tokens <= u32::from(!heartbeat) {", "if self.tokens == 0 {",
     "tos-health-services", "http", "edge_router_reserves_burst_token_for_approved_heartbeat"),
    ("classified-connection-lifetime", "crates/health-services/src/ingress.rs",
     "*slot = Some(permit);", "drop(permit);",
     "tos-health-services", "ingress", "seven_slow_regular_requests_leave_classified_heartbeat_capacity"),
    ("missed-tick-skip", "crates/health-services/src/native_cache.rs",
     "completed + NATIVE_INTERVAL", "next_due",
     "tos-health-services", "native_typed", "scheduler_skips_a_tick_missed_by_a_slow_source"),
]

parser = argparse.ArgumentParser()
parser.add_argument("--log-dir", type=Path, default=ROOT / "evidence/c02-edge/mutation-logs")
parser.add_argument("--timeout", type=int, default=90)
parser.add_argument("--case", action="append", dest="selected")
args = parser.parse_args()
if args.timeout <= 0:
    parser.error("--timeout must be positive")
args.log_dir.mkdir(parents=True, exist_ok=True)

def run(label, phase, package, target, test):
    command = ["cargo", "test", "--locked", "-p", package, "--test", target, test, "--", "--exact"]
    try:
        result = subprocess.run(command, cwd=ROOT, env=ENV, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=args.timeout)
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        result = subprocess.CompletedProcess(command, 124, output + "\nTIMEOUT\n")
    (args.log_dir / f"{label}.{phase}.log").write_text(
        f"$ {' '.join(command)}\ntimeout_seconds={args.timeout}\n{result.stdout}\nEXIT={result.returncode}\n"
    )
    return result

for label, relative, old, new, package, target, test in CASES:
    if args.selected and label not in args.selected:
        continue
    path = ROOT / relative
    original = path.read_text()
    if original.count(old) != 1:
        raise RuntimeError(f"{label}: expected one target, found {original.count(old)}")
    baseline = run(label, "baseline", package, target, test)
    if baseline.returncode or "1 passed; 0 failed" not in baseline.stdout:
        raise RuntimeError(f"{label}: baseline failed; see raw log")
    try:
        path.write_text(original.replace(old, new, 1))
        mutant = run(label, "mutant", package, target, test)
        if (mutant.returncode == 0 or f"test {test} ... FAILED" not in mutant.stdout
                or "0 passed; 1 failed" not in mutant.stdout):
            raise RuntimeError(f"{label}: no compiled assertion failure; see raw log")
        print(f"{label}: compiled mutant killed", flush=True)
    finally:
        path.write_text(original)

print("C02 mutation sources restored", flush=True)
