#!/usr/bin/env python3
"""Compile each changed protection and require its named behavior test to fail."""
import os
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = [
    ("source-single-flight", "source.rs", "if self.active.is_some() {", "if false {", "timeout_does_not_release_actual_work"),
    ("source-refresh-interval", "source.rs", "if now < self.next_due {", "if false {", "scheduler_skips_missed_ticks"),
    ("source-token-ownership", "source.rs", "if token != id {", "if false {", "timeout_does_not_release_actual_work"),
    ("source-availability", "source.rs", "|| self.availability != Availability::Available", "|| false", "absence_never_becomes_zero"),
    ("cohort-completeness", "duty.rs", "if !self.complete || start >= end {", "if start >= end {", "duties_do_not_hide_pending_or_incomplete_population"),
    ("model-single-flight", "broker.rs", "if self.active.is_some() {", "if false {", "cancellation_keeps_model_resource_exclusive"),
    ("heartbeat-replay", "observer.rs", "|| self.last_sequence.is_some_and(|s| sequence <= s)", "|| false", "repeated_deadman_does_not_keep_monitor_alive"),
    ("run-call-budget", "query.rs", "if grant.calls >= 16 {", "if false {", "failed_calls_consume_budget"),
    ("run-token-auth", "query.rs", "|| difference != 0", "|| false", "query_authentication_and_run_are_independent"),
    ("missing-source-recovery", "incident.rs", "self.severity = Severity::Unknown;", "self.severity = Severity::Unknown; self.active = false;", "missing_source_does_not_recover_incident"),
]

def run(cargo, name):
    return subprocess.run([cargo, "test", "--manifest-path", str(ROOT / "Cargo.toml"), "-p", "tos-health-core", "--test", "contracts", name, "--", "--exact"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,env={**os.environ,"CARGO_INCREMENTAL":"0"})

def main():
    cargo = sys.argv[1] if len(sys.argv) > 1 else "cargo"
    results = []
    for label, filename, original, replacement, name in CASES:
        baseline = run(cargo, name)
        if baseline.returncode != 0 or "1 passed; 0 failed" not in baseline.stdout:
            raise RuntimeError(f"{label}: named baseline did not pass\n{baseline.stdout}")
        path = ROOT / "crates/health-core/src" / filename
        content = path.read_text()
        if content.count(original) != 1:
            raise RuntimeError(f"{label}: expected exactly one mutation anchor")
        try:
            path.write_text(content.replace(original, replacement))
            mutant = run(cargo, name)
        finally:
            path.write_text(content)
        if mutant.returncode == 0 or "0 passed; 1 failed" not in mutant.stdout or f"test {name} ... FAILED" not in mutant.stdout:
            raise RuntimeError(f"{label}: mutation did not reach and fail its case\n{mutant.stdout}")
        results.append({"mutation": label, "test": name, "baseline": "passed", "mutant": "compiled_and_failed"})
        print(label + ": compiled mutant rejected", flush=True)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
