#!/usr/bin/env python3
"""Kill C01 publisher mutants with compiled assertion failures and raw logs."""
import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser()
parser.add_argument("build")
parser.add_argument("evidence")
parser.add_argument("--cmake", default="cmake")
parser.add_argument("--case", action="append", dest="selected")
parser.add_argument("--jobs", type=int, default=2)
parser.add_argument("--build-timeout", type=int, default=180)
args = parser.parse_args()
if not 1 <= args.jobs <= 64 or args.build_timeout <= 0:
    parser.error("--jobs must be 1..64 and --build-timeout must be positive")
build_dir = Path(args.build).resolve()
evidence = Path(args.evidence).resolve()
evidence.mkdir(parents=True, exist_ok=True)

NATIVE = "test-health-native-snapshot"
CASES = [
    ("frozen-body", "metrics/prometheus-exporter.cpp",
     'respond(std::move(promise), 200, "OK", snapshot_);',
     'respond(std::move(promise), 200, "OK", snapshot_ + "# mutant\\n");', NATIVE, "fast"),
    ("body-limit", "metrics/source-admission.h",
     "static constexpr std::size_t max_snapshot_bytes = 2 * 1024 * 1024;",
     "static constexpr std::size_t max_snapshot_bytes = 2 * 1024 * 1024 + 1;", "test-health-source-policy", None),
    ("source-gate", "metrics/metrics-collectors.cpp",
     "const bool publish_source_metadata = health::enabled.load(std::memory_order_relaxed);",
     "const bool publish_source_metadata = true;", "test-health-collector-timestamps", None),
    ("source-family-merge", "metrics/metrics-collectors.cpp",
     "family.metrics.push_back(std::move(scalar.metrics.front()));",
     "if (family.metrics.empty()) family.metrics.push_back(std::move(scalar.metrics.front()));", NATIVE, "sources"),
    ("callback-completion-time", "metrics/metrics-collectors.cpp",
     ".callback_completed_at = publish_source_metadata ? td::Timestamp::now().at_unix() : 0,",
     ".callback_completed_at = publish_source_metadata ? 1.0 : 0.0,", "test-health-collector-timestamps", None),
    ("bounded-counter-update", "metrics/core-registry.h",
     "static constexpr std::size_t max_update_attempts = 8;",
     "static constexpr std::size_t max_update_attempts = 0;", "test-health-core-registry", None),
    ("gauge-owner-clear", "metrics/core-registry.h",
     "slot->value.store(0, std::memory_order_relaxed);\n      slot->owner_active.store(false, std::memory_order_release);",
     "slot->value.store(slot->value.load(std::memory_order_relaxed), std::memory_order_relaxed);\n      slot->owner_active.store(false, std::memory_order_release);",
     "test-health-core-registry", None),
    ("per-path-construction-gate", "quic/health-metrics-policy.h",
     "inline constexpr bool build_per_path = false;", "inline constexpr bool build_per_path = true;",
     "test-health-source-policy", None),
    ("lease-inflight", "metrics/source-admission.h",
     "!std::isfinite(now) || inflight_ || now < next_start_",
     "!std::isfinite(now) || now < next_start_", "test-health-source-policy", None),
]

def record(name, phase, command, result):
    text = "$ " + " ".join(map(str, command)) + "\n" + result.stdout
    text += f"\nEXIT={result.returncode}\n"
    (evidence / f"{name}-{phase}.log").write_text(text)

def execute(name, phase, command, timeout):
    try:
        result = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        def normalized(value):
            if value is None:
                return ""
            return value.decode(errors="replace") if isinstance(value, bytes) else value
        output = normalized(exc.stdout) + normalized(exc.stderr)
        result = subprocess.CompletedProcess(command, 124, output + "\nTIMEOUT\n")
    record(name, phase, command, result)
    return result

def build(name, target, phase):
    command = [args.cmake, "--build", str(build_dir), "--target", target, f"-j{args.jobs}"]
    result = execute(name, phase, command, args.build_timeout)
    if result.returncode:
        raise RuntimeError(f"{name}: {phase} compile failed; compile failures do not kill mutants")

def run(name, target, mode, phase):
    binary = build_dir / target
    command = ([str(binary)] if mode is None else
               [sys.executable, str(ROOT / "tools/node-health-monitor/tests/native-snapshot-http.py"),
                str(binary), "--mode", mode])
    return execute(name, phase, command, 90)

for name, relative, old, new, target, mode in CASES:
    if args.selected and name not in args.selected:
        continue
    path = ROOT / relative
    original = path.read_text()
    if original.count(old) != 1:
        raise RuntimeError(f"{name}: mutation target count is {original.count(old)}, expected one")
    build(name, target, "baseline-build")
    baseline = run(name, target, mode, "baseline-run")
    if baseline.returncode:
        raise RuntimeError(f"{name}: baseline failed")
    try:
        path.write_text(original.replace(old, new))
        build(name, target, "mutant-build")
        mutant = run(name, target, mode, "mutant-run")
        if mutant.returncode == 0 or not any(marker in mutant.stdout for marker in ("Check", "AssertionError")):
            raise RuntimeError(f"{name}: compiled mutant did not die by assertion")
        print(f"{name}: compiled mutant killed", flush=True)
    finally:
        path.write_text(original)

for target in sorted({case[4] for case in CASES if not args.selected or case[0] in args.selected}):
    build("restored", target, "final-build")
print("C01 mutation sources restored", flush=True)
