"""Measure live c4 and the committed c4 of the built configuration contract."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SANITIZER_ENV = {
    "ASAN_OPTIONS": "detect_leaks=1:detect_stack_use_after_return=1",
    "UBSAN_OPTIONS": "halt_on_error=1",
}


def execute(command: list[str], log: Path, sanitized: bool = False) -> dict:
    env = dict(os.environ)
    if sanitized:
        env.update(SANITIZER_ENV)
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, check=False)
    record = {"command": command, "exit_code": result.returncode,
              "stdout": result.stdout, "stderr": result.stderr}
    log.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record), flush=True)
    return record


def compile_contract(build: Path, source: Path, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    fif = out / "config-code.fif"
    boc = out / "config-code.boc"
    result = execute([str(build / "crypto/func"), "-PS", "-o", str(fif),
                      str(ROOT / "crypto/smartcont/stdlib.fc"), str(source)], out / "compile.json")
    if result["exit_code"] != 0:
        raise RuntimeError("contract compilation failed; no mutation qualification")
    assembler = out / "assemble.fif"
    assembler.write_text(f'"Asm.fif" include\n"{fif}" include\n2 boc+>B "{boc}" B>file\n')
    result = execute([str(build / "crypto/fift"), "-I", str(ROOT / "crypto/fift/lib"),
                      "-s", str(assembler)], out / "assemble.json")
    if result["exit_code"] != 0 or not boc.is_file() or not boc.stat().st_size:
        raise RuntimeError("contract assembly failed; no mutation qualification")
    return boc


def run_cases(binary: Path, boc: Path, cases: list[str], out: Path, sanitized: bool = False) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    return {case: execute([str(binary), str(boc), case], out / f"{case}.json", sanitized)
            for case in cases}


def passed(record: dict, case: str) -> bool:
    return (record["exit_code"] == 0 and record["stderr"] == "" and
            f"CASE_PASS {case}" in record["stdout"].splitlines() and
            record["stdout"].splitlines()[-1:] == ["SUMMARY cases=1 passed=1"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=Path("build-p0"))
    parser.add_argument("--sanitized-build", type=Path, default=Path("build-p0-sanitized"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build, san_build = args.build.resolve(), args.sanitized_build.resolve()
    binary = build / "test/validator-auth-implementation/test-p0-config-contract"
    sanitized_binary = san_build / "test/validator-auth-implementation/test-p0-config-contract"
    source = ROOT / "crypto/smartcont/config-code.fc"
    original = source.read_bytes()
    report = {"source_sha256": hashlib.sha256(original).hexdigest(),
              "phase": "compute measurement, not action-phase evidence"}
    boc = compile_contract(build, source, out / "baseline-contract")
    report["artifact_sha256"] = hashlib.sha256(boc.read_bytes()).hexdigest()
    listed = execute([str(binary), str(boc), "--list"], out / "list.json")
    if listed["exit_code"] != 0 or listed["stderr"]:
        raise RuntimeError("case inventory failed")
    cases = listed["stdout"].splitlines()
    if not cases or len(set(cases)) != len(cases):
        raise RuntimeError("case inventory is empty or duplicated")
    report["cases"] = cases
    report["normal"] = run_cases(binary, boc, cases, out / "normal")
    report["sanitized"] = run_cases(sanitized_binary, boc, cases, out / "sanitized", True)
    report["export"] = execute([str(binary), str(boc), "--export", str(out / "cells")], out / "export.json")

    # First falsify installation on the unchanged contract, in a private source
    # copy. Never label this a qualified mutant if the original baseline is red.
    anchor = "    set_conf_param(46, registry);"
    text = original.decode()
    if text.count(anchor) != 1:
        raise RuntimeError("installation anchor is not unique")
    changed = text.replace(anchor, "    ;; installation removed by the measurement control", 1)
    mutant = out / "without-installation.fc"
    mutant.write_text(changed)
    if mutant.read_text() != changed or changed == text:
        raise RuntimeError("installation edit did not reach its source")
    mutant_boc = compile_contract(build, mutant, out / "without-installation-contract")
    report["without_installation"] = run_cases(binary, mutant_boc, cases, out / "without-installation")
    report["installation_control"] = {
        "edit_reached_source": True, "compiled": True,
        "baseline_all_passed": all(passed(report["normal"][case], case) for case in cases),
        "newly_failing_cases": [case for case in cases if passed(report["normal"][case], case)
                                and not passed(report["without_installation"][case], case)],
        "qualification": "measurement only; final mutation isolation follows a passing baseline",
    }
    report["restored"] = run_cases(binary, boc, cases, out / "restored")
    report["source_unchanged"] = source.read_bytes() == original
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("CONFIG_PERSISTENCE_REPORT", json.dumps(report["installation_control"]), flush=True)
    return 0 if (report["source_unchanged"] and report["export"]["exit_code"] == 0 and
                 all(passed(report[flavor][case], case) for flavor in ("normal", "sanitized", "restored")
                     for case in cases)) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"HARNESS_FAILURE {error}", file=sys.stderr)
        sys.exit(2)
