#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""How much of the C++ reference the conformance vectors execute, as a gate that may only go up.

handlers.py measure --build-dir B --source-dir S --out report.json
    Run every fixture and the REL-02 chain replay through the instrumented reference of build directory B
    (configured with -fprofile-instr-generate -fcoverage-mapping), merge the profiles and write, per VM
    instruction handler (crypto/vm/*ops.cpp exec_* functions), whether it executed, and the line coverage
    of the components listed in COMPONENTS.
handlers.py check report.json [--baseline-dir D]
    Fail when a handler listed in D/vm-handlers-covered.txt did not execute, when a handler is in neither
    that file nor D/vm-handlers-unreachable.txt (each line there says why it cannot run at version 16),
    or when a component's line coverage falls more than SLACK points below D/components.json. Handlers in
    D/vm-handlers-gaps.txt are reachable but not yet executed: accepted, and printed on every run.
handlers.py baseline report.json [--baseline-dir D]
    Write vm-handlers-covered.txt and components.json from a report (unreachable entries are kept as is).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
COMPONENTS = [
    "crypto/vm/",
    "crypto/block/transaction.cpp",
    "crypto/block/mc-config.cpp",
    "crypto/block/block.cpp",
    "crypto/pq/",
    "emulator/",
]
SLACK = 0.5


def tool(*names: str) -> str:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    raise SystemExit(f"none of {names} found")


def run(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(cmd, capture_output=True, text=True, check=False, **kw)
    if done.returncode != 0:
        raise SystemExit(f"{cmd[0]} failed ({done.returncode}): {done.stderr.strip()[-1500:]}")
    return done


def measure(build: Path, source: Path, out: Path) -> None:
    ref = build / "test/conformance/conformance-ref-cli"
    replay = build / "emulator/test-epoch-replay"
    lib = build / "test/conformance/libconformance-ref.so"
    for p in (ref, replay, lib):
        if not p.exists():
            raise SystemExit(f"{p} not built")
    profdata_tool, cov_tool = (
        tool("llvm-profdata-21", "llvm-profdata"),
        tool("llvm-cov-21", "llvm-cov"),
    )
    conformance = source / "test/conformance"
    with tempfile.TemporaryDirectory(prefix="conformance-coverage-") as tmp:
        work = Path(tmp)
        env = {**os.environ, "LLVM_PROFILE_FILE": str(work / "prof" / "%p-%m.profraw")}
        vectors = run(
            [sys.executable, "-B", str(conformance / "runner/conformance.py"), "run", "--target", str(ref),
             str(conformance / "vectors")], env=env)  # fmt: skip
        chain = run(
            [sys.executable, "-B", str(conformance / "migrate/rel02.py"), "chain", str(replay), str(ref),
             str(source / "test/rel02/corpus")], env=env)  # fmt: skip
        profiles = sorted(str(p) for p in (work / "prof").glob("*.profraw"))
        if not profiles:
            raise SystemExit("no profile was written: is the build instrumented?")
        merged = work / "all.profdata"
        run([profdata_tool, "merge", "-sparse", *profiles, "-o", str(merged)])
        objects = [str(lib), "-object", str(replay)]
        ops = sorted(str(p.relative_to(source)) for p in (source / "crypto/vm").glob("*ops.cpp"))
        functions = run([cov_tool, "report", *objects, f"-instr-profile={merged}", "-show-functions", *ops],
                        cwd=source).stdout  # fmt: skip
        summary = run([cov_tool, "report", *objects, f"-instr-profile={merged}"], cwd=source).stdout
    handlers: dict[str, bool] = {}
    current = ""
    for line in functions.splitlines():
        m = re.match(r"^File '(.*)':", line)
        if m:
            current = Path(m.group(1)).name
            continue
        parts = line.split()
        if current and len(parts) >= 6 and "exec_" in parts[0]:
            try:
                lines, missed = int(parts[4]), int(parts[5])
            except ValueError:
                continue
            handlers[f"{current}:{parts[0]}"] = not (lines > 0 and lines == missed)
    if not handlers:
        raise SystemExit("no instruction handler found in the coverage report")
    totals = {c: [0, 0] for c in COMPONENTS}
    for line in summary.splitlines():
        parts = line.split()
        if len(parts) < 7:
            continue
        for c in COMPONENTS:
            if parts[0].startswith(c):
                try:
                    totals[c][0] += int(parts[4])
                    totals[c][1] += int(parts[5])
                except ValueError:
                    pass
                break
    components = {c: round(100.0 * (t - m) / t, 2) for c, (t, m) in totals.items() if t}
    report = {
        "vectors": vectors.stdout.strip().splitlines()[-1],
        "chain": chain.stdout.strip().splitlines()[-1],
        "handlers": dict(sorted(handlers.items())),
        "components": components,
    }
    out.write_text(json.dumps(report, indent=1) + "\n")
    executed = sum(handlers.values())
    print(f"handlers executed {executed}/{len(handlers)}; components {components}")


def read_list(path: Path) -> dict[str, str]:
    """Entries "<handler>" or "<handler>\t<reason>", '#' comments allowed."""
    entries: dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                name, _, reason = line.partition("\t")
                entries[name.strip()] = reason.strip()
    return entries


def check(report_path: Path, base: Path) -> int:
    report = cast(dict[str, Any], json.loads(report_path.read_text()))
    handlers = cast(dict[str, bool], report["handlers"])
    covered = read_list(base / "vm-handlers-covered.txt")
    unreachable = read_list(base / "vm-handlers-unreachable.txt")
    gaps = read_list(base / "vm-handlers-gaps.txt")
    floors = cast(dict[str, float], json.loads((base / "components.json").read_text()))
    problems: list[str] = []
    if not covered:
        problems.append("empty baseline of covered handlers")
    for name in sorted(covered):
        if name not in handlers:
            problems.append(f"baseline handler no longer exists: {name}")
        elif not handlers[name]:
            problems.append(f"handler no longer executed: {name}")
    for name, executed in sorted(handlers.items()):
        if name not in covered and name not in unreachable and name not in gaps:
            problems.append(f"handler not classified (executed={executed}): {name}")
        if (name in unreachable and not unreachable[name]) or (name in gaps and not gaps[name]):
            problems.append(f"listed handler without a reason: {name}")
    for component, floor in sorted(floors.items()):
        now = cast(dict[str, float], report["components"]).get(component)
        if now is None or now + SLACK < floor:
            problems.append(f"line coverage of {component}: {now} below baseline {floor}")
    newly = [n for n in sorted({**unreachable, **gaps}) if handlers.get(n)]
    for name, reason in sorted(gaps.items()):
        if not handlers.get(name):
            print(f"GAP {name}: {reason}")
    for line in problems:
        print(f"COVERAGE {line}")
    for name in newly:
        print(f"NOTE now executed, move to the covered list: {name}")
    executed = sum(handlers.values())
    print(
        f"handlers {executed}/{len(handlers)} executed; {len(covered)} required; {len(problems)} problems"
    )
    return 1 if problems else 0


def baseline(report_path: Path, base: Path) -> None:
    report = cast(dict[str, Any], json.loads(report_path.read_text()))
    handlers = cast(dict[str, bool], report["handlers"])
    listed = {
        **read_list(base / "vm-handlers-unreachable.txt"),
        **read_list(base / "vm-handlers-gaps.txt"),
    }
    covered = sorted(n for n, executed in handlers.items() if executed and n not in listed)
    (base / "vm-handlers-covered.txt").write_text(
        "# VM instruction handlers the conformance vectors must execute (handlers.py check).\n"
        + "".join(f"{n}\n" for n in covered)
    )
    (base / "components.json").write_text(
        json.dumps(report["components"], indent=1, sort_keys=True) + "\n"
    )
    print(f"baseline: {len(covered)} covered handlers, components {report['components']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    m = sub.add_parser("measure")
    m.add_argument("--build-dir", type=Path, required=True)
    m.add_argument("--source-dir", type=Path, required=True)
    m.add_argument("--out", type=Path, required=True)
    for name in ("check", "baseline"):
        p = sub.add_parser(name)
        p.add_argument("report", type=Path)
        p.add_argument("--baseline-dir", type=Path, default=HERE)
    args = parser.parse_args(argv)
    if args.command == "measure":
        measure(args.build_dir.resolve(), args.source_dir.resolve(), args.out)
        return 0
    if args.command == "check":
        return check(args.report, args.baseline_dir)
    baseline(args.report, args.baseline_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
