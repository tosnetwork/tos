#!/usr/bin/env python3
"""Run the N6.2 feasibility microbench under an explicit CPU affinity."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"N6_MICROBENCH_RUNNER_FAILURE: {message}")


parser = argparse.ArgumentParser()
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--build", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--single-samples", type=int, default=10_000)
parser.add_argument("--small-batch-samples", type=int, default=100)
parser.add_argument("--large-batch-samples", type=int, default=30)
args = parser.parse_args()
repo = args.repo.resolve()
build = args.build.resolve()
cache = (build / "CMakeCache.txt").read_text(encoding="utf-8")
if "CMAKE_BUILD_TYPE:STRING=Release" not in cache:
    fail("benchmark build is not Release")
binary = build / "n6-microbench"
if not binary.is_file():
    fail(f"benchmark binary is missing: {binary}")

commit = subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"], text=True).strip()
if subprocess.run(["git", "-C", repo, "diff", "--quiet"]).returncode != 0 or subprocess.run(
    ["git", "-C", repo, "diff", "--cached", "--quiet"]
).returncode != 0:
    fail("diagnostic result must still identify a clean source commit")
criteria = repo / "doc/pq-native/N6-ACCEPTANCE-CRITERIA.json"
criteria_sha256 = hashlib.sha256(criteria.read_bytes()).hexdigest()

allowed = sorted(os.sched_getaffinity(0))
if not allowed:
    fail("no CPUs are available")
pinned = allowed[: min(16, len(allowed))]
affinity = ",".join(str(cpu) for cpu in pinned)
args.output.parent.mkdir(parents=True, exist_ok=True)
command = [
    "taskset",
    "-c",
    affinity,
    str(binary),
    "--output",
    str(args.output),
    "--git-commit",
    commit,
    "--criteria-sha256",
    criteria_sha256,
    "--single-samples",
    str(args.single_samples),
    "--small-batch-samples",
    str(args.small_batch_samples),
    "--large-batch-samples",
    str(args.large_batch_samples),
]
print("N6_MICROBENCH_COMMAND:", " ".join(command), flush=True)
subprocess.run(command, cwd=repo, check=True)
