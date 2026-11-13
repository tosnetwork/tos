#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Coverage-guided fuzzing of the reference, and harvesting its corpus into contexts.

guided.py campaign --build-dir B --corpus DIR --seconds N [--harness vm|txn] [--seeds PATH] [--forks K]
    Run the libFuzzer entry of a build configured with -fsanitize=fuzzer-no-link and
    -DCONFORMANCE_FUZZ_GUIDED=ON, comparing the reference library with its twin. libFuzzer keeps in DIR
    every input that reached new code of the reference; a mismatch aborts the run (it would be a defect of
    the reference build itself) and is kept as a crash file.
guided.py harvest --build-dir B --corpus DIR --out contexts.jsonl [--harness vm|txn] [--seeds PATH]
    Replay the corpus once and write the context of every input both libraries ran with equal effects, one
    create entry per distinct context. Fill them with runner/conformance.py create (source "fuzz").
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def env_for(build: Path, harness: str, seeds: Path | None) -> dict[str, str]:
    lib = build / "test/conformance"
    env = {
        **os.environ,
        "CONFORMANCE_FUZZ_HARNESS": harness,
        "CONFORMANCE_FUZZ_REFERENCE": str(lib / "libconformance-ref.so"),
        "CONFORMANCE_FUZZ_TARGET": str(lib / "libconformance-ref-fuzz-twin.so"),
        "CONFORMANCE_FUZZ_ABORT": "1",
    }
    if seeds is not None:
        env["CONFORMANCE_FUZZ_SEEDS"] = str(seeds)
    return env


def fuzzer(build: Path) -> Path:
    path = build / "test/conformance/conformance-fuzz-libfuzzer"
    if not path.exists():
        raise SystemExit(f"{path} not built (configure with -DCONFORMANCE_FUZZ_GUIDED=ON)")
    return path


def campaign(
    build: Path, corpus: Path, seconds: int, harness: str, seeds: Path | None, forks: int
) -> int:
    corpus.mkdir(parents=True, exist_ok=True)
    artifacts = corpus.parent / f"{corpus.name}-crashes"
    artifacts.mkdir(parents=True, exist_ok=True)
    cmd = [str(fuzzer(build)), str(corpus), f"-max_total_time={seconds}", f"-artifact_prefix={artifacts}/",
           "-print_final_stats=1"]  # fmt: skip
    if forks > 1:
        cmd.append(f"-fork={forks}")
    done = subprocess.run(cmd, env=env_for(build, harness, seeds), check=False)
    print(
        f"corpus {sum(1 for _ in corpus.iterdir())} inputs; crashes {sum(1 for _ in artifacts.iterdir())}"
    )
    return done.returncode


def harvest(build: Path, corpus: Path, out: Path, harness: str, seeds: Path | None) -> int:
    with tempfile.TemporaryDirectory(prefix="conformance-harvest-") as tmp:
        emitted = Path(tmp) / "contexts.jsonl"
        env = {**env_for(build, harness, seeds), "CONFORMANCE_FUZZ_EMIT": str(emitted)}
        done = subprocess.run(
            [str(fuzzer(build)), "-runs=0", str(corpus)], env=env, capture_output=True, check=False
        )
        if done.returncode != 0:
            raise SystemExit(f"replay of the corpus failed ({done.returncode})")
        lines = emitted.read_text().splitlines() if emitted.exists() else []
    seen: dict[str, str] = {}
    for line in lines:
        canonical = json.dumps(json.loads(line), sort_keys=True, separators=(",", ":"))
        seen.setdefault(hashlib.sha256(canonical.encode()).hexdigest(), canonical)
    entries = [
        {"fixture_id": f"fuzz-{d[:20]}", "context": json.loads(c)} for d, c in sorted(seen.items())
    ]
    out.write_text("".join(json.dumps(e, separators=(",", ":")) + "\n" for e in entries))
    print(f"{len(lines)} executed corpus inputs, {len(entries)} distinct contexts")
    return 0 if entries else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("campaign", "harvest"):
        p = sub.add_parser(name)
        p.add_argument("--build-dir", type=Path, required=True)
        p.add_argument("--corpus", type=Path, required=True)
        p.add_argument("--harness", choices=("vm", "txn"), default="vm")
        p.add_argument("--seeds", type=Path)
        if name == "campaign":
            p.add_argument("--seconds", type=int, required=True)
            p.add_argument("--forks", type=int, default=1)
        else:
            p.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    build = args.build_dir.resolve()
    if args.command == "campaign":
        return campaign(build, args.corpus, args.seconds, args.harness, args.seeds, args.forks)
    return harvest(build, args.corpus, args.out, args.harness, args.seeds)


if __name__ == "__main__":
    sys.exit(main())
