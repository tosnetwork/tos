#!/usr/bin/env python3
# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Re-run the native-only transaction families under the call recorder and check the whole migration.

    txnfam_selfcheck.py <libemulator.so> <target> <vectors dir>

For each family below that needs nothing but the C++ emulator, run the unchanged family script with
txnfam_site/ on PYTHONPATH, convert the recorded calls, and require

1. ``<target> txn`` reproduces every recorded native result (txnfam_convert.py check);
2. every record the family itself retains matches one of those contexts (txnfam_artifacts.py), and
3. the frozen fixtures of that family carry the same contexts and effects (txnfam_convert.py fixtures).

So a change to a family script, the recorder, the converter or the C++ shows up here, not only as a
changed fixture.
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(HERE), str(HERE.parent / "runner")]
# Sibling and test-helper modules are loaded by name: they live outside the type checker's import roots.
txnfam_artifacts = importlib.import_module("txnfam_artifacts")
txnfam_convert = importlib.import_module("txnfam_convert")
conformance = importlib.import_module("conformance")

FAMILIES = (
    ("storage-cache-carry", "storage_cache_carry.py", "storage-cache-carry.json"),
    ("storage-rollback-carry", "storage_rollback_carry.py", "storage-rollback-carry.json"),
    ("storage-tick-carry", "storage_tick_carry.py", "storage-tick-carry.json"),
    ("storage-option-carry", "storage_option_carry.py", "storage-option-carry.json"),
    ("deploy-state", "deploy_state.py", None),
)


def same_contexts(work: Path, fixture_file: Path, blobs_file: Path) -> int:
    """The frozen contexts, blobs inlined, equal the freshly converted unique contexts."""
    blobs = conformance.load_blobs(blobs_file)
    frozen = [
        conformance.resolve(f["context"], blobs) for f in conformance.read_jsonl(fixture_file)
    ]
    fresh = [e["context"] for e in txnfam_convert.read_jsonl(work / "unique.jsonl")]
    if frozen != fresh:
        print(f"{fixture_file.name}: frozen contexts differ from the converted native calls")
        return 1
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    library, target, vectors = Path(argv[0]).resolve(), argv[1], Path(argv[2])
    failures = 0
    with tempfile.TemporaryDirectory(prefix="txnfam-selfcheck-") as directory:
        base = Path(directory)
        for family, script, record in FAMILIES:
            capture, work, output = base / family / "capture", base / family / "work", base / family
            capture.mkdir(parents=True)
            report = output / "report.json"
            env = dict(
                os.environ,
                TXNFAM_CAPTURE_DIR=str(capture),
                TXNFAM_NATIVE=str(library),
                EMULATOR_PATH=str(library),
                PYTHONPATH=str(HERE / "txnfam_site"),
            )
            done = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "test/executor-parity" / script),
                    "--output",
                    str(report),
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=1800,
                check=False,
            )
            if done.returncode != 0:
                print(f"{family}: family run failed: {done.stderr[-2000:]}")
                failures += 1
                continue
            txnfam_convert.command_contexts(capture, work, family)
            failures += txnfam_convert.command_check(work, target)
            records = [str(output)]
            if record is not None:
                records.append(str(ROOT / "tosctl/src/executor/tests/fixtures" / record))
            else:
                records.append(str(report))
            failures += txnfam_artifacts.main([str(work), *records])
            fixture_file = vectors / "txn" / "fixtures" / f"{family}.jsonl"
            failures += txnfam_convert.command_fixtures(work, fixture_file)
            failures += same_contexts(work, fixture_file, fixture_file.with_suffix(".blobs.json"))
    print(f"{len(FAMILIES)} families re-run, {failures} failed checks")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
