"""Compile the actual Rust scheduler; deletion controls must fail semantic assertions."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_schedule.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    variants = [
        ("production", None, None, None),
        (
            "local_reservation",
            "first.max(chain_next_leaf).max(local_next)",
            "first.max(chain_next_leaf)",
            "exported_but_unbroadcast_and_reorged_leaves_stay_burned",
        ),
        (
            "restore_wait",
            "proven_time < barrier.resume_at",
            "false",
            "restore_waits_even_at_exact_boundary_and_ignores_old_counter",
        ),
        (
            "calendar_burn",
            "first.max(chain_next_leaf).max(local_next)",
            "chain_next_leaf.max(local_next)",
            "exported_but_unbroadcast_and_reorged_leaves_stay_burned",
        ),
        ("restored", None, None, None),
    ]
    results = {}
    for name, before, after, witness in variants:
        candidate = source
        if before is not None:
            assert candidate.count(before) == 1
            candidate = candidate.replace(before, after)
        path, binary = args.output / f"{name}.rs", args.output / name
        path.write_text(candidate)
        build = subprocess.run(
            ["rustc", "--edition", "2024", "--test", str(path), "-o", str(binary)],
            capture_output=True,
            text=True,
        )
        (args.output / f"{name}-build.log").write_text(build.stdout + build.stderr)
        assert build.returncode == 0, build.stderr
        run = subprocess.run([str(binary.resolve())], capture_output=True, text=True)
        log = run.stdout + run.stderr
        (args.output / f"{name}.log").write_text(log)
        if witness is None:
            assert run.returncode == 0, log
        else:
            assert run.returncode != 0
            assert f"tests::{witness} ... FAILED" in log
            assert "assertion `left == right` failed" in log
        results[name] = {"exit": run.returncode, "semantic_witness": witness}
    assert SOURCE.read_text() == source
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Scheduler passed; three deleted boundaries fail semantic tests; restored source passed")


if __name__ == "__main__":
    main()
