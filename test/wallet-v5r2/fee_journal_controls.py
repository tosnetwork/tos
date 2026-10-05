"""Require real SDK journal tests to fail after independent persistence guard deletions."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_journal.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    mutations = [
        (
            "lock",
            "file.try_lock_exclusive()?;",
            "",
            "durable_reservations_exclude_writers_and_restarts_wait",
        ),
        (
            "append",
            "self.file.write_all(&record)?;",
            "",
            "durable_reservations_exclude_writers_and_restarts_wait",
        ),
        ("poison", "self.poisoned = true;", "", "failed_write_poison_survives_repaired_handle"),
        (
            "restore",
            "if let Some(barrier) = self.barrier {",
            "if let Some(barrier) = None::<RestoreBarrier> {",
            "rollback_snapshot_cannot_resume_current_slot",
        ),
    ]
    results = {}

    def run(name):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--lib",
                "lms_fee_",
                "--",
                "--nocapture",
            ],
            capture_output=True,
            text=True,
        )
        log = result.stdout + result.stderr
        (args.output / f"{name}.log").write_text(log)
        return result.returncode, log

    try:
        code, log = run("production")
        assert code == 0, log[-2000:]
        for name, old, new, witness in mutations:
            assert source.count(old) == 1
            SOURCE.write_text(source.replace(old, new))
            code, log = run(name)
            assert code != 0 and f"lms_fee_journal::tests::{witness} ... FAILED" in log
            assert "panicked at" in log and "assertion" in log
            results[name] = {"exit": code, "semantic_witness": witness}
    finally:
        SOURCE.write_text(source)
        code, log = run("restored")
        assert code == 0, log[-2000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Four journal deletion controls fail semantic tests; restored SDK tests pass")


if __name__ == "__main__":
    main()
