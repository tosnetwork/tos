"""Prove raw-account response binding tests detect independent guard deletions."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/proven_getters.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    cases = [
        ("state hash", "raw_binding_state_hash", "state_hash"),
        ("address", "raw_binding_address", "address"),
        ("code/data", "raw_binding_code", "code_hash"),
        ("code/data", "raw_binding_data", "data_hash"),
        ("balance", "raw_binding_balance", "balance"),
    ]

    def test(label, test_filter):
        run = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--test",
                "proven_pool_snapshot",
                test_filter,
            ],
            capture_output=True,
            text=True,
        )
        log = run.stdout + run.stderr
        (args.output / f"{label}.log").write_text(log)
        return run.returncode, log

    results = {}
    try:
        code, log = test("baseline", "raw_")
        assert code == 0 and "11 passed" in log, log[-3000:]
        for guard, witness, mutation in cases:
            marker = f'"raw account {guard} mismatch"'
            assert source.count(marker) == 1
            at = source.index(marker)
            start = source.rfind("        anyhow::ensure!(", 0, at)
            end = source.index("\n        );", at) + len("\n        );")
            assert start >= 0
            SOURCE.write_text(source[:start] + source[end:])
            code, log = test(witness, witness)
            assert code != 0 and f"test {witness} ... FAILED" in log, log[-3000:]
            assert f"accepted corrupted {mutation}" in log, log[-3000:]
            results[witness] = {"exit": code, "semantic_failure": f"accepted corrupted {mutation}"}
    finally:
        SOURCE.write_text(source)
        code, log = test("restored", "raw_")
        assert code == 0 and "11 passed" in log, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("5 raw-account binding deletion controls detected; restored 11 tests pass")


if __name__ == "__main__":
    main()
