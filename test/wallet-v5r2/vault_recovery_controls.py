"""Require preparation and funded migration gates across asynchronous Vault loading."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTS = {
    "preparation": "native_preparation_signing_binds_successor_and_current_rescue",
    "migration": "native_migration_requires_both_funded_pops",
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    path = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_vault.rs"
    original = path.read_text()
    cases = []
    for operation in TESTS:
        arguments = (
            "before, valid_until, successor, amounts, policy"
            if operation == "preparation"
            else "before, valid_until, successor, evidence"
        )
        witness = (
            "preparation opened custody before successor validation"
            if operation == "preparation"
            else "migration opened custody before funded POP validation"
        )
        recheck = (
            "view.sign_preparation_submission(\n            after,"
            if operation == "preparation"
            else "view.sign_migration_submission(after,"
        )
        cases.extend(
            [
                (operation, "preflight", f"view.{operation}_request({arguments})?;", "", witness),
                (
                    operation,
                    "clock",
                    "after >= before",
                    "true",
                    f"Vault {operation} accepted regressed clock after loading",
                ),
                (
                    operation,
                    "recheck",
                    recheck,
                    recheck.replace("after,", "before,"),
                    f"Vault {operation} accepted stale proof after loading",
                ),
            ]
        )
    for operation, name, old, _, _ in cases:
        assert original.count(old) == 1, (operation, name, original.count(old))

    def run(label, test):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--features",
                "native-wallet-vault",
                "--lib",
                test,
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        for operation, test in TESTS.items():
            code, log = run(f"{label}_{operation}", test)
            assert code == 0 and "1 passed; 0 failed" in log and test in log, log[-4000:]

    results = {}
    try:
        positive("baseline")
        for operation, name, old, new, witness in cases:
            path.write_text(original.replace(old, new))
            label = f"{operation}_{name}"
            code, log = run(label, TESTS[operation])
            assert (
                code != 0
                and "test result: FAILED" in log
                and witness in log
                and f"::{TESTS[operation]} ... FAILED" in log
            ), log[-4000:]
            results[label] = {"exit": code, "semantic_witness": witness}
            path.write_text(original)
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} Vault recovery controls detected; both restored tests pass")


if __name__ == "__main__":
    main()
