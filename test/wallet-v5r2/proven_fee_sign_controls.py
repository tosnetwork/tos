"""Semantic controls for the proven-state to durable fee-signing adapter."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_journal.rs"
TEST = "proven_fee_signing_uses_journal_and_bound_key"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    cases = [
        ("route", "self.route == vault.route()", "true", 1, "wrong route invoked signer"),
        ("freshness", "vault.validate_freshness(now)?;", "", 2, "preflight invoked signer"),
        ("deadline", "valid_until > now", "true", 1, "preflight invoked signer"),
        ("key", "vault.fee_public_key()", "&[0; 60]", 2, "verification key substitution"),
        (
            "export",
            "verify(vault.fee_public_key(), plan.leaf, intent.digest(), &signature)?",
            "true",
            1,
            "cache was not reverified before export",
        ),
        ("counter", "vault.next_leaf()", "0", 2, "chain counter ignored"),
        ("config", "*vault.config_hash()", "[0; 32]", 1, "proven fee intent mismatch"),
    ]

    def run(label):
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
                TEST,
            ],
            capture_output=True,
            text=True,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    results = {}
    try:
        code, log = run("baseline")
        assert code == 0 and "1 passed" in log, log[-3000:]
        for label, old, new, count, reason in cases:
            assert source.count(old) == count, label
            SOURCE.write_text(source.replace(old, new))
            code, log = run(label)
            assert code != 0 and f"::{TEST} ... FAILED" in log and reason in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": reason}
    finally:
        SOURCE.write_text(source)
        code, log = run("restored")
        assert code == 0 and "1 passed" in log, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("7 proven fee signing controls detected; restored test passes")


if __name__ == "__main__":
    main()
