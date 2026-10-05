"""Semantic controls for authenticated history and complete internal delivery."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/proven_transactions.rs"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    guards = [
        ("fetch_budget", "invalid receipt history budget", "invalid budget invoked transport"),
        ("hash", "transaction hash mismatch", "accepted receipt substitution hash"),
        ("lt", "transaction logical time mismatch", "accepted receipt substitution lt"),
        ("account", "transaction account mismatch", "accepted receipt substitution account"),
        (
            "post_state",
            "transaction post-state differs from proven account",
            "accepted receipt substitution post_state",
        ),
        ("time", "transaction is newer than account proof", "accepted receipt substitution future"),
        ("history", "transaction state chain mismatch", "accepted broken transaction state chain"),
        ("anchor", "receipt trust anchors differ", "accepted receipt from another trust anchor"),
        ("inbound", "inbound message mismatch", "accepted unrelated recipient input"),
        (
            "aborted",
            "transaction aborted, destroyed or bounced",
            "accepted incomplete execution aborted",
        ),
        ("compute", "transaction compute failed", "accepted incomplete execution compute"),
        ("action", "transaction actions incomplete", "accepted incomplete execution action"),
        (
            "emitted",
            "transaction did not emit expected message",
            "accepted message absent from sender",
        ),
    ]
    cases = []
    for label, message, reason in guards:
        marker = json.dumps(message)
        assert source.count(marker) == 1
        at = source.index(marker)
        start = source.rfind("anyhow::ensure!(", 0, at)
        end = source.index(");", at) + 2
        assert start >= 0
        cases.append((label, source[:start] + source[end:], reason))
    for label, old, reason in [
        ("fetch_limit", "for _ in 0..maximum", "accepted an over-budget history"),
        (
            "exit",
            "(compute.exit_code == 0 || compute.exit_code == 1)",
            "accepted incomplete execution exit",
        ),
        ("skipped", "action.skipped_actions == 0", "accepted incomplete execution skipped"),
    ]:
        assert source.count(old) == 1
        cases.append((label, source.replace(old, "for _ in 0..=maximum" if label == "fetch_limit" else "true"), reason))

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
                "transaction_receipt_tests",
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
        assert code == 0 and "7 passed" in log, log[-3000:]
        for label, mutated, reason in cases:
            SOURCE.write_text(mutated)
            code, log = run(label)
            assert code != 0 and " ... FAILED" in log and reason in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": reason}
    finally:
        SOURCE.write_text(source)
        code, log = run("restored")
        assert code == 0 and "7 passed" in log, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("16 receipt/history/delivery guard controls detected; restored tests pass")


if __name__ == "__main__":
    main()
