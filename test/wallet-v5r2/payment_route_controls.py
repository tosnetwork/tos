"""Require full payment routes to reject mismatched enrollment and spliced receipts."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "tosctl/src/node-control/contracts/src"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    cases = [
        (
            "address",
            "wallet_v5r2_receipts.rs",
            "payment route address mismatch",
            "accepted payment route mismatch address",
        ),
        (
            "code",
            "wallet_v5r2_receipts.rs",
            "payment route executed code mismatch",
            "accepted payment route mismatch code",
        ),
        (
            "keys",
            "wallet_v5r2_receipts.rs",
            "payment route module keys mismatch",
            "accepted payment route mismatch keys",
        ),
    ]
    originals = {name: (SOURCES / name).read_text() for _, name, _, _ in cases}

    def run(label):
        p = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--lib",
                "wallet_v5r2_receipts",
            ],
            capture_output=True,
            text=True,
        )
        log = p.stdout + p.stderr
        (args.output / f"{label}.log").write_text(log)
        return p.returncode, log

    statements = [
        (
            "fee_data",
            "crate::wallet_v5r2_state::checked_counter(&data, &self.fee_data)?;",
            "accepted payment route mismatch fee_data",
        ),
        (
            "origin",
            "receipts.fee.require_inbound(submitted_external)?;",
            "accepted payment route unrelated submission",
        ),
        (
            "links",
            "sender.require_internal_delivery(receiver, message.repr_hash().as_array())?;",
            "accepted spliced payment route",
        ),
    ]
    results = {}
    try:
        code, log = run("baseline")
        assert code == 0 and "1 passed" in log, log[-3000:]
        for label, name, message, failure in cases:
            source = originals[name]
            marker = json.dumps(message)
            assert source.count(marker) == 1
            at = source.index(marker)
            start = source.rfind("anyhow::ensure!(", 0, at)
            end = source.index(");", at) + 2
            assert start >= 0
            (SOURCES / name).write_text(source[:start] + source[end:])
            code, log = run(label)
            assert code != 0 and " ... FAILED" in log and failure in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": failure}
            (SOURCES / name).write_text(source)
        for label, statement, failure in statements:
            name = "wallet_v5r2_receipts.rs"
            source = originals[name]
            assert source.count(statement) == 1
            (SOURCES / name).write_text(source.replace(statement, ""))
            code, log = run(label)
            assert code != 0 and " ... FAILED" in log and failure in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": failure}
            (SOURCES / name).write_text(source)
    finally:
        for name, source in originals.items():
            (SOURCES / name).write_text(source)
        code, log = run("restored")
        assert code == 0 and "1 passed" in log, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("6 payment route guard controls detected; restored test passes")


if __name__ == "__main__":
    main()
