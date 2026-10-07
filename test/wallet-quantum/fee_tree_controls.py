"""Require complete fixed-profile fee tree reconstruction and safe public path extraction."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "fee_tree_path_bounds_order_and_invalid_seed_cleanup"
INTEGRATION = "fee_tree_matches_independent_enrollment"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    rust = ROOT / "tosctl/src/wallet-pq-signer/src/fee_tree.rs"
    native = ROOT / "crypto/pq/wallet-lms-tree-c.cpp"
    originals = {p: p.read_text() for p in (rust, native)}
    cases = [
        (
            "wipe",
            rust,
            "let seed = WipeSeed(seed);",
            "struct Unwiped<'a>(&'a mut [u8]); let seed = Unwiped(seed);",
            TEST,
            "fee tree rejected seed not cleared",
        ),
        (
            "leaf_bound",
            rust,
            "leaf >= LEAVES as u32",
            "false",
            TEST,
            "fee path accepted exhausted leaf",
        ),
        (
            "sibling",
            rust,
            "(index ^ 1).checked_mul(32)",
            "index.checked_mul(32)",
            TEST,
            "fee path sibling/order mismatch",
        ),
        (
            "leaf_domain",
            native,
            "input[20] = input[21] = 0x82;",
            "input[20] = input[21] = 0x83;",
            INTEGRATION,
            "fee tree independent root mismatch",
        ),
        (
            "parent_domain",
            native,
            "input[20] = input[21] = 0x83;",
            "input[20] = input[21] = 0x82;",
            INTEGRATION,
            "fee tree independent root mismatch",
        ),
    ]
    for name, source, old, _, _, _ in cases:
        assert originals[source].count(old) == 1, name

    def run(label, test):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "wallet-pq-signer",
                "--lib",
                test,
                "--",
                "--include-ignored",
            ],
            capture_output=True,
            text=True,
            timeout=3600,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        for test in (TEST, INTEGRATION):
            code, log = run(label + "-" + test, test)
            assert code == 0 and "1 passed; 0 failed" in log and f"::{test} ... ok" in log, log[
                -4000:
            ]

    results = {}
    try:
        positive("baseline")
        for name, source, old, new, test, witness in cases:
            source.write_text(originals[source].replace(old, new))
            code, log = run(name, test)
            assert (
                code != 0
                and "test result: FAILED" in log
                and f"::{test} ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            source.write_text(originals[source])
    finally:
        for source, original in originals.items():
            source.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("5 fee tree controls detected; restored full reconstruction and path tests pass")


if __name__ == "__main__":
    main()
