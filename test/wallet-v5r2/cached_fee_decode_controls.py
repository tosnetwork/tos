"""Require pending fee intent parsing to reject noncanonical and out-of-profile cells."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "cached_fee_decode_is_canonical_and_bounded"
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_fee_decode.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = SOURCE.read_text()
    cases = [
        (
            "canonical",
            "decoded.cell.repr_hash() == cell.repr_hash()",
            "cached parser accepted noncanonical amount",
        ),
        ("leaf", "leaf < LEAF_COUNT", "cached parser accepted exhausted leaf"),
        ("value", "value > 0", "cached parser accepted zero value"),
    ]
    for name, old, _ in cases:
        assert source.count(old) == 1, name

    def run(label, witness=None):
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
            timeout=600,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        if witness:
            assert (
                result.returncode != 0
                and "test result: FAILED" in log
                and f"::{TEST} ... FAILED" in log
                and witness in log
            ), log[-4000:]
        else:
            assert result.returncode == 0 and "1 passed" in log and f"::{TEST} ... ok" in log, log[
                -4000:
            ]
        return {"exit": result.returncode, "semantic_witness": witness}

    results = {"baseline": run("baseline")}
    try:
        for name, old, witness in cases:
            SOURCE.write_text(source.replace(old, "true"))
            results[name] = run(name, witness)
            SOURCE.write_text(source)
    finally:
        SOURCE.write_text(source)
        results["restored"] = run("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("3 cached fee parser controls detected; restored test passes")


if __name__ == "__main__":
    main()
