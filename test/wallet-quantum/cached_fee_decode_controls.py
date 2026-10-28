"""Require pending fee intent parsing to reject noncanonical and out-of-profile cells."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "cached_fee_decode_is_canonical_and_bounded"
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/wallet_quantum_fee_decode.rs"
COINS_READ = "let value = Coins::construct_from(&mut s)?.as_u128();"
# Test-only fallback: independently exercise the cache hash check if strict
# primitive decoding regresses. The real decoder is restored in finally.
PERMISSIVE_READ = """let value = {
            let length = s.get_next_int(4)? as usize;
            let mut value = 0_u128;
            for byte in s.get_next_bytes(length)? {
                value = value.checked_mul(256)
                    .and_then(|n| n.checked_add(u128::from(byte)))
                    .ok_or_else(|| anyhow::anyhow!("cached amount overflow"))?;
            }
            value
        };"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--release", action="store_true", help="reuse a release-profile local build"
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = SOURCE.read_text()
    assert source.count(COINS_READ) == 1
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
                *(["--release"] if args.release else []),
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
        # Each independent defense must still reject the padded amount when the
        # other is bypassed. Removing both must reach the original test witness.
        canonical = cases[0][1]
        for label, changed in (
            ("codec-defense", source.replace(canonical, "true")),
            ("canonical-defense", source.replace(COINS_READ, PERMISSIVE_READ)),
        ):
            SOURCE.write_text(changed)
            results[label] = run(label)
        for name, old, witness in cases:
            changed = source.replace(old, "true")
            if name == "canonical":
                changed = changed.replace(COINS_READ, PERMISSIVE_READ)
            SOURCE.write_text(changed)
            results[name] = run(name, witness)
            SOURCE.write_text(source)
    finally:
        SOURCE.write_text(source)
        results["restored"] = run("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("3 cached fee parser controls detected; both independent defenses and restored test pass")


if __name__ == "__main__":
    main()
