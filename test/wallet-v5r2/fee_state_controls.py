"""Require semantic failures when initial fee-state binding guards are removed."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_state.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    cases = [
        ("live", "evidence.live", "true", "initial_fee_state_binding", "accepted bad live"),
        (
            "address",
            'evidence.account.address == format!("0:{}", hex::encode(vault))',
            "true",
            "initial_fee_state_binding",
            "accepted bad address",
        ),
        (
            "code",
            "evidence.account.code_hash == code.repr_hash().to_hex_string()",
            "true",
            "initial_fee_state_binding",
            "accepted bad code",
        ),
        (
            "version",
            "actual.get_next_byte()? == 3",
            "{ actual.get_next_byte()?; true }",
            "initial_fee_state_binding",
            "accepted bad version",
        ),
        (
            "counter",
            "next <= LEAF_COUNT",
            "true",
            "initial_fee_state_binding",
            "accepted bad counter",
        ),
        (
            "config",
            "actual.into_cell()?.repr_hash() == expected.into_cell()?.repr_hash()",
            "true",
            "initial_fee_state_binding",
            "accepted bad config",
        ),
        (
            "age_policy",
            "(1..SLOT_SECONDS).contains(&max_age)",
            "true",
            "fee_time_policy",
            "unsafe time accepted",
        ),
        ("age", "age <= max_age", "true", "fee_time_policy", "unsafe time accepted"),
        ("slot", "slot == local_slot", "true", "fee_time_policy", "unsafe time accepted"),
    ]

    def test(label, name):
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
                name,
            ],
            capture_output=True,
            text=True,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    results = {}
    try:
        for name in ["initial_fee_state_binding", "fee_time_policy"]:
            code, log = test("baseline-" + name, name)
            assert code == 0 and "1 passed" in log, log[-2000:]
        for label, old, new, name, reason in cases:
            assert source.count(old) == 1, label
            SOURCE.write_text(source.replace(old, new))
            code, log = test(label, name)
            assert code != 0 and " ... FAILED" in log and reason in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": reason}
    finally:
        SOURCE.write_text(source)
        for name in ["initial_fee_state_binding", "fee_time_policy"]:
            code, log = test("restored-" + name, name)
            assert code == 0 and "1 passed" in log, log[-2000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("9 fee state binding deletion controls detected; restored tests pass")


if __name__ == "__main__":
    main()
