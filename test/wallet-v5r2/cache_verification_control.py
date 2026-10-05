"""Require a real cached LMS signature with the wrong public key to expose verifier deletion."""

import argparse
import json
import subprocess
from pathlib import Path

from cached_fee_fixture import signature

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/examples/lms_fee_cache_fixture.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True, help="SDK cache fixture directory")
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    fixture = json.loads((args.baseline / "sign-input.json").read_text())
    source = SOURCE.read_text()
    guard = "Ok(vm.stack().get(0)?.as_integer_value(-1..=0)? == -1)"
    assert source.count(guard) == 1

    def build(label):
        result = subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "contracts",
                "--example",
                "lms_fee_cache_fixture",
            ],
            capture_output=True,
            text=True,
        )
        (args.output / f"{label}-build.log").write_text(result.stdout + result.stderr)
        assert result.returncode == 0

    def exercise(label):
        return signature(
            args.driver,
            args.output / label,
            tree=Path(fixture["tree"]),
            key=bytes.fromhex(fixture["public_key"]),
            vault=int(fixture["vault"], 16),
            digest=bytes.fromhex(fixture["digest"]),
            now=fixture["proven_time"],
            epoch0=fixture["epoch0"],
        )

    try:
        SOURCE.write_text(source.replace(guard, "Ok(true)"))
        build("deleted")
        try:
            exercise("deleted")
        except AssertionError:
            # Require a successful verifier result for the wrong key, not a
            # build failure or unavailable fixture/signer, to count the control.
            accepted = json.loads((args.output / "deleted/wrong-key-output.json").read_text())
            assert accepted["verified"] and accepted["backend_calls"] == 0
        else:
            raise AssertionError("deleted verifier was not detected")
    finally:
        SOURCE.write_text(source)
        build("restored")
    restored = exercise("restored")
    assert len(restored) == 2832
    (args.output / "results.json").write_text(
        json.dumps(
            {
                "deleted_verifier_accepts_wrong_key": True,
                "fixture_detected_semantic_failure": True,
                "restored_real_signature_and_negative_controls_pass": True,
            },
            indent=2,
        )
        + "\n"
    )
    print("Real wrong-key cache accepted only after verifier deletion; restored checks pass")


if __name__ == "__main__":
    main()
