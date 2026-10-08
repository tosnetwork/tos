"""Require proof-bound native fee signing to wipe secrets and reject before reservation."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "native_fee_signing_preserves_proof_reservation_and_seed_cleanup"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    native = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_native.rs"
    journal = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_journal.rs"
    originals = {p: p.read_text() for p in (native, journal)}
    cases = [
        (
            "preflight_wipe",
            native,
            "        self.0.zeroize();",
            "",
            "native fee preflight retained seed",
        ),
        (
            "identifier",
            native,
            "&seed.0[32..] == &key[12..28]",
            "true",
            "native fee preflight consumed a leaf 1",
        ),
        (
            "local_deadline",
            journal,
            "valid_until > now",
            "true",
            "native fee accepted invalid preflight 2",
        ),
    ]
    for name, source, old, _, _ in cases:
        assert originals[source].count(old) == 1, name

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
                "--features",
                "native-wallet-signer",
                "--lib",
                TEST,
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        code, log = run(label)
        assert code == 0 and "1 passed; 0 failed" in log and f"::{TEST} ... ok" in log, log[-4000:]

    results = {}
    try:
        positive("baseline")
        for name, source, old, new, witness in cases:
            source.write_text(originals[source].replace(old, new))
            code, log = run(name)
            assert (
                code != 0
                and "test result: FAILED" in log
                and f"::{TEST} ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            source.write_text(originals[source])
    finally:
        for source, original in originals.items():
            source.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("3 proof-bound native signing controls detected; restored test passes")


if __name__ == "__main__":
    main()
