"""Require Vault PQ record and enrollment checks to fail when removed."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    path = ROOT / "tosctl/src/wallet-pq-signer/src/vault.rs"
    original = path.read_text()
    cases = [
        (
            "profile",
            "metadata.get_tag(PROFILE_TAG) != Some(PROFILE_V1)",
            "accepted invalid profile",
        ),
        ("role", "metadata.get_tag(ROLE_TAG) != Some(role_tag(role))", "accepted invalid role"),
        ("expiration", "metadata.is_expired()", "accepted invalid expiration"),
        ("enrollment", "signer.public_key() != expected_key", "wrong enrollment accepted"),
    ]
    for _, old, _ in cases:
        assert original.count(old) == 1

    def run(label):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "wallet-pq-signer",
                "--features",
                "vault",
                "--lib",
                "vault::tests",
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
        assert code == 0 and "2 passed; 0 failed" in log, log[-5000:]

    results = {}
    try:
        positive("baseline")
        for name, old, witness in cases:
            path.write_text(original.replace(old, "false"))
            code, log = run(name)
            assert code != 0 and "test result: FAILED" in log and witness in log, log[-5000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(original)
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} Vault signer controls detected; restored tests pass")


if __name__ == "__main__":
    main()
