"""Require AUTH SDK tests to fail semantically after independent binding guard deletions."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2.rs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = SOURCE.read_text()
    cases = [
        ("parties", "binding.account != binding.module", "true", "wallet_cannot_be_its_own_module"),
        (
            "primary_authority",
            "role != AuthRole::Primary || kind == 0",
            "true",
            "primary_cannot_change_authority",
        ),
        ("ttl", "(1..=3600).contains(&ttl)", "true", "deadline_and_signature_framing_are_strict"),
        (
            "signature_width",
            "signature.len() == self.role.signature_bytes()",
            "true",
            "deadline_and_signature_framing_are_strict",
        ),
        (
            "domain",
            'domain.append_raw(b"TOS-AUTH", 64)?;',
            'domain.append_raw(b"BAD-AUTH", 64)?;',
            "independent_python_wire_vectors",
        ),
    ]

    def test(label):
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
                "wallet_v5r2::tests",
            ],
            capture_output=True,
            text=True,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    results = {}
    try:
        code, _ = test("baseline")
        assert code == 0
        for name, old, new, witness in cases:
            assert source.count(old) == 1
            SOURCE.write_text(source.replace(old, new))
            code, log = test(name)
            assert code != 0 and f"wallet_v5r2::tests::{witness} ... FAILED" in log, log[-3000:]
            results[name] = {"exit": code, "semantic_witness": witness}
    finally:
        SOURCE.write_text(source)
        code, log = test("restored")
        assert code == 0, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Five AUTH SDK semantic deletion controls detected; restored tests pass")


if __name__ == "__main__":
    main()
