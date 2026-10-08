"""Require fixed KDF bytes, domain separation and secret-buffer cleanup."""

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
    path = ROOT / "tosctl/src/wallet-pq-signer/src/kdf.rs"
    original = path.read_text()
    vectors = "frozen_dual_root_and_fee_vectors"
    cases = [
        (
            "extract_expand",
            "HkdfMode::EXTRACT_THEN_EXPAND",
            "HkdfMode::EXPAND_ONLY",
            vectors,
            "KDF output differs from frozen vector",
        ),
        (
            "salt",
            "set_hkdf_salt(PROFILE)",
            'set_hkdf_salt(b"wrong-profile")',
            vectors,
            "KDF output differs from frozen vector",
        ),
        (
            "role_label",
            'Self::Primary => b"ML-DSA-44"',
            'Self::Primary => b"ML-DSA-45"',
            vectors,
            "KDF info bytes changed",
        ),
        (
            "master_width",
            "master.0.len() != 32 || ",
            "",
            "rejected_sizes_clear_master_and_output",
            "invalid KDF width accepted",
        ),
        (
            "master_wipe",
            "let master = WipeSeed(master);",
            "let master = (master,);",
            vectors,
            "master not wiped after derivation",
        ),
        (
            "failure_output",
            "output.zeroize();",
            "",
            "rejected_sizes_clear_master_and_output",
            "failed derivation retained output",
        ),
    ]
    for field in ("network", "global_id", "account_index", "key_generation", "tree_id"):
        expression = (
            f"&context.{field}"
            if field == "network"
            else "&tree_id"
            if field == "tree_id"
            else f"&context.{field}.to_be_bytes()"
        )
        cases.append(
            (field, f"info.extend_from_slice({expression});", "", vectors, "KDF info bytes changed")
        )
    for name, old, _, _, _ in cases:
        assert original.count(old) == 1, (name, original.count(old))

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
                "--lib",
                "kdf::tests",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        code, log = run(label)
        assert code == 0 and "3 passed; 0 failed" in log and f"::{vectors} ... ok" in log, log[
            -4000:
        ]

    results = {}
    try:
        positive("baseline")
        for name, old, new, test, witness in cases:
            path.write_text(original.replace(old, new))
            code, log = run(name)
            assert (
                code != 0
                and f"::{test} ... FAILED" in log
                and witness in log
                and "test result: FAILED" in log
            ), log[-4000:]
            results[name] = {"exit": code, "test": test, "semantic_witness": witness}
            path.write_text(original)
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} KDF controls detected; restored tests pass")


if __name__ == "__main__":
    main()
