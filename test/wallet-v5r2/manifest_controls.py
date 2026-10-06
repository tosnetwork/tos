"""Require manifest reconstruction to reject altered profiles, code, identities and resource bounds."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "manifest_rejects_profile_code_identity_and_trusted_wallet_changes"
FORMAT = "manifest_rejects_unknown_duplicate_oversized_and_noncanonical_inputs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    path = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_manifest.rs"
    original = path.read_text()
    cases = [
        ("schema", "wire.schema == SCHEMA", "true", TEST, "manifest accepted changed schema"),
        ("kdf", "wire.kdf == KDF", "true", TEST, "manifest accepted changed kdf"),
        ("workchain", "wire.workchain == 0", "true", TEST, "manifest accepted wrong workchain"),
        (
            "fee_profile",
            'wire.fee_profile == "HSS-L1-LMS-SHA256-M32-H20-LMOTS-SHA256-N32-W4"',
            "true",
            TEST,
            "manifest accepted changed fee_profile",
        ),
        (
            "policy",
            '_ => anyhow::bail!("unsupported manifest rescue policy"),',
            "_ => RescuePolicy::Ready,",
            TEST,
            "manifest accepted changed policy",
        ),
        (
            "trusted_wallet",
            "*g.wallet_init().repr_hash().as_array() == expected_basechain_wallet",
            "true",
            TEST,
            "manifest ignored trusted wallet",
        ),
        (
            "canonical_hex",
            "hex::encode(decoded) == value",
            "true",
            FORMAT,
            "manifest accepted noncanonical hex",
        ),
        (
            "input_limit",
            'anyhow::ensure!(encoded.len() <= MAX_MANIFEST_BYTES, "manifest size limit");\n        let wire:',
            "let wire:",
            FORMAT,
            "manifest accepted oversized input",
        ),
        (
            "unknown_field",
            "#[serde(deny_unknown_fields)]\nstruct Wire",
            "struct Wire",
            FORMAT,
            "manifest accepted unknown field",
        ),
        (
            "unknown_derivation",
            "#[serde(deny_unknown_fields)]\npub struct RecoveryDerivation",
            "pub struct RecoveryDerivation",
            FORMAT,
            "manifest accepted unknown derivation field",
        ),
    ]
    for item in ("wallet", "module", "vault"):
        cases.append(
            (
                f"{item}_code",
                f"bytes::<32>(&wire.{item}_code)? == hashes.{item}",
                "true",
                TEST,
                f"manifest accepted changed {item}_code",
            )
        )
        cases.append(
            (
                f"{item}_identity",
                f"bytes::<32>(&wire.{item}_state_init)? == *g.{item}_init().repr_hash().as_array()",
                "true",
                TEST,
                f"manifest accepted changed {item}_state_init",
            )
        )
    cases.append(
        (
            "fee_config",
            "bytes::<32>(&wire.fee_config_hash)? == *g.config_hash()",
            "true",
            TEST,
            "manifest accepted changed fee_config_hash",
        )
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
                "contracts",
                "--lib",
                "wallet_v5r2_manifest",
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
        assert code == 0 and "3 passed; 0 failed" in log and f"::{TEST} ... ok" in log, log[-4000:]

    results = {}
    try:
        positive("baseline")
        for name, old, new, test, witness in cases:
            path.write_text(original.replace(old, new))
            code, log = run(name)
            assert (
                code != 0
                and "test result: FAILED" in log
                and f"::{test} ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(original)
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} manifest controls detected; restored tests pass")


if __name__ == "__main__":
    main()
