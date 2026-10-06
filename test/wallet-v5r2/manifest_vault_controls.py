"""Require manifest-to-Vault recovery to retain namespace, profile and cancellation guards."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "manifest_vault_restores_only_bound_keys_without_overwrite"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    path = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_manifest.rs"
    original = path.read_text()
    cases = [
        (
            "input_profile",
            "declared == input_profile",
            "true",
            TEST,
            "vault accepted wrong input profile",
        ),
        (
            "account_index",
            "account_index: d.account_index",
            "account_index: 5",
            TEST,
            "vault accepted changed account_index",
        ),
        (
            "key_generation",
            "key_generation: d.key_generation",
            "key_generation: 7",
            TEST,
            "vault accepted changed key_generation",
        ),
        (
            "unpolled_wipe",
            "let master = Wipe(master);\n        async move {",
            "async move {\n            let master = Wipe(master);",
            TEST,
            "unpolled manifest restore retained master",
        ),
    ]
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
                "--features",
                "native-wallet-vault",
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
        assert code == 0 and "5 passed; 0 failed" in log and f"::{TEST} ... ok" in log, log[-4000:]

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
    print(f"{len(results)} manifest Vault controls detected; restored tests pass")


if __name__ == "__main__":
    main()
