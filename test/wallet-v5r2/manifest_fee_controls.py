"""Require initial manifest fee recovery to bind profiles, KDF inputs and keys."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "initial_fee_manifest_binds_profile_namespace_and_enrollment"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_manifest_fee.rs"
    original = source.read_text()
    cases = [
        (
            "profile",
            "d.fee_seed_profile == input_profile",
            "true",
            "fee manifest preflight accepted input 0",
        ),
        (
            "account_index",
            "account_index: d.account_index",
            "account_index: 5",
            "fee manifest preflight accepted input 1",
        ),
        (
            "key_generation",
            "key_generation: d.key_generation",
            "key_generation: 7",
            "fee manifest preflight accepted input 2",
        ),
        (
            "tree_id",
            "bytes(&self.wire.fee_tree_id)?",
            "[0xa5; 32]",
            "fee manifest preflight accepted input 5",
        ),
        (
            "network",
            "network: bytes(&self.wire.network)?",
            "network: [1; 32]",
            "fee manifest preflight accepted input 6",
        ),
        (
            "global_id",
            "global_id: self.wire.global_id",
            "global_id: 42",
            "fee manifest preflight accepted input 7",
        ),
        (
            "key_binding",
            "wallet_pq_signer::fee::verify_seed_and_wipe(&mut *seed, &key, leaf, path)?;",
            "",
            "fee manifest preflight accepted input 1",
        ),
        (
            "unpolled_wipe",
            "        let master = Wipe(master);\n        async move {",
            "        async move {\n            let master = Wipe(master);",
            "fee manifest unpolled restore retained master",
        ),
        (
            "preflight_wipe",
            "        let master = Wipe(master);\n        let (context, tree_id, key)",
            "        struct Unwiped<'a>(&'a mut [u8]); let master = Unwiped(master);\n        let (context, tree_id, key)",
            "fee manifest preflight retained master",
        ),
        (
            "restore_binding",
            """            crate::lms_fee_vault::restore_derived_and_wipe(
                vault, id, master.0, context, tree_id, &key, leaf, path,
            )
            .await?;""",
            "",
            "fee manifest restore accepted input 1",
        ),
    ]
    for name, old, _, _ in cases:
        assert original.count(old) == 1, name

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
        for name, old, new, witness in cases:
            source.write_text(original.replace(old, new))
            code, log = run(name)
            assert (
                code != 0
                and "test result: FAILED" in log
                and f"::{TEST} ... FAILED" in log
                and witness in log
            ), log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            source.write_text(original)
    finally:
        source.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("10 initial fee manifest controls detected; restored test passes")


if __name__ == "__main__":
    main()
