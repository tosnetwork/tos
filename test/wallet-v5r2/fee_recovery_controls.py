"""Require fee recovery to preserve every KDF input and secret cleanup."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "fee_master_and_mnemonic_restore_bind_context_and_wipe"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_restore.rs"
    original = source.read_text()
    derive = "derive_seed_and_wipe(master.0, context, Material::Fee { tree_id }, &mut locked)?;"
    cases = []
    for name, value, case in [
        ("network", "[1; 32]", 1),
        ("global_id", "42", 2),
        ("account_index", "5", 3),
        ("key_generation", "7", 4),
    ]:
        changed = derive.replace(
            ", context,", ", DerivationContext { " + name + ": " + value + ", ..context },"
        )
        cases.append((name, derive, changed, f"fee master restore accepted wrong input {case}"))
    cases.extend(
        [
            (
                "tree_id",
                derive,
                derive.replace(
                    "Material::Fee { tree_id }", "Material::Fee { tree_id: [0xa5; 32] }"
                ),
                "fee master restore accepted wrong input 5",
            ),
            (
                "unpolled_wipe",
                "    let master = Wipe(master);\n    async move {",
                "    async move {\n        let master = Wipe(master);",
                "unpolled fee master restore retained input",
            ),
            (
                "exact_password",
                "private_seed(phrase, password)",
                "private_seed(phrase, password.trim())",
                "fee mnemonic rejected exact password",
            ),
        ]
    )
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
    print("7 fee recovery controls detected; restored test passes")


if __name__ == "__main__":
    main()
