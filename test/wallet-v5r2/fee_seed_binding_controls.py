"""Require read-only fee seed binding to check enrollment and erase the seed."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "fee_seed_binding_checks_root_path_profile_and_wipes"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    native = ROOT / "crypto/pq/wallet-lms-sign-c.cpp"
    rust = ROOT / "tosctl/src/wallet-pq-signer/src/fee_binding.rs"
    originals = {p: p.read_text() for p in (native, rust)}
    profile = """!tos::pq::lms_fee_worst_compressions(
          std::string_view(reinterpret_cast<const char*>(public_key), key_size), 32)"""
    cases = [
        (
            "root",
            native,
            "return CRYPTO_memcmp(node, public_key + 28, 32) == 0 ? 1 : 0;",
            "return 1;",
            "fee binding accepted invalid input 0",
        ),
        ("profile", native, profile, "false", "fee binding accepted invalid input 6"),
        (
            "wipe",
            rust,
            "let seed = WipeSeed(seed);",
            "struct Unwiped<'a>(&'a mut [u8]); let seed = Unwiped(seed);",
            "fee binding retained valid seed",
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
                "wallet-pq-signer",
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
    print("3 fee seed binding controls detected; restored test passes")


if __name__ == "__main__":
    main()
