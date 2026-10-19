"""Require the shared native mnemonic mapping and validation to retain their boundaries."""

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
    path = ROOT / "tosctl/src/tos-native-mnemonic/src/lib.rs"
    original = path.read_text()
    frozen = "preserves_native_vectors_and_exact_passwords"
    cases = [
        (
            "basic_seed",
            "check[0] == 0",
            "true",
            "rejects_bip39_words_that_do_not_form_a_tos_basic_seed",
        ),
        ("normalization", "word.to_ascii_lowercase()", "word.to_owned()", frozen),
        ("native_salt", 'b"TOS default seed"', 'b"mnemonic"', frozen),
        ("password", "mac.update(password.as_bytes());", 'mac.update(b"");', frozen),
        ("iterations", "PBKDF_ITERATIONS: u32 = 100_000", "PBKDF_ITERATIONS: u32 = 99_999", frozen),
        (
            "seed_half",
            "seed.copy_from_slice(&derived[..32]);",
            "seed.copy_from_slice(&derived[32..]);",
            frozen,
        ),
    ]
    for name, old, _, _ in cases:
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
                "tos-native-mnemonic",
                "--lib",
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
        assert code == 0 and "3 passed; 0 failed" in log and f"::{frozen} ... ok" in log, log[
            -4000:
        ]

    results = {}
    try:
        positive("baseline")
        for name, old, new, test in cases:
            path.write_text(original.replace(old, new))
            code, log = run(name)
            assert code != 0 and "test result: FAILED" in log and f"::{test} ... FAILED" in log, (
                log[-4000:]
            )
            results[name] = {"exit": code, "semantic_test": test}
            path.write_text(original)
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} native mnemonic controls detected; restored tests pass")


if __name__ == "__main__":
    main()
