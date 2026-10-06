"""Require internal LMS signing to verify output and erase rejected output bytes."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "internal_fee_primitive_signs_and_clears_rejected_outputs"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    vendor = ROOT / "third-party/lms-reference"
    for item in json.loads((vendor / "SOURCE.json").read_text())["files"]:
        assert hashlib.sha256((vendor / item["file"]).read_bytes()).hexdigest() == item["sha256"], (
            item["file"]
        )
    source = ROOT / "crypto/pq/wallet-lms-sign-c.cpp"
    original = source.read_text()
    verify = original[original.index("  if (!signed_ok ||") :].split(" {", 1)[0]
    clear = "  OPENSSL_cleanse(output, output_size);\n"
    preflight = original[original.index(clear) : original.index("  struct seed_derive derive{};")]
    cases = [
        ("verify_output", verify, "  if (!signed_ok)", "fee primitive accepted bad input 0"),
        (
            "initial_clear",
            preflight,
            preflight.replace(clear, "", 1) + clear,
            "fee primitive leaked rejected output 1",
        ),
        (
            "failed_clear",
            "    OPENSSL_cleanse(output, output_size);\n    return 0;\n  }\n  return 1;",
            "    return 0;\n  }\n  return 1;",
            "fee primitive leaked rejected output 0",
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
                "wallet-pq-signer",
                "--lib",
                "fee::",
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
    print("3 internal fee-signing controls detected; restored tests and vendor hashes pass")


if __name__ == "__main__":
    main()
