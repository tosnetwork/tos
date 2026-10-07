"""Prove full transaction receipts detect broken native LMS chain encoding."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "crypto/pq/lms-fee.cpp"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = SOURCE.read_text()
    controls = [
        ("chain-index", "chain_input[21] = static_cast<unsigned char>(i);", "chain_input[21] = 0;"),
        ("chain-hash", "SHA256(chain_input.data(), chain_input.size(), tmp.data());", ""),
    ]

    def command(label, argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=300)
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def build(label):
        code, log = command(
            label, ["cmake", "--build", str(args.build.resolve()), "--target", "emulator", "-j2"]
        )
        assert code == 0, log[-3000:]

    def replay(label):
        return command(
            label,
            [
                sys.executable,
                str(Path(__file__).with_name("benchmark_transactions.py")),
                "--fixtures",
                str(args.fixtures.resolve()),
                "--output",
                str((args.output / label).resolve()),
                "--iterations",
                "1",
                "--warmup",
                "1",
            ],
        )

    results = {}
    try:
        build("baseline-build")
        code, log = replay("baseline")
        assert code == 0, log[-3000:]
        for label, old, new in controls:
            assert source.count(old) == 1
            SOURCE.write_text(source.replace(old, new))
            build(label + "-build")
            code, log = replay(label)
            assert code != 0 and "ValueError: replay differs:" in log, log[-3000:]
            results[label] = {"exit": code, "semantic_failure": "replay differs"}
    finally:
        SOURCE.write_text(source)
        build("restored-build")
        code, log = replay("restored")
        assert code == 0, log[-3000:]
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Two LMS chain mutations detected; restored full replay passes")


if __name__ == "__main__":
    main()
