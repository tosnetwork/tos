"""Prove PRIMARY CLI delivery checks reject unrelated receipts and recipient failures."""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--genesis-driver", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "test/wallet-v5r2/cli_sign_primary.py"
    original = source.read_text()
    mutations = {
        "input_binding": (
            "incoming is not None and incoming.hash == message.hash",
            "unrelated input was classified as delivery",
        ),
        "execution_success": (
            'details.get("compute_success")\n        and not details.get("aborted")\n'
            '        and (details.get("action") is None or details["action"]["success"])',
            "recipient failure was classified as delivery",
        ),
    }

    def run(label, failure=None):
        r = subprocess.run(
            [
                sys.executable,
                str(source),
                "--cli",
                str(args.cli),
                "--genesis-driver",
                str(args.genesis_driver),
                "--fixture",
                str(args.fixture),
                "--output",
                str(args.output / label),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        text = r.stdout + r.stderr
        (args.output / (label + ".log")).write_text(text)
        if failure is None:
            assert r.returncode == 0 and "7 primary signing CLI outcomes passed" in text, text
        else:
            assert r.returncode != 0 and failure in text, text
            assert "SyntaxError" not in text and "CalledProcessError" not in text, text

    run("baseline")
    try:
        for label, (guard, failure) in mutations.items():
            assert original.count(guard) == 1, label
            source.write_text(original.replace(guard, "True"))
            run(label, failure)
    finally:
        source.write_text(original)
        run("restored")
    (args.output / "result.txt").write_text(
        "Input-binding and execution-success deletions permit false delivery; restored guards reject both.\n"
    )
    print("2 CLI delivery semantic controls and restored 7 signing outcomes passed")


if __name__ == "__main__":
    main()
