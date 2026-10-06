"""Require actual initial preparation to preserve the requested rescue policy."""

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
    source = ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_cmd.rs"
    original = source.read_text()
    old = '"RESCUE_READY" => RescuePolicy::Ready,'
    assert original.count(old) == 1

    def build(label):
        result = subprocess.run(
            [
                "cargo",
                "build",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "tosctl",
                "--features",
                "pq-wallet",
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}-build.log").write_text(log)
        assert result.returncode == 0, log[-3000:]

    def run(label, positive):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "test/wallet-v5r2/cli_prepare_initial.py"),
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
            timeout=600,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        if positive:
            assert result.returncode == 0 and "9 initial preparation CLI outcomes passed" in log, (
                log
            )
        else:
            assert result.returncode != 0 and "CLI prepared wrong rescue policy" in log, log

    try:
        build("baseline")
        run("baseline", True)
        source.write_text(original.replace(old, '"RESCUE_READY" => RescuePolicy::Required,'))
        build("bypass")
        run("bypass", False)
    finally:
        source.write_text(original)
        build("restored")
        run("restored", True)
    (args.output / "result.txt").write_text(
        "Policy mutation changes prepared identity; restored CLI preserves both policies.\n"
    )
    print("CLI policy mutation detected; restored 9 preparation outcomes pass")


if __name__ == "__main__":
    main()
