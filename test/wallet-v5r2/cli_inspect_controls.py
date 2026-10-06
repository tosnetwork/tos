"""Require the inspection CLI to enforce the enrolled module data binding."""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_wallet_state.rs"
    original = source.read_text()
    old = "m.account.data_hash == module_data.repr_hash().to_hex_string(),"
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
                str(ROOT / "test/wallet-v5r2/cli_inspect_initial.py"),
                "--cli",
                str(args.cli),
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
            assert result.returncode == 0 and "8 initial inspection CLI outcomes passed" in log, log
        else:
            assert result.returncode != 0 and "('module_data', '')" in log, log

    try:
        build("baseline")
        run("baseline", True)
        source.write_text(original.replace(old, "true,"))
        build("bypass")
        run("bypass", False)
    finally:
        source.write_text(original)
        build("restored")
        run("restored", True)
    (args.output / "result.txt").write_text(
        "Module-data guard deletion admits a substituted module; restored CLI refuses it.\n"
    )
    print("CLI module-data mutation detected; restored 8 inspection outcomes pass")


if __name__ == "__main__":
    main()
