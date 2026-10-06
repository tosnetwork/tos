"""Require actual fee-session CLI restore barriers and exclusive ownership."""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--fee-session-tree", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_journal.rs"
    original = source.read_text()
    cases = [
        (
            "barrier",
            "if let Some(barrier) = self.barrier {",
            "if let Some(barrier) = None::<RestoreBarrier> {",
            "session skipped restore barrier",
        ),
        ("exclusive", "file.try_lock_exclusive()?;", "", "concurrent journal owner accepted"),
    ]

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

    def run(label, failure=None):
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "test/wallet-v5r2/cli_fee_session.py"),
                "--cli",
                str(args.cli),
                "--fee-session-tree",
                str(args.fee_session_tree),
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
        if failure is None:
            assert (
                result.returncode == 0
                and "Fee session restore barrier, exclusive owner and reopen checks passed" in log
            ), log
        else:
            assert result.returncode != 0 and failure in log, log
            assert "TimeoutExpired" not in log and "SyntaxError" not in log, log

    try:
        build("baseline")
        run("baseline")
        for label, old, replacement, failure in cases:
            assert original.count(old) == 1, label
            source.write_text(original.replace(old, replacement))
            build(label)
            run(label, failure)
    finally:
        source.write_text(original)
        build("restored")
        run("restored")
    (args.output / "result.txt").write_text(
        "Restore-barrier and exclusive-lock deletions fail their specific CLI assertions; restored startup and refusal checks pass.\n"
    )
    print("2 fee-session lifecycle mutations detected; restored startup and refusal checks pass")


if __name__ == "__main__":
    main()
