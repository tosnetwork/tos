"""TEST ONLY: feed native receipts with synthetic proof metadata to Rust migration signing."""

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verify-execution", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    suffix = ".execution" if args.verify_execution else ""
    log = output.with_suffix(suffix + ".log")
    result_path = output.with_suffix(suffix + ".json")
    assert not log.exists() and not result_path.exists(), "refuse to overwrite gate evidence"
    assert output.exists() == args.verify_execution, "unexpected migration output state"
    test = (
        "recorded_migration_submission_executed"
        if args.verify_execution
        else "recorded_dual_pop_migration_gate"
    )
    env = dict(
        os.environ,
        TOS_V5R2_MIGRATION_FIXTURES=str(args.fixtures.resolve()),
        TOS_V5R2_MIGRATION_OUTPUT=str(output),
    )
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
            "native-wallet-signer",
            "--lib",
            test,
            "--",
            "--ignored",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    text = result.stdout + result.stderr
    log.write_text(text)
    assert result.returncode == 0 and f"{test} ... ok" in text and "1 passed" in text, text[-4000:]
    assert output.is_file() and output.stat().st_size > 7856
    result_path.write_text(
        json.dumps(
            {
                "scope": "Real native execution cells and synthetic proof metadata; fixed PUBLIC test rescue seed only",
                "passed": True,
                "test": test,
                "exit": result.returncode,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
