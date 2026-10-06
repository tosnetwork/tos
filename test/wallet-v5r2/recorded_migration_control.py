"""Require recorded execution to reject a different gated migration signature."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
from cells import Cell, from_boc  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    body = from_boc(args.submission.read_bytes())
    signature = body.refs[1]
    changed = Cell(
        bits=("1" if signature.bits[0] == "0" else "0") + signature.bits[1:], refs=signature.refs
    )
    changed_body = Cell(bits=body.bits, refs=[body.refs[0], changed])
    bad = args.output / "different-submission.boc"
    bad.write_bytes(changed_body.boc())
    source = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_recorded_migration_tests.rs"
    original = source.read_text()
    witness = "executed migration differs from gated signature"
    at = original.index(json.dumps(witness))
    start = original.rfind("    assert_eq!(", 0, at)
    end = original.index(");", at) + 2
    assert start >= 0 and original.count(witness) == 1

    def run(label, submission):
        env = dict(
            os.environ,
            TOS_V5R2_MIGRATION_FIXTURES=str(args.fixtures.resolve()),
            TOS_V5R2_MIGRATION_OUTPUT=str(submission.resolve()),
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
                "recorded_migration_submission_executed",
                "--",
                "--ignored",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    try:
        code, log = run("baseline", args.submission)
        assert code == 0 and "1 passed" in log, log[-4000:]
        code, log = run("different-signature", bad)
        assert code != 0 and witness in log and " ... FAILED" in log, log[-4000:]
        source.write_text(original[:start] + original[end:])
        code, log = run("deleted-binding", bad)
        assert code == 0 and "1 passed" in log, log[-4000:]
    finally:
        source.write_text(original)
        code, log = run("restored-positive", args.submission)
        assert code == 0 and "1 passed" in log, log[-4000:]
        code, log = run("restored-negative", bad)
        assert code != 0 and witness in log and " ... FAILED" in log, log[-4000:]
    (args.output / "results.json").write_text(
        json.dumps(
            {
                "different_signature_rejected": True,
                "deleted_binding_admits_it": True,
                "restored_positive_and_negative": True,
            },
            indent=2,
        )
        + "\n"
    )
    print("Recorded migration signature binding detects substitution and guard deletion")


if __name__ == "__main__":
    main()
