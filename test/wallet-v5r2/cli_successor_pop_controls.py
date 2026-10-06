"""Require successor operation, proven module and retained POP binding gates."""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in (
        "cli",
        "genesis-driver",
        "fee-session-tree",
        "successor-fee-fixture",
        "fixture",
        "output",
    ):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    command_source = (
        ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_fee_session.rs"
    )
    context_source = (
        ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_inspect_cmd.rs"
    )
    pop_source = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_pop.rs"
    originals = {path: path.read_text() for path in (command_source, context_source, pop_source)}
    cases = [
        (
            "operation",
            command_source,
            "context.successor().is_none()",
            "true",
            "successor authority preflight gate missing",
        ),
        (
            "module",
            context_source,
            "account.account().get_data() == expected.data",
            "true",
            "successor POP accepted changed module data",
        ),
        (
            "retained",
            pop_source,
            "request.cell.repr_hash() == cell.repr_hash()",
            "true",
            "receipt CLI accepted wrong_enrollment",
        ),
    ]
    for label, path, old, _, _ in cases:
        assert originals[path].count(old) == 1, label

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
        (args.output / (label + "-build.log")).write_text(log)
        assert result.returncode == 0, log[-3000:]

    def run(label, failure=None):
        command = [
            sys.executable,
            str(ROOT / "test/wallet-v5r2/cli_sign_primary.py"),
            "--fee-session-prepare",
        ]
        for name in (
            "cli",
            "genesis-driver",
            "fee-session-tree",
            "successor-fee-fixture",
            "fixture",
        ):
            command += ["--" + name, str(getattr(args, name.replace("-", "_")))]
        command += ["--output", str(args.output / label)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        log = result.stdout + result.stderr
        (args.output / (label + ".log")).write_text(log)
        if failure:
            assert result.returncode != 0 and failure in log, log
            assert "TimeoutExpired" not in log and "SyntaxError" not in log, log
        else:
            assert (
                result.returncode == 0
                and "Prepared successor, independent custody, 3 funded POPs and authenticated receipts passed"
                in log
            ), log

    try:
        build("baseline")
        run("baseline")
        for label, path, old, replacement, failure in cases:
            for target, original in originals.items():
                target.write_text(original)
            path.write_text(originals[path].replace(old, replacement))
            build(label)
            run(label, failure)
    finally:
        for path, original in originals.items():
            path.write_text(original)
        build("restored")
        run("restored")
    (args.output / "result.txt").write_text(
        "Successor preflight, module-data and retained-challenge binding mutations fail named assertions; restored native deployment, POP and receipts pass.\n"
    )
    print("3 successor POP semantic mutations detected; restored native flow passed")


if __name__ == "__main__":
    main()
