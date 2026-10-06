"""Inject process death after fee caching and require durable intent recovery."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cli", "genesis-driver", "fee-session-tree", "fixture", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    source = ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_fee_session.rs"
    original = source.read_text()
    anchor = "                let signed = journal.retry_proven_fee(&view, now()?, &intent)?;\n                export(&output_dir, &signed)"
    persisted = '                // Persist the complete intent before any stateful fee signature.\n                put(&output_dir, "pending-intent.boc", &chain_block::write_boc(intent.cell())?)?;'
    assert original.count(anchor) == original.count(persisted) == 1
    injected = original.replace(anchor, "                std::process::exit(73);\n" + anchor)

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

    def run(label, crash, failure=None):
        command = [sys.executable, str(ROOT / "test/wallet-v5r2/cli_fee_session_sign.py")]
        for name in ("cli", "genesis-driver", "fee-session-tree", "fixture"):
            command += ["--" + name, str(getattr(args, name.replace("-", "_")))]
        command += ["--output", str(args.output / label)]
        env = dict(os.environ, TOS_TEST_FEE_EXPORT_CRASH="1" if crash else "0")
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=600)
        log = result.stdout + result.stderr
        (args.output / (label + ".log")).write_text(log)
        if failure:
            assert result.returncode != 0 and failure in log, log
            assert "TimeoutExpired" not in log and "SyntaxError" not in log, log
        else:
            assert result.returncode == 0 and "consumed retry refusal passed" in log, log

    try:
        source.write_text(injected)
        build("crash")
        run("crash", True)
        source.write_text(injected.replace(persisted, ""))
        build("missing-intent")
        run("missing-intent", True, "cached signature lost its persisted intent")
    finally:
        source.write_text(original)
        build("restored")
        run("restored", False)
    (args.output / "result.txt").write_text(
        "Actual process death after cache commit recovers a native-valid funded lock; removing intent persistence fails the named recovery assertion; restored normal retry passes.\n"
    )
    print("Fee export crash recovered; missing-intent mutation detected; restored retry passed")


if __name__ == "__main__":
    main()
