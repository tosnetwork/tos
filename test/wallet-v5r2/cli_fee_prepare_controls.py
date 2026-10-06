"""Require successor template pinning and preparation funding checks."""

import argparse
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
    command_source = (
        ROOT / "tosctl/src/node-control/commands/src/commands/nodectl/wallet_pq_fee_session.rs"
    )
    manifest_source = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_manifest.rs"
    originals = {path: path.read_text() for path in (command_source, manifest_source)}
    cases = [
        (
            "template",
            manifest_source,
            "*g.wallet_init().repr_hash().as_array() == expected_basechain_wallet,",
            "true,",
            "preparation accepted wrong_template",
        ),
        (
            "funding",
            command_source,
            "value > request.deployment_value(),",
            "true,",
            "preparation accepted insufficient_funding",
        ),
    ]
    cases.append(
        (
            "required-policy",
            command_source,
            "context.read(if needs_primary_policy { &[48] } else { &[] })",
            "context.read(if preparation.is_some() { &[48] } else { &[] })",
            "REQUIRED preparation depended on PRIMARY policy",
        )
    )
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
        for name in ("cli", "genesis-driver", "fee-session-tree", "fixture"):
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
                and "6 preparation refusals, exact retry and both native successor deployments passed"
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
        "Template pin and preparation funding deletions fail named assertions; restored native deployments pass.\n"
    )
    print("3 preparation semantic mutations detected; restored native deployments passed")


if __name__ == "__main__":
    main()
