"""Reject active LMS-key reuse before successor preparation or fee-route selection."""

import argparse
import json
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
    source = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_genesis.rs"
    original = source.read_text()
    guard = "candidate.repr_hash() != previous.repr_hash()"
    assert original.count(guard) == 1
    reused = json.loads(args.fixture.read_text())
    key = json.loads(
        (ROOT / "tosctl/src/wallet-pq-signer/tests/fixtures/native-fee-recovery.json").read_text()
    )["public_key_hex"]
    reused["input"]["fee_public_key"] = key
    reused["input"]["fee_tree_id"] = "a6" * 32
    fixture = args.output / "PUBLIC-TEST-ONLY-reused-fee-key.json"
    fixture.write_text(json.dumps(reused, indent=2) + "\n")
    cargo = ["cargo", "--manifest-path", str(ROOT / "tosctl/src/Cargo.toml")]

    def run(label, command, expected=None):
        result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
        log = result.stdout + result.stderr
        (args.output / (label + ".log")).write_text(log)
        if expected is None:
            assert result.returncode == 0, log[-5000:]
        else:
            assert result.returncode != 0 and expected in log, log[-5000:]
            assert (
                "could not compile" not in log
                and "TimeoutExpired" not in log
                and "SyntaxError" not in log
            ), log[-5000:]
        return log

    def build(label):
        run(
            label,
            [cargo[0], "build", *cargo[1:], "--locked", "-p", "tosctl", "--features", "pq-wallet"],
        )

    def sdk(label, selected, expected=None):
        log = run(
            label,
            [
                cargo[0],
                "test",
                *cargo[1:],
                "--locked",
                "-p",
                "contracts",
                "--features",
                "native-wallet-vault",
                "--lib",
                selected,
            ],
            expected,
        )
        assert "preparation_rejects_active_lms_key_in_another_vault" in log
        if expected is None:
            for name in (
                "preparation_rejects_active_lms_key_in_another_vault",
                "native_preparation_signing_binds_successor_and_current_rescue",
                "native_migration_requires_both_funded_pops",
                "proven_wallet_requires_installed_successor",
            ):
                assert f"::{name} ... ok" in log, f"missing SDK gate: {name}"
            assert "test result: ok." in log, log[-2000:]

    def cli(label, reuse, expected=None):
        command = [sys.executable, str(ROOT / "test/wallet-v5r2/cli_sign_primary.py")]
        for name in ("cli", "genesis-driver", "fee-session-tree"):
            command += ["--" + name, str(getattr(args, name.replace("-", "_")))]
        command += [
            "--fixture",
            str(fixture if reuse else args.fixture),
            "--output",
            str(args.output / label),
        ]
        command += (
            ["--expect-fee-reuse-refusal"]
            if reuse
            else ["--successor-fee-fixture", str(args.successor_fee_fixture)]
        )
        log = run(label, command, expected)
        if expected is None:
            wanted = (
                "Reused active LMS key refused before output, custody and reservation"
                if reuse
                else "Prepared successor, independent custody, 3 funded POPs and authenticated receipts passed"
            )
            assert wanted in log, log

    try:
        source.write_text(original.replace(guard, "true"))
        sdk(
            "deleted-sdk",
            "preparation_rejects_active_lms_key_in_another_vault",
            "preparation accepted reused active LMS key",
        )
        build("deleted-cli-build")
        cli("deleted-cli", True, "preparation accepted reused active LMS key")
    finally:
        source.write_text(original)
        sdk("restored-sdk", "proven_getters::fee_state_tests")
        build("restored-cli-build")
        cli("restored-reuse-refusal", True)
        cli("restored-successor", False)
    (args.output / "result.txt").write_text(
        "Shared active-LMS-key guard deletion fails both SDK and CLI assertions; restored code rejects reuse and completes fresh successor POP/receipts. Historical key reuse outside the active tuple remains a separate custody-history gate.\n"
    )
    print("Active LMS-key reuse guard: SDK and CLI red/green controls passed")


if __name__ == "__main__":
    main()
