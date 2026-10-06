"""Require proven-state gates before and after asynchronous Vault signer loading."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "vault_wallet_signing_rechecks_proofs_after_loading"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    path = ROOT / "tosctl/src/node-control/contracts/src/wallet_v5r2_vault.rs"
    original = path.read_text()
    cases = [
        (
            "primary_preflight",
            "view.primary_request(policy, before, valid_until, actions.clone())?;",
            "",
            "opened custody before policy validation",
        ),
        (
            "rescue_preflight",
            "view.rescue_request(before, valid_until, action.clone())?;",
            "",
            "opened custody before rescue validation",
        ),
        (
            "clock_regression",
            "after >= before",
            "true",
            "accepted regressed clock after custody load",
        ),
        (
            "primary_recheck",
            "view.sign_primary_submission(policy, after,",
            "view.sign_primary_submission(policy, before,",
            "accepted stale proof after custody load",
        ),
        (
            "rescue_recheck",
            "view.sign_rescue_submission(after,",
            "view.sign_rescue_submission(before,",
            "accepted rescue stale proof after custody load",
        ),
        (
            "migration_preflight",
            "!matches!(action, AuthAction::Migrate { .. })",
            "true",
            "opened custody for ungated migration",
        ),
    ]
    for name, old, _, _ in cases:
        assert original.count(old) == 1, name

    def run(label):
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
                "native-wallet-vault",
                "--lib",
                TEST,
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        code, log = run(label)
        assert code == 0 and "1 passed; 0 failed" in log and TEST in log, log[-4000:]

    results = {}
    try:
        positive("baseline")
        for name, old, new, witness in cases:
            path.write_text(original.replace(old, new))
            code, log = run(name)
            assert code != 0 and "test result: FAILED" in log and witness in log, log[-4000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(original)
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} proven Vault controls detected; restored test passes")


if __name__ == "__main__":
    main()
