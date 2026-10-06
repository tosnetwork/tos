"""Require both high-level fee replacement signing gates to fail when removed."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ROOT / "tosctl/src/node-control/contracts/src"
GUARD = "!matches!(action, AuthAction::Configure { fee_replacement: Some(_) })"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    cases = [
        ("wallet_v5r2_wallet_state.rs", "ungated fee rollover signed"),
        ("wallet_v5r2_vault.rs", "opened custody for ungated fee rollover"),
    ]
    originals = {SOURCES / name: (SOURCES / name).read_text() for name, _ in cases}

    def run(label, query):
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
                query,
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    results = {}
    try:
        code, log = run("production", "fee_state_tests")
        assert code == 0, log[-4000:]
        for name, witness in cases:
            for path, source in originals.items():
                path.write_text(source)
            path = SOURCES / name
            source = originals[path]
            assert source.count(GUARD) == 1
            path.write_text(source.replace(GUARD, "true"))
            code, log = run(name, "fee_rollover_cannot")
            assert code != 0 and "panicked at" in log and witness in log, log[-4000:]
            results[name] = {"exit": code, "witness": witness}
    finally:
        for path, source in originals.items():
            path.write_text(source)
        code, log = run("restored", "fee_state_tests")
        assert code == 0, log[-4000:]
        for name in (
            "native_fee_rollover_cannot_bypass_funded_pop_gate",
            "vault_fee_rollover_cannot_open_custody_before_pop_gate",
            "native_same_module_rollover_requires_both_funded_pops",
            "native_migration_requires_both_funded_pops",
        ):
            assert f"{name} ... ok" in log
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Both fee replacement gates fail semantically when removed; restored suite passes")


if __name__ == "__main__":
    main()
