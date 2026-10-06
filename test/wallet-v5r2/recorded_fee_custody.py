"""Match encrypted fee custody output to executed transactions; synthetic proof metadata only."""

import argparse
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "recorded_fee_custody_matches_executed_messages"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--controls", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    journal = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_journal.rs"
    vault = ROOT / "tosctl/src/node-control/contracts/src/lms_fee_vault.rs"
    originals = {p: p.read_text() for p in (journal, vault)}
    cases = [
        (
            "tree_enrollment",
            vault,
            "tree.public_key() == view.fee_public_key()",
            "true",
            "wrong fee tree reached key loading path",
        ),
        (
            "config_binding",
            journal,
            "config_hash: *vault.config_hash(),",
            "config_hash: [0; 32],",
            "protected custody changed executed fee body",
        ),
        (
            "clock_resample",
            vault,
            "            clock(),\n            valid_until,",
            "            view.proven_time(),\n            valid_until,",
            "recorded custody accepted stale clock after key loading",
        ),
    ]
    for name, path, old, _, _ in cases:
        assert originals[path].count(old) == 1, name

    def run(label, witness=None):
        output = args.output / f"{label}.json"
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
                "--",
                "--ignored",
            ],
            env=dict(
                os.environ,
                TOS_V5R2_FEE_FIXTURES=str(args.fixtures.resolve()),
                TOS_V5R2_FEE_OUTPUT=str(output.resolve()),
            ),
            capture_output=True,
            text=True,
            timeout=600,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        if witness:
            assert (
                result.returncode != 0
                and "test result: FAILED" in log
                and f"::{TEST} ... FAILED" in log
                and witness in log
            ), log[-5000:]
        else:
            assert result.returncode == 0 and "1 passed" in log and f"::{TEST} ... ok" in log, log[
                -5000:
            ]
            assert len(json.loads(output.read_text())["messages"]) == 6
        return {"exit": result.returncode, "semantic_witness": witness}

    results = {"baseline": run("baseline")}
    if args.controls:
        try:
            for name, path, old, new, witness in cases:
                path.write_text(originals[path].replace(old, new))
                results[name] = run(name, witness)
                path.write_text(originals[path])
        finally:
            for path, text in originals.items():
                path.write_text(text)
            results["restored"] = run("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Six encrypted fee signatures match executed messages; requested controls pass")


if __name__ == "__main__":
    main()
