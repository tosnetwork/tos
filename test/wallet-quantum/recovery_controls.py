"""Require successful wallet receipts to expose deleted recovery state transitions."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = {}
    for name in ("lock", "migrate"):
        out = args.output / name
        out.mkdir(parents=True, exist_ok=True)
        for tree in ("PUBLIC-TEST-ONLY-lms-tree", "PUBLIC-TEST-ONLY-successor-tree"):
            if not (out / tree).exists():
                os.link(args.baseline / "native" / tree, out / tree)
        with (out / "run.log").open("w") as log:
            result = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("test_fee_delivery.py")),
                    "--prepare",
                    "--recovery",
                    "--credit-probe",
                    "--recovery-delete-transition",
                    name,
                    "--output",
                    str(out),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        assert result.returncode != 0
        label = "lock" if name == "lock" else "migration"
        failure = label + " state transition missing"
        assert failure in (out / "run.log").read_text()
        receipt = json.loads((out / "recovery" / f"{name}-wallet.json").read_text())
        assert receipt["success"] and receipt["details"]["exit"] == 0
        assert not receipt["details"]["aborted"]
        results[name] = {
            "runner_exit": result.returncode,
            "semantic_failure": failure,
            "wallet_exit": 0,
            "aborted": False,
        }
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Both transition deletions fail on actual successful wallet receipts")


if __name__ == "__main__":
    main()
