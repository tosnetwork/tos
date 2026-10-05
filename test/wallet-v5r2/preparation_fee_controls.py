"""Require semantic fee admission failures after independent preparation guard deletions."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "test/auth-extensions"))
import native  # noqa: E402
from cells import from_boc  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline", type=Path, required=True, help="Successful preparation parity directory"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, options, witness in [
        ("constructor", ["--delete-payload-guard"], "payload_constructor"),
        ("floors", ["--delete-preparation-guard", "floors"], "prepare_module_floor"),
        ("ceiling", ["--delete-preparation-guard", "ceiling"], "above_ceiling"),
    ]:
        out = args.output / name
        out.mkdir(exist_ok=True)
        for tree in ("PUBLIC-TEST-ONLY-lms-tree", "PUBLIC-TEST-ONLY-successor-tree"):
            source = args.baseline / "native" / tree
            assert source.is_file()
            if not (out / tree).exists():
                os.link(source, out / tree)
        with (out / "run.log").open("w") as log:
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "test/wallet-v5r2/test_fee_delivery.py"),
                    "--prepare",
                    "--credit-probe",
                    "--output",
                    str(out),
                    *options,
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        assert result.returncode != 0, "deleted guard escaped the intended negative assertion"
        receipt = json.loads((out / f"negative-{witness}.json").read_text())
        assert receipt["success"] and receipt["details"]["exit"] == 0
        assert not receipt["details"]["aborted"]
        data = native.account_data(from_boc(receipt["shard_account"]))[0].slice()
        assert data.uint(8) == 3 and data.uint(32) == 9
        assert len(native.outgoing(from_boc(receipt["transaction"]))) == 1
        results[name] = {
            "runner_exit": result.returncode,
            "unexpected_fee_acceptance": True,
            "leaf_after": 9,
            "witness": f"negative-{witness}.json",
        }
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("3 preparation fee guard deletions expose accepted sends and leaf consumption")


if __name__ == "__main__":
    main()
