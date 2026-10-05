"""Require exact recorded rent and reject one extra unit of prior-fund loss."""

import argparse
import inspect
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "test/auth-extensions"), str(ROOT / "test/rescue-fee-gate")]
import native  # noqa: E402
from cells import from_boc  # noqa: E402
from funded_recovery import preserve_module_funds  # noqa: E402


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    before = json.loads((args.baseline / "genesis-deployment/module.json").read_text())
    after = json.loads((args.baseline / "recovery/lock-module.json").read_text())
    a = native.account_data(from_boc(before["shard_account"]))
    b = native.account_data(from_boc(after["shard_account"]))
    transaction = from_boc(after["transaction"])
    charge = preserve_module_funds(a, b, transaction)
    assert charge > 0 and a[1] - b[1] == charge, "fixture must exhibit real rent"
    bad = (b[0], b[1] - 1)

    def reject(check):
        try:
            check(a, bad, transaction)
        except AssertionError as error:
            assert "beyond protocol rent" in str(error)
        else:
            raise AssertionError("extra prior-fund loss accepted")

    reject(preserve_module_funds)
    source = inspect.getsource(preserve_module_funds)
    guard = (
        'assert after[1] + collected >= before[1], "module spent prior funds beyond protocol rent"'
    )
    assert source.count(guard) == 1
    namespace = {}
    exec(source.replace(guard, "pass"), namespace)
    assert namespace["preserve_module_funds"](a, bad, transaction) == charge
    reject(preserve_module_funds)
    args.output.write_text(
        json.dumps(
            dict(
                storage_collected=charge,
                actual_loss=a[1] - b[1],
                extra_unit_rejected=True,
                deleted_guard_accepts_extra_loss=True,
                restored_guard_rejects=True,
            ),
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
