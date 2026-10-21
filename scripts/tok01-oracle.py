#!/usr/bin/env python3
"""Independently check TOK-01 receipts and mutate copies for red controls."""

import argparse
import base64
import copy
import json
from pathlib import Path

from pytosiq_core import Cell


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def check_field(row):
    require(row["getter"] == row["rpc_or_expected"], f"field mismatch: {row['field']}")
    require(row["pass"] is True, f"field marked failed: {row['field']}")


def check_supply(row):
    require(row["supply"] == row["expected_supply"], "unexpected supply")
    require(sum(row["balances"]) == row["supply"], "wallet sum differs from supply")
    require(all(b >= 0 for b in row["balances"]), "negative wallet balance")
    require(row["sum"] == sum(row["balances"]), "incorrect recorded wallet sum")
    require(row["pass"] is True, "invariant marked failed")


def check_bounce(row):
    require(
        row["incoming"]
        == row["returned"]
        + row["transaction_fees"]
        - row["storage_fees_from_existing_balance"]
        + row["forwarding_remainder"],
        "bounce accounting mismatch",
    )
    require(len(row["checks"]) == 2, "bounce checks missing")
    for field in row["checks"]:
        check_field(field)


def check_tx(tx):
    observed = Cell.one_from_boc(base64.b64decode(tx["data"])).hash
    require(observed == base64.b64decode(tx["transaction_id"]["hash"]), "transaction hash mismatch")
    require(
        all(
            key in tx["block_id"]
            for key in ("root_hash", "file_hash", "seqno", "workchain", "shard")
        ),
        "full block ID missing",
    )


def load(directory, name):
    return [json.loads(line) for line in (directory / name).read_text().splitlines()]


def verify(directory, records=None):
    def read(name):
        return load(directory, name) if records is None else records[name]

    (summary,) = read("summary.jsonl")
    require(summary["pass"] and not summary["failures"], "lifecycle reported failures")
    steps = read("steps.jsonl")
    require(len(steps) == 13 and len(summary["steps"]) == 13, "incomplete lifecycle")
    for row in read("checks.jsonl"):
        check_field(row)
    invariants = read("invariants.jsonl")
    require(len(invariants) == 13, "missing per-step invariant")
    for row in invariants:
        check_supply(row)
    bounces = read("bounce.jsonl")
    require(len(bounces) == 2, "missing refused-operation bounce")
    for row in bounces:
        check_bounce(row)
    for step in steps:
        require(bool(step["comparisons"]), "missing getter/RPC comparisons")
        for transactions in step["transactions"].values():
            for tx in transactions:
                check_tx(tx)
    (notifications,) = read("notifications.jsonl")
    require(len(notifications["transactions"]) == 1, "notification absent")
    return {"pass": True, "steps": len(steps), "invariants": len(invariants)}


def controls(directory):
    # Use measured receipts without modifying any retained file. Each fixture is
    # green before mutation, red after mutation, and green after restoration.
    receipts = []

    def exercise(name, original, validate, mutate):
        validate(original)
        changed = copy.deepcopy(original)
        mutate(changed)
        try:
            validate(changed)
        except (AssertionError, KeyError, ValueError) as error:
            receipts.append(
                {
                    "control": name,
                    "baseline_exit": 0,
                    "mutant_exit": 1,
                    "error": str(error),
                    "restored_exit": 0,
                }
            )
        else:
            raise AssertionError(f"Control did not turn red: {name}")
        validate(original)

    supply = next(
        row for row in load(directory, "invariants.jsonl") if row["supply"] > 0 and row["pass"]
    )
    exercise(
        "wrong expected supply",
        supply,
        check_supply,
        lambda row: row.update(expected_supply=row["expected_supply"] + 1),
    )
    exercise(
        "wallet balance omitted",
        supply,
        check_supply,
        lambda row: row["balances"].__setitem__(0, row["balances"][0] + 1),
    )

    def negative(row):
        row["balances"] = [-1, row["supply"] + 1, 0]

    exercise("negative balance with conserved sum", supply, check_supply, negative)
    exercise("wrong recorded sum", supply, check_supply, lambda row: row.update(sum=row["sum"] + 1))
    exercise(
        "failed invariant flag",
        supply,
        check_supply,
        lambda row: row.__setitem__("pass", False),
    )
    checks = load(directory, "checks.jsonl")
    for label in ("total_supply", "notification payload", "refused operation persistent data"):
        field = next(row for row in checks if row["field"].startswith(label) and row["pass"])
        exercise(
            label, field, check_field, lambda row: row.update(rpc_or_expected="deliberately wrong")
        )
    field = next(row for row in checks if row["pass"])
    exercise(
        "failed comparison flag", field, check_field, lambda row: row.__setitem__("pass", False)
    )
    bounce = next(
        row for row in load(directory, "bounce.jsonl") if all(c["pass"] for c in row["checks"])
    )
    exercise(
        "bounce value off by one",
        bounce,
        check_bounce,
        lambda row: row.update(returned=row["returned"] + 1),
    )
    exercise("bounce check omitted", bounce, check_bounce, lambda row: row["checks"].pop())
    exercise(
        "bounce receipt missing",
        bounce,
        check_bounce,
        lambda row: row["checks"][1].update(getter=0),
    )
    tx = next(
        tx
        for step in load(directory, "steps.jsonl")
        for rows in step["transactions"].values()
        for tx in rows
    )
    exercise(
        "wrong transaction hash",
        tx,
        check_tx,
        lambda row: row["transaction_id"].update(hash=base64.b64encode(bytes(32)).decode()),
    )
    exercise("incomplete block ID", tx, check_tx, lambda row: row["block_id"].pop("file_hash"))
    records = {
        name: load(directory, name)
        for name in (
            "summary.jsonl",
            "steps.jsonl",
            "checks.jsonl",
            "invariants.jsonl",
            "bounce.jsonl",
            "notifications.jsonl",
        )
    }

    def full(data):
        return verify(directory, data)

    for label, mutate in (
        (
            "failed lifecycle summary",
            lambda data: data["summary.jsonl"][0].__setitem__("pass", False),
        ),
        ("missing lifecycle step", lambda data: data["steps.jsonl"].pop()),
        ("missing summary step", lambda data: data["summary.jsonl"][0]["steps"].pop()),
        ("missing invariant receipt", lambda data: data["invariants.jsonl"].pop()),
        ("missing bounce receipt", lambda data: data["bounce.jsonl"].pop()),
        (
            "missing comparison table",
            lambda data: data["steps.jsonl"][0].__setitem__("comparisons", []),
        ),
        (
            "missing notification receipt",
            lambda data: data["notifications.jsonl"][0]["transactions"].clear(),
        ),
    ):
        exercise(label, records, full, mutate)
    return receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--red-controls", action="store_true")
    args = parser.parse_args()
    result = controls(args.evidence) if args.red_controls else verify(args.evidence)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
