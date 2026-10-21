#!/usr/bin/env python3
"""Independently check TOK-01 receipts and mutate copies for red controls."""

import argparse
import base64
import copy
import json
import re
from pathlib import Path

from pytosiq_core import Cell
from pytosiq_core.tlb.transaction import Transaction

# Independent acceptance contract: matching counts alone cannot establish coverage.
REQUIRED_STEPS = [
    "token deploy",
    "collection deploy",
    "mint 1000",
    "mint 100",
    "transfer existing wallet",
    "transfer undeployed wallet",
    "transfer payload notification",
    "insufficient balance",
    "burn",
    "admin change",
    "NFT mint",
    "NFT transfer",
    "NFT non-owner refused",
]

# The outcome each step must produce on chain. The verifier holds this table itself so a
# runner cannot pass by recording whatever exit code it observed as the expected one.
EXPECTED_EXIT = {"insufficient balance": 706, "NFT non-owner refused": 401}
SOURCE_HEAD = re.compile(r"^[0-9a-f]{40}$")


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


def decoded_outcome(tx):
    """Compute exit, aborted flag and action result read from the hash-checked BOC itself."""
    parsed = Transaction.deserialize(Cell.one_from_boc(base64.b64decode(tx["data"])).begin_parse())
    description = parsed.description
    compute = getattr(description, "compute_ph", None)
    require(getattr(compute, "exit_code", None) is not None, "target has no compute phase")
    action = getattr(description, "action", None)
    return {
        "exit_code": compute.exit_code,
        "aborted": bool(description.aborted),
        "action_success": None if action is None else bool(action.success),
    }


def check_outcome(step):
    """The target transaction's own phases decide the outcome, not the runner's summary."""
    expected = EXPECTED_EXIT.get(step["step"], 0)
    require(
        step["expected_exit"] == expected,
        "runner expected outcome differs from the lifecycle contract",
    )
    target = step["target"]
    decoded = decoded_outcome(target)
    require(
        decoded["exit_code"] == expected,
        "target compute exit differs from the expected outcome",
    )
    require(decoded["aborted"] is (expected != 0), "target aborted flag differs from the outcome")
    if expected == 0 and decoded["action_success"] is not None:
        require(decoded["action_success"] is True, "target action phase failed")
    # The RPC rendering the runner compared against must agree with the decoded BOC.
    require(
        target["compute"]["exit_code"] == decoded["exit_code"]
        and bool(target["aborted"]) is decoded["aborted"]
        and (target.get("action") or {}).get("success") == decoded["action_success"],
        "RPC outcome rendering disagrees with the decoded transaction",
    )


def check_sender_message(step):
    """The step's message must appear among the sender's own outgoing messages."""
    sender = step.get("sender")
    require(sender, "step sender missing")
    sent = [
        message
        for tx in step["transactions"].get(sender, [])
        for message in tx.get("out_msgs", [])
        if message.get("hash") == step.get("message_hash")
    ]
    require(len(sent) == 1, "step message missing from the sender's outgoing messages")
    require(sent[0].get("destination"), "step message has no destination")


def check_provenance(provenance, summary):
    """Evidence counts only when the run that wrote it finished on an unchanged clean head."""
    require(provenance is not None, "provenance missing")
    require(provenance.get("completed") is True, "run did not complete on a clean source tree")
    head = provenance.get("source_head")
    require(isinstance(head, str) and SOURCE_HEAD.match(head), "source head is not a commit")
    require(provenance.get("source_head_after") == head, "source head changed during the run")
    require(
        provenance.get("run_id") and provenance["run_id"] == summary.get("run_id"),
        "provenance does not belong to this run",
    )
    require(isinstance(provenance.get("global_id"), int), "network identity missing")


def load(directory, name):
    return [json.loads(line) for line in (directory / name).read_text().splitlines()]


def load_object(directory, name):
    path = directory / name
    return json.loads(path.read_text()) if path.exists() else None


def verify(directory, records=None, expect_source_head=None, expect_global_id=None):
    def read(name):
        return load(directory, name) if records is None else records[name]

    def read_object(name):
        return load_object(directory, name) if records is None else records.get(name)

    (summary,) = read("summary.jsonl")
    provenance = read_object("provenance.json")
    check_provenance(provenance, summary)
    if expect_source_head is not None:
        require(
            provenance["source_head"] == expect_source_head,
            "evidence was sealed at another source head",
        )
    if expect_global_id is not None:
        require(provenance["global_id"] == expect_global_id, "evidence comes from another network")
    require(summary["pass"] and not summary["failures"], "lifecycle reported failures")
    steps = read("steps.jsonl")
    require([step["step"] for step in steps] == REQUIRED_STEPS, "incorrect lifecycle steps")
    require(summary["steps"] == REQUIRED_STEPS, "incorrect summary steps")
    for row in read("checks.jsonl"):
        check_field(row)
    invariants = read("invariants.jsonl")
    require([row["step"] for row in invariants] == REQUIRED_STEPS, "incorrect invariant steps")
    for row in invariants:
        check_supply(row)
    bounces = read("bounce.jsonl")
    require(len(bounces) == 2, "missing refused-operation bounce")
    for row in bounces:
        check_bounce(row)
    for step in steps:
        require(bool(step["comparisons"]), "missing getter/RPC comparisons")
        target = step["target"]
        check_tx(target)
        destination_transactions = step["transactions"].get(step["destination"], [])
        require(target in destination_transactions, "destination transaction missing from step")
        require(
            (target.get("in_msg") or {}).get("hash") == step.get("message_hash"),
            "destination transaction did not consume the step's message",
        )
        check_sender_message(step)
        check_outcome(step)
        for transactions in step["transactions"].values():
            for tx in transactions:
                check_tx(tx)
    (notifications,) = read("notifications.jsonl")
    require(len(notifications["transactions"]) == 1, "notification absent")
    return {
        "pass": True,
        "steps": len(steps),
        "invariants": len(invariants),
        "source_head": provenance["source_head"],
        "global_id": provenance["global_id"],
        "run_id": provenance["run_id"],
    }


def exercise(receipts, name, original, validate, mutate, reason):
    """Green before mutation, red for the stated reason after it, green after restoration."""
    validate(original)
    changed = copy.deepcopy(original)
    mutate(changed)
    try:
        validate(changed)
    except (AssertionError, KeyError, ValueError) as error:
        if reason not in str(error):
            raise AssertionError(
                f"Control {name} turned red for another reason: {error!r}; expected {reason!r}"
            ) from error
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


def controls(directory):
    # Use measured receipts without modifying any retained file.
    receipts = []

    def exercise(name, original, validate, mutate, reason):
        globals()["exercise"](receipts, name, original, validate, mutate, reason)

    supply = next(
        row for row in load(directory, "invariants.jsonl") if row["supply"] > 0 and row["pass"]
    )
    exercise(
        "wrong expected supply",
        supply,
        check_supply,
        lambda row: row.update(expected_supply=row["expected_supply"] + 1),
        "unexpected supply",
    )
    exercise(
        "wallet balance omitted",
        supply,
        check_supply,
        lambda row: row["balances"].__setitem__(0, row["balances"][0] + 1),
        "wallet sum differs from supply",
    )

    def negative(row):
        row["balances"] = [-1, row["supply"] + 1, 0]

    exercise("negative balance with conserved sum", supply, check_supply, negative, "negative")
    exercise(
        "wrong recorded sum",
        supply,
        check_supply,
        lambda row: row.update(sum=row["sum"] + 1),
        "incorrect recorded wallet sum",
    )
    exercise(
        "failed invariant flag",
        supply,
        check_supply,
        lambda row: row.__setitem__("pass", False),
        "invariant marked failed",
    )
    checks = load(directory, "checks.jsonl")
    for label in ("total_supply", "notification payload", "refused operation persistent data"):
        field = next(row for row in checks if row["field"].startswith(label) and row["pass"])
        exercise(
            label,
            field,
            check_field,
            lambda row: row.update(rpc_or_expected="deliberately wrong"),
            "field mismatch",
        )
    field = next(row for row in checks if row["pass"])
    exercise(
        "failed comparison flag",
        field,
        check_field,
        lambda row: row.__setitem__("pass", False),
        "field marked failed",
    )
    bounce = next(
        row for row in load(directory, "bounce.jsonl") if all(c["pass"] for c in row["checks"])
    )
    exercise(
        "bounce value off by one",
        bounce,
        check_bounce,
        lambda row: row.update(returned=row["returned"] + 1),
        "bounce accounting mismatch",
    )
    exercise(
        "bounce check omitted",
        bounce,
        check_bounce,
        lambda row: row["checks"].pop(),
        "bounce checks missing",
    )
    exercise(
        "bounce receipt missing",
        bounce,
        check_bounce,
        lambda row: row["checks"][1].update(getter=0),
        "field mismatch",
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
        "transaction hash mismatch",
    )
    exercise(
        "incomplete block ID",
        tx,
        check_tx,
        lambda row: row["block_id"].pop("file_hash"),
        "full block ID missing",
    )
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
    records["provenance.json"] = load_object(directory, "provenance.json")

    def full(data):
        return verify(directory, data)

    def tamper_target(mutate):
        # The runner retains the same transaction as the step's target and under the
        # destination account; a tampered outcome must be tampered in both places.
        def apply(data):
            step = data["steps.jsonl"][0]
            for tx in [step["target"], *step["transactions"][step["destination"]]]:
                mutate(tx)

        return apply

    def swap_target_with(index):
        # A genuine transaction from another step, consistent in hash and rendering, but
        # with the wrong decoded outcome for this step.
        def apply(data):
            step = data["steps.jsonl"][0]
            donor = data["steps.jsonl"][index]["target"]
            for tx in [step["target"], *step["transactions"][step["destination"]]]:
                for key in ("data", "transaction_id", "compute", "aborted", "action"):
                    tx[key] = copy.deepcopy(donor.get(key))
                tx["in_msg"] = {**(tx.get("in_msg") or {}), "hash": step["message_hash"]}

        return apply

    for label, mutate, reason in (
        (
            "failed lifecycle summary",
            lambda data: data["summary.jsonl"][0].__setitem__("pass", False),
            "lifecycle reported failures",
        ),
        (
            "duplicated lifecycle step",
            lambda data: data["steps.jsonl"].__setitem__(8, copy.deepcopy(data["steps.jsonl"][7])),
            "incorrect lifecycle steps",
        ),
        (
            "renamed summary step",
            lambda data: data["summary.jsonl"][0]["steps"].__setitem__(8, "substituted operation"),
            "incorrect summary steps",
        ),
        (
            "empty step transactions",
            lambda data: data["steps.jsonl"][0].__setitem__("transactions", {}),
            "destination transaction missing",
        ),
        (
            "wrong destination",
            lambda data: data["steps.jsonl"][0].__setitem__("destination", "missing destination"),
            "destination transaction missing",
        ),
        (
            "target not the step's message",
            lambda data: data["steps.jsonl"][0].__setitem__("message_hash", "another message"),
            "did not consume the step's message",
        ),
        (
            "runner expected outcome tampered",
            lambda data: data["steps.jsonl"][7].__setitem__("expected_exit", 0),
            "runner expected outcome differs",
        ),
        (
            "RPC compute exit tampered",
            tamper_target(lambda tx: tx["compute"].__setitem__("exit_code", 1)),
            "RPC outcome rendering disagrees",
        ),
        (
            "RPC aborted flag tampered",
            tamper_target(lambda tx: tx.__setitem__("aborted", True)),
            "RPC outcome rendering disagrees",
        ),
        (
            "RPC action result tampered",
            tamper_target(lambda tx: tx.__setitem__("action", {"success": False})),
            "RPC outcome rendering disagrees",
        ),
        (
            "target transaction swapped for a refused one",
            swap_target_with(7),
            "target compute exit differs",
        ),
        (
            "step message absent from the sender's outgoing messages",
            lambda data: [
                tx.__setitem__("out_msgs", [])
                for tx in data["steps.jsonl"][0]["transactions"][data["steps.jsonl"][0]["sender"]]
            ],
            "missing from the sender's outgoing messages",
        ),
        (
            "provenance missing",
            lambda data: data.__setitem__("provenance.json", None),
            "provenance missing",
        ),
        (
            "run not completed",
            lambda data: data["provenance.json"].__setitem__("completed", False),
            "did not complete",
        ),
        (
            "source head changed during the run",
            lambda data: data["provenance.json"].__setitem__("source_head_after", "0" * 40),
            "source head changed",
        ),
        (
            "provenance of another run",
            lambda data: data["provenance.json"].__setitem__("run_id", "another run"),
            "does not belong to this run",
        ),
        (
            "missing lifecycle step",
            lambda data: data["steps.jsonl"].pop(),
            "incorrect lifecycle steps",
        ),
        (
            "missing summary step",
            lambda data: data["summary.jsonl"][0]["steps"].pop(),
            "incorrect summary steps",
        ),
        (
            "missing invariant receipt",
            lambda data: data["invariants.jsonl"].pop(),
            "incorrect invariant steps",
        ),
        (
            "missing bounce receipt",
            lambda data: data["bounce.jsonl"].pop(),
            "missing refused-operation bounce",
        ),
        (
            "missing comparison table",
            lambda data: data["steps.jsonl"][0].__setitem__("comparisons", []),
            "missing getter/RPC comparisons",
        ),
        (
            "missing notification receipt",
            lambda data: data["notifications.jsonl"][0]["transactions"].clear(),
            "notification absent",
        ),
    ):
        exercise(label, records, full, mutate, reason)
    return receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--red-controls", action="store_true")
    parser.add_argument("--expect-source-head", help="Commit the evidence must have been sealed at")
    parser.add_argument(
        "--expect-global-id", type=int, help="Network identity the evidence must come from"
    )
    args = parser.parse_args()
    result = (
        controls(args.evidence)
        if args.red_controls
        else verify(
            args.evidence,
            expect_source_head=args.expect_source_head,
            expect_global_id=args.expect_global_id,
        )
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
