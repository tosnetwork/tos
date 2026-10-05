"""Fault injection for the actual R2 fee candidate; never a deployable profile."""

import json

from cells import from_boc
from native import account_data, outgoing

COMMIT = "  commit();\n"
SOLVENCY = "  throw_unless(2008, amount + reserve <= balance);\n"
SEND = ".store_ref(payload).end_cell(), 3);"
PAD = (
    "  repeat (300) { payload = begin_cell().store_uint(123, 32).store_ref(payload).end_cell(); }\n"
)
FAULTS = {
    "low-gas-cap": [],
    "gas-cap-below-minimum": [],
    "gas-cap-minimum": [],
    "low-gas-cap-unguarded": [
        ("  throw_unless(2017, r2fee_gas_limit() >= r2fee::compute_bound);\n", "")
    ],
    "throw-before-commit": [(COMMIT, "  throw(78);\n" + COMMIT)],
    "throw-after-commit": [(COMMIT, COMMIT + "  throw(77);\n")],
    "gas-before-commit": [(COMMIT, "  set_gas_limit(1);\n" + COMMIT)],
    "gas-after-commit": [(COMMIT, COMMIT + "  set_gas_limit(1);\n")],
    "unfunded-ignore": [(SOLVENCY, "")],
    "unfunded-strict": [(SOLVENCY, ""), (SEND, ".store_ref(payload).end_cell(), 1);")],
    "oversized-ignore": [(COMMIT, COMMIT + PAD)],
    "oversized-control": [(COMMIT, COMMIT + PAD)],
}


def inject(source, name):
    for old, new in FAULTS[name]:
        assert source.count(old) == 1, (name, "ambiguous injection", old)
        source = source.replace(old, new)
    return source


def expected_exit(name):
    if name == "throw-before-commit":
        return 78
    if name == "throw-after-commit":
        return 77
    return -14 if name in ("gas-before-commit", "gas-after-commit", "low-gas-cap-unguarded") else 0


def leaf_balance(shard):
    data, balance = account_data(shard)
    ds = data.slice()
    assert ds.uint(8) == 3
    return ds.uint(32), balance


def verify(name, emulator, initial, external, result, out):
    """Assert safe cases and the intentionally unsafe controls, including replay."""
    if name in ("low-gas-cap", "gas-cap-below-minimum"):
        assert not result["success"] and result.get("vm_exit_code") == 2017, result
        replay = emulator.send(initial, external)
        assert not replay["success"] and replay.get("vm_exit_code") == 2017
        (out / "fault-replay.json").write_text(json.dumps(replay, indent=2) + "\n")
        report = {
            "scope": "Actual candidate rejects insufficient configured gas cap before ACCEPT",
            "fault": name,
            "accepted": False,
            "exit": 2017,
            "replay_accepted": False,
        }
        (out / "fault-results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return
    assert result["success"] and result["details"]["exit"] == expected_exit(name), result
    after = from_boc(result["shard_account"])
    before_leaf, before_balance = leaf_balance(initial)
    leaf, balance = leaf_balance(after)
    assert before_leaf == 0 and balance < before_balance
    rolled_back = name in (
        "throw-before-commit",
        "gas-before-commit",
        "unfunded-strict",
        "low-gas-cap-unguarded",
    )
    assert leaf == (0 if rolled_back else 9), (name, leaf, result)
    messages = outgoing(from_boc(result["transaction"]))
    assert len(messages) == (1 if name in ("oversized-control", "gas-cap-minimum") else 0)
    if name == "unfunded-strict":
        assert result["details"]["aborted"] and not result["details"]["action"]["success"]
        assert result["details"]["action"]["code"] == 37
    elif not rolled_back:
        assert not result["details"]["aborted"]
    replay = emulator.send(after, external)
    (out / "fault-replay.json").write_text(json.dumps(replay, indent=2) + "\n")
    if rolled_back:
        assert replay["success"] and replay["details"]["exit"] == expected_exit(name)
        repeated_leaf, repeated_balance = leaf_balance(from_boc(replay["shard_account"]))
        assert repeated_leaf == 0 and repeated_balance < balance
    else:
        assert not replay["success"] and replay.get("vm_exit_code") == 2004
    report = {
        "scope": "Injected failure semantics, not production-credit or reachability evidence",
        "fault": name,
        "transaction": result["details"],
        "leaf_after": leaf,
        "balance_loss": before_balance - balance,
        "outgoing_count": len(messages),
        "unsafe_repeated_charge_control": rolled_back,
        "replay_accepted": replay["success"],
        "replay_exit": replay.get("vm_exit_code", replay.get("details", {}).get("exit")),
    }
    (out / "fault-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
