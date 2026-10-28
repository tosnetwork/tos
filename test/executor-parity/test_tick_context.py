"""Corrupt actual tick/tock artifacts and delete workflow obligations."""

import argparse
import copy
import json
from pathlib import Path

import tick_context

RUN = "python3 test/executor-parity/tick_context.py --native build/emulator/libemulator.so --rust tosctl/src/target/release/libtos_emulator.so --output result/tick-context"
CONTROLS = "python3 test/executor-parity/test_tick_context.py --artifacts result/tick-context"
FINAL = tuple(
    f"cmp artifacts/epoch-replay-x86-64/tick-context/{side}/outcomes.json artifacts/epoch-replay-arm64/tick-context/{side}/outcomes.json"
    for side in ("native", "rust")
)


def workflow_contract(text):
    replay, compare = text.split("  compare:", 1)
    for arch in ("x86-64", "arm64"):
        assert f"          - arch: {arch}\n" in replay
    for command in (RUN, CONTROLS):
        assert "          " + command + "\n" in replay
    for command in FINAL:
        assert "          " + command + "\n" in compare


def rejected(function):
    try:
        function()
    except AssertionError:
        return
    raise AssertionError("control did not detect corruption")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    native = json.loads((args.artifacts / "native/outcomes.json").read_text())
    rust = json.loads((args.artifacts / "rust/outcomes.json").read_text())
    tick_context.compare_reports(native, rust)
    count = 0
    for field in ("transaction", "account", "shard_account"):
        changed = copy.deepcopy(native)
        changed[0][field] = "0" * 64
        rejected(lambda: tick_context.compare_reports(changed, changed))
        count += 1
    for field in ("total", "storage"):
        changed = copy.deepcopy(native)
        changed[0]["details"][field] += 1
        rejected(lambda: tick_context.compare_reports(changed, changed))
        count += 1
    for field in ("balance", "paid", "due", "lt"):
        changed = copy.deepcopy(native)
        changed[0]["details"]["account"][field] += 1
        rejected(lambda: tick_context.compare_reports(changed, changed))
        count += 1
    changed = copy.deepcopy(native)
    changed[0]["details"]["compute"]["gas"] += 1
    rejected(lambda: tick_context.compare_reports(changed, changed))
    count += 1
    changed = copy.deepcopy(native)
    future = next(row for row in changed if not row["success"])
    future["stage"] = "other"
    rejected(lambda: tick_context.compare_reports(changed, changed))
    count += 1
    for changed in (native[:-1], native[::-1], native + native[:1]):
        rejected(lambda: tick_context.compare_reports(changed, changed))
        count += 1
    changed = copy.deepcopy(rust)
    changed[0]["transaction"] = "0" * 64
    rejected(lambda: tick_context.compare_reports(native, changed))
    count += 1
    workflow = (tick_context.ROOT / ".github/workflows/epoch-replay.yml").read_text()
    workflow_contract(workflow)
    deleted = 0
    for command in (RUN, CONTROLS, *FINAL):
        rejected(lambda: workflow_contract(workflow.replace("          " + command + "\n", "")))
        deleted += 1
    for arch in ("x86-64", "arm64"):
        rejected(lambda: workflow_contract(workflow.replace(f"          - arch: {arch}\n", "")))
        deleted += 1
    print(f"PASS: {count} actual-artifact corruptions and {deleted} workflow deletions detected")


if __name__ == "__main__":
    main()
