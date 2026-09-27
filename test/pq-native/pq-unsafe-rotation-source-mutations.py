#!/usr/bin/env python3
"""Mutate both sides of the PQ unsafe-rotation source boundary."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2])
guard = root / "scripts/check-pq-unsafe-rotation.py"


def run_guard() -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(guard), str(root)], capture_output=True, text=True)


baseline = run_guard()
if baseline.returncode != 0:
    raise SystemExit(f"PQ_UNSAFE_ROTATION_MUTATION_FAILURE: baseline guard is red: {baseline.stderr}")


def mutate(relative: str, change, expected: str) -> None:
    path = root / relative
    original = path.read_text()
    changed = change(original)
    if changed == original:
        raise SystemExit(f"PQ_UNSAFE_ROTATION_MUTATION_FAILURE: mutation did not apply to {relative}")
    try:
        path.write_text(changed)
        result = run_guard()
        if result.returncode == 0 or expected not in result.stderr:
            raise SystemExit(
                f"PQ_UNSAFE_ROTATION_MUTATION_FAILURE: {relative} mutation did not kill "
                f"{expected!r}: rc={result.returncode} stderr={result.stderr!r}"
            )
    finally:
        path.write_text(original)


def replace_once(before: str, after: str):
    def change(text: str) -> str:
        if text.count(before) != 1:
            raise SystemExit(f"PQ_UNSAFE_ROTATION_MUTATION_FAILURE: ambiguous marker {before!r}")
        return text.replace(before, after, 1)

    return change


manager_path = "validator/manager.cpp"
mutate(
    manager_path,
    replace_once("rotation_tag != 0", "rotation_tag == 0"),
    "nonzero rotation condition count=0",
)
mutate(
    manager_path,
    replace_once("rotation_tag != 0", "rotation_tag >= 0"),
    "nonzero rotation condition count=0",
)
mutate(
    manager_path,
    replace_once(
        "refusing to create PQ Simplex validator group for ",
        "continuing PQ Simplex validator group for ",
    ),
    "named PQ refusal count=0",
)


def move_count_before_refusal(text: str) -> str:
    count_line = (
        "        ++(shard.is_masterchain() ? active_validator_groups_master_ "
        ": active_validator_groups_shard_);\n"
    )
    condition_line = "        if (auto rotation_tag =\n"
    if text.count(count_line) != 1 or text.count(condition_line) != 1:
        raise SystemExit("PQ_UNSAFE_ROTATION_MUTATION_FAILURE: group-order markers changed")
    return text.replace(count_line, "", 1).replace(condition_line, count_line + condition_line, 1)


mutate(
    manager_path,
    move_count_before_refusal,
    "nonzero rotation refusal no longer precedes active PQ group counting and creation",
)
def inject_old_hash(text: str) -> str:
    marker = "if (destroyed_validator_sessions_.contains(val_group_id)) {"
    if text.count(marker) != 2:  # current and future groups; change only current
        raise SystemExit("PQ_UNSAFE_ROTATION_MUTATION_FAILURE: active hash insertion point changed")
    return text.replace(marker, "val_group_id = sha256_bits256(td::Slice{});\n        " + marker, 1)


mutate(manager_path, inject_old_hash, "local rotation hash again overwrites consensus session")
mutate(
    ".github/workflows/branch-chain-python.yml",
    replace_once("uv run python test/integration/test_pq_unsafe_rotation_refusal.py", "uv run python test/integration/test_basic.py"),
    "every-push process regression invocation absent or duplicated",
)
mutate(
    "test/integration/test_pq_unsafe_rotation_refusal.py",
    lambda text: text.replace('"masterchain_stats_success"', '"group_created"'),
    "process regression lost zero-rotation masterchain stats control",
)

print("PQ_UNSAFE_ROTATION_MUTATIONS_OK: zero-allow, nonzero-refuse, ordering, hash and CI bindings were killable")
