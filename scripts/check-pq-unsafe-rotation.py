#!/usr/bin/env python3
"""Pin the temporary PQ unsafe-rotation refusal and its process regression."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"PQ_UNSAFE_ROTATION_SOURCE_FAILURE: {message}")


root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
manager = (root / "validator/manager.cpp").read_text()
active_begin = "active_validator_groups_master_ = active_validator_groups_shard_ = 0;"
future_begin = "if (allow_validate_) {\n    for (auto &shard : future_shards)"
require(manager.count(active_begin) == 1 and manager.count(future_begin) == 1, "manager group regions changed")
active = manager.split(active_begin, 1)[1].split(future_begin, 1)[0]
collapsed = re.sub(r"\s+", " ", active)

condition = "rotation_tag != 0"
refusal = "refusing to create PQ Simplex validator group for "
group_count = "++(shard.is_masterchain() ? active_validator_groups_master_ : active_validator_groups_shard_)"
derivation = "auto val_group_id = block::derive_validator_session_identity"
creation = "auto entry = find_or_create_validator_group()"
for name, marker in (
    ("nonzero rotation condition", condition),
    ("named PQ refusal", refusal),
    ("active group count", group_count),
    ("canonical session derivation", derivation),
    ("active group creation", creation),
):
    require(collapsed.count(marker) == 1, f"{name} count={collapsed.count(marker)}, expected=1")
require(
    collapsed.index(condition) < collapsed.index(refusal) < collapsed.index(group_count)
    < collapsed.index(derivation) < collapsed.index(creation),
    "nonzero rotation refusal no longer precedes active PQ group counting and creation",
)
require("val_group_id = sha256_bits256" not in active, "local rotation hash again overwrites consensus session")
require(
    "check_unsafe_catchain_rotate(last_masterchain_seqno_, val_set->get_catchain_seqno())" in active,
    "active-group refusal no longer consults the effective rotation tag",
)

test = (root / "test/integration/test_pq_unsafe_rotation_refusal.py").read_text()
for name, marker in (
    ("zero-rotation masterchain stats control", '"masterchain_stats_success"'),
    ("zero-rotation refusal control", '"zero_rotation_refused"'),
    ("production trusted-session rejection", '"trusted_session_mismatch"'),
    ("nonzero refusal result", '"rotation_refused"'),
    ("refusal-then-create rejection", '"refused_then_group_created"'),
):
    require(marker in test, f"process regression lost {name}")
workflow = (root / ".github/workflows/branch-chain-python.yml").read_text()
invocation = "uv run python test/integration/test_pq_unsafe_rotation_refusal.py"
require(workflow.count(invocation) == 1, "every-push process regression invocation absent or duplicated")

print(
    "PQ_UNSAFE_ROTATION_SOURCE_OK: nonzero tag refusal precedes active group creation; "
    "the process regression is scheduled on every branch push"
)
