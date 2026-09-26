#!/usr/bin/env python3
"""Prove every launch-cap source binding is independently load-bearing."""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "scripts/check-pq-launch-cap.py"

mutations = [
    ("crypto/smartcont/config-code.fc", '#include "pq-launch-limits.fc";', ""),
    ("crypto/smartcont/config-code.fc", "param_id == 16", "param_id == 160"),
    ("crypto/smartcont/config-code.fc", "param_id == 28", "param_id == 280"),
    ("crypto/smartcont/config-code.fc", "param_id >= 34", "param_id >= 340"),
    (
        "crypto/smartcont/config-code.fc",
        "ifnot (valid_live_validator_set_limits?(cfg_dict, param_val))",
        "ifnot (true)",
    ),
    ("crypto/smartcont/config-code.fc", "total > min(max_validators", "total > min(uncapped_max_validators"),
    ("crypto/smartcont/config-code.fc", "main > min(max_main_validators", "main > min(uncapped_max_main_validators"),
    (
        "validator/manager.cpp",
        "config_holder.ok()->validate_pq_launch_resource_config()",
        "config_holder.ok()->visit_validator_params()",
    ),
    (
        "validator/impl/config.hpp",
        "return config_->validate_pq_launch_resource_config()",
        "return td::Status::OK()",
    ),
    (
        "validator/manager.cpp",
        '"refusing to create validator group for " << shard.to_str() << ": committee has "',
        '"validator cap removed for " << shard.to_str() << ": committee has "',
    ),
    (
        "validator/manager.cpp",
        '"refusing to create observer group for " << shard.to_str() << ": committee has "',
        '"observer cap removed for " << shard.to_str() << ": committee has "',
    ),
    (
        "crypto/pq/pq-consensus.h",
        "max_main_validators = launch_limits::max_masterchain_committee",
        "max_main_validators = 100",
    ),
    ("crypto/smartcont/gen-zerostate.fif", "21 21 4 config.validator_num!", "21 22 4 config.validator_num!"),
    ("crypto/smartcont/gen-zerostate.fif", "250 250 1000 21 true", "250 250 1000 22 true"),
    ("test/tostester/src/tostester/zerostate.py", '"max_validators": MAX_TOTAL_VALIDATORS', '"max_validators": 40'),
    ("test/tostester/src/tostester/zerostate.py", '"max_main_validators": MAX_MASTERCHAIN_COMMITTEE', '"max_main_validators": 20'),
    ("test/tostester/src/tostester/zerostate.py", '"shard_validators_per_group": MAX_SHARD_COMMITTEE', '"shard_validators_per_group": 23'),
    (
        "test/tostester/src/tostester/zerostate.py",
        "validator_count > MAX_MASTERCHAIN_COMMITTEE",
        "validator_count > UNBOUNDED_MASTERCHAIN_COMMITTEE",
    ),
]

for relative, before, after in mutations:
    path = ROOT / relative
    original = path.read_text()
    if original.count(before) != 1:
        raise SystemExit(f"PQ_LAUNCH_CAP_MUTATION_FAILURE: ambiguous mutation in {relative}: {before!r}")
    try:
        path.write_text(original.replace(before, after, 1))
        result = subprocess.run([sys.executable, str(CHECK), str(ROOT)], text=True, capture_output=True)
        if result.returncode == 0 or "PQ_LAUNCH_CAP_SOURCE_FAILURE" not in result.stderr:
            raise SystemExit(
                f"PQ_LAUNCH_CAP_MUTATION_FAILURE: removing {before!r} from {relative} did not make the guard red"
            )
    finally:
        path.write_text(original)

# A new direct constructor call is not in the marker table; the bidirectional count must
# still catch it, or the inventory only proves today's paths and not future additions.
manager = ROOT / "validator/manager.cpp"
original = manager.read_text()
try:
    manager.write_text(original + "\n// probe: IValidatorGroup::create_bridge(\n")
    result = subprocess.run([sys.executable, str(CHECK), str(ROOT)], text=True, capture_output=True)
    if result.returncode == 0 or "committee-forming path count changed" not in result.stderr:
        raise SystemExit("PQ_LAUNCH_CAP_MUTATION_FAILURE: a new committee-forming path was not detected")
finally:
    manager.write_text(original)

print(f"PQ_LAUNCH_CAP_MUTATIONS_OK: {len(mutations)} removals and one new path were detected")
