#!/usr/bin/env python3
"""Fail closed if any live committee-forming path escapes the launch cap."""

import json
import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"PQ_LAUNCH_CAP_SOURCE_FAILURE: {message}")


root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parents[1]).resolve()
policy = json.loads((root / "config/pq-launch-limits.json").read_text())
expected = {
    "schema_version": 1,
    "decision_status": "OWNER_ACCEPTED",
    "enforcement": "REJECT_NOT_CLAMP",
    "rationale": (
        "At 21 signers ML-DSA-44 uses 50,820 signature bytes, ML-DSA-87 uses 97,167, and "
        "SLH-DSA-256s uses 625,632; all fit the 984,260-byte structural carrier while preserving "
        "algorithm-change headroom. The 400-signer N5 retention sizing is a separate rotation/resource "
        "bound and is not reduced by this launch cap."
    ),
    "max_total_validators": 21,
    "max_masterchain_committee": 21,
    "max_shard_committee": 21,
}
if policy != expected:
    fail(f"launch-limit policy changed without review: {policy}")

generated_views = {
    "crypto/pq/pq-launch-limits.h": (
        "max_total_validators = 21",
        "max_masterchain_committee = 21",
        "max_shard_committee = 21",
    ),
    "crypto/smartcont/pq-launch-limits.fc": (
        "max_total_validators = 21",
        "max_masterchain_committee = 21",
        "max_shard_committee = 21",
    ),
    "test/tostester/src/tostester/pq_launch_limits.py": (
        "MAX_TOTAL_VALIDATORS = 21",
        "MAX_MASTERCHAIN_COMMITTEE = 21",
        "MAX_SHARD_COMMITTEE = 21",
    ),
}
for path, literals in generated_views.items():
    text = (root / path).read_text()
    for literal in literals:
        if text.count(literal) != 1:
            fail(f"generated launch-limit view drifted: {path} marker {literal!r}")


def collapsed(path: str) -> str:
    return re.sub(r"\s+", " ", (root / path).read_text()).strip()


markers = {
    "contract includes generated launch policy": (
        "crypto/smartcont/config-code.fc",
        '#include "pq-launch-limits.fc";',
    ),
    "Param16 proposal admission is capped": (
        "crypto/smartcont/config-code.fc",
        "param_id == 16) & (~ valid_validator_limits?(cfg_dict, param_val))",
    ),
    "Param28 proposal admission is capped": (
        "crypto/smartcont/config-code.fc",
        "param_id == 28) & (~ valid_catchain_limits?(param_val))",
    ),
    "governance-installed live validator sets are capped": (
        "crypto/smartcont/config-code.fc",
        "if ((param_id >= 34) & (param_id <= 37)) { ifnot (valid_live_validator_set_limits?(cfg_dict, param_val))",
    ),
    "elector-installed set total is capped": (
        "crypto/smartcont/config-code.fc",
        "total > min(max_validators, pq_launch::max_total_validators)",
    ),
    "elector-installed set main count is capped": (
        "crypto/smartcont/config-code.fc",
        "main > min(max_main_validators, pq_launch::max_masterchain_committee)",
    ),
    "node validates authoritative launch configuration": (
        "validator/manager.cpp",
        "config_holder.ok()->validate_pq_launch_resource_config()",
    ),
    "production config holder delegates launch validation": (
        "validator/impl/config.hpp",
        "return config_->validate_pq_launch_resource_config()",
    ),
    "validator actor constructor is independently capped": (
        "validator/manager.cpp",
        'refusing to create validator group for " << shard.to_str() << ": committee has "',
    ),
    "observer actor constructor is independently capped": (
        "validator/manager.cpp",
        'refusing to create observer group for " << shard.to_str() << ": committee has "',
    ),
    "consensus main-validator view uses the launch cap": (
        "crypto/pq/pq-consensus.h",
        "max_main_validators = launch_limits::max_masterchain_committee",
    ),
    "production Genesis Param16 is capped": (
        "crypto/smartcont/gen-zerostate.fif",
        "21 21 4 config.validator_num!",
    ),
    "production Genesis Param28 is capped": (
        "crypto/smartcont/gen-zerostate.fif",
        "250 250 1000 21 true config.catchain_params!",
    ),
    "tostester Genesis uses the launch total": (
        "test/tostester/src/tostester/zerostate.py",
        '"max_validators": MAX_TOTAL_VALIDATORS',
    ),
    "tostester Genesis uses the masterchain cap": (
        "test/tostester/src/tostester/zerostate.py",
        '"max_main_validators": MAX_MASTERCHAIN_COMMITTEE',
    ),
    "tostester Genesis uses the shard cap": (
        "test/tostester/src/tostester/zerostate.py",
        '"shard_validators_per_group": MAX_SHARD_COMMITTEE',
    ),
    "tostester refuses a 22-validator Genesis": (
        "test/tostester/src/tostester/zerostate.py",
        "validator_count > MAX_MASTERCHAIN_COMMITTEE",
    ),
}
for name, (path, marker) in markers.items():
    count = collapsed(path).count(re.sub(r"\s+", " ", marker).strip())
    if count != 1:
        fail(f"{name}: {path} marker matches {count} times, expected 1")

# These are the two production actor constructors.  Count their call sites globally:
# adding another path cannot silently bypass the admission in ValidatorManagerImpl.
cpp = "\n".join(path.read_text() for path in (root / "validator").rglob("*.cpp"))
for symbol in ("IValidatorGroup::create_bridge(", "IValidatorGroup::create_bridge_observer("):
    if cpp.count(symbol) != 2:  # one definition in bridge.cpp, one admitted call in manager.cpp
        fail(f"committee-forming path count changed for {symbol}: found {cpp.count(symbol)}, expected 2")

print(f"PQ_LAUNCH_CAP_SOURCE_OK: {len(markers)} cap bindings and 2 actor constructors are pinned")
