#!/usr/bin/env python3
"""Pin the production and local Genesis Simplex parameters used by Z01."""

import argparse
from pathlib import Path
import re


PRODUCTION_PARAM30 = "\n".join((
    "dictnew",
    "<b 400 32 u, b> <s 0 rot 8 udict! drop",
    "<b 1000 32 u, b> <s 1 rot 8 udict! drop",
    "<b 250 32 u, b> <s 10 rot 8 udict! drop",
    "<b x{22} s, 0 5 u, 2 2 u, 1 1 u, 4 32 u, swap dict, b>",
))


def check(production: str, harness: str, manager: str) -> list[str]:
    errors = []
    if production.count("21 21 4 config.validator_num!") != 1:
        errors.append("production Param16 launch ceiling changed")
    if production.count("250 250 1000 21 true config.catchain_params!") != 1:
        errors.append("production Param28 launch ceiling changed")
    if production.count(PRODUCTION_PARAM30) != 2 or production.count("config.new_consensus_params_all!") != 1:
        errors.append("production masterchain/shard Param30 differs from fixed v2 values")
    defaults = (
        "target_block_rate_ms: int = 400",
        "slots_per_leader_window: int = 4",
        "first_block_timeout_ms: int = 1000",
        "max_leader_window_desync: int = 250",
        "protocol_version: int = 2",
        "use_quic: bool = True",
    )
    for field in defaults:
        if len(re.findall(r"^\s*" + re.escape(field) + r"\s*$", harness, re.MULTILINE)) != 1:
            errors.append(f"local Genesis Simplex default changed: {field}")
    for field in ("mc_consensus", "shard_consensus"):
        if len(re.findall(r"^\s*" + field + r": SimplexConsensusConfig \| None = field\(\s*default_factory=SimplexConsensusConfig\s*\)", harness, re.MULTILINE)) != 1:
            errors.append(f"local Genesis {field} no longer defaults to Simplex")
    if manager.count("last_masterchain_state_->get_selected_new_consensus_config(shard.workchain)") != 3:
        errors.append("manager current/future/observer paths no longer select chain Param30")
    if manager.count(".simplex_config_cell_hash = selected_config.value().cell_hash") != 3:
        errors.append("manager sessions no longer bind selected Param30 cell hash")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    errors = check(
        (root / "crypto/smartcont/gen-zerostate.fif").read_text(),
        (root / "test/tostester/src/tostester/zerostate.py").read_text(),
        (root / "validator/manager.cpp").read_text(),
    )
    if errors:
        for error in errors:
            print("Z01_GENESIS_SOURCE_FAILURE: " + error)
        return 1
    print("Z01_GENESIS_SOURCE_OK: production Param16/28/30, local defaults and three chain-selected sessions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
