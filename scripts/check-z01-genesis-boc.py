#!/usr/bin/env python3
"""Read back Z01 launch limits and Simplex cells from a retained zerostate BOC."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "test/tostester/src"))


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def decode(path: Path) -> dict:
    from pytosiq_core import ShardStateUnsplit
    from pytosiq_core.boc.deserialize import Boc
    from pytosiq_core.tlb.config import ConfigParam16, ConfigParam28

    raw = path.read_bytes()
    roots = Boc(raw).deserialize()
    require(len(roots) == 1, "zerostate BOC must have exactly one root")
    config = ShardStateUnsplit.deserialize(roots[0].begin_parse()).custom.config.config
    require(all(number in config for number in (16, 28, 30)), "Param16/28/30 absent from zerostate")
    limits = ConfigParam16.deserialize(config[16].copy())
    catchain = ConfigParam28.deserialize(config[28].copy())

    outer = config[30].copy()
    require(outer.load_uint(8) == 0x10, "Param30 is not new_consensus_config_all")
    selected = {}
    for name in ("masterchain", "shard"):
        cell = outer.load_maybe_ref()
        require(cell is not None, f"Param30 {name} cell absent")
        value = cell.begin_parse()
        selected[name] = {
            "cell_hash": cell.hash.hex(),
            "tag": value.load_uint(8),
            "flags": value.load_uint(5),
            "protocol_version": value.load_uint(2),
            "use_quic": value.load_bool(),
            "slots_per_leader_window": value.load_uint(32),
            "noncritical_params": value.load_dict(8, value_deserializer=lambda bits: bits.load_uint(32)),
        }
        require(value.remaining_bits == 0 and value.remaining_refs == 0,
                f"Param30 {name} cell has unparsed fields")
    require(outer.remaining_bits == 0 and outer.remaining_refs == 0,
            "Param30 wrapper has unparsed fields")
    return {
        "boc_sha256": hashlib.sha256(raw).hexdigest(),
        "root_hash": roots[0].hash.hex(),
        "param16_cell_hash": config[16].copy().to_cell().hash.hex(),
        "param16": {"max_validators": limits.max_validators,
                    "max_main_validators": limits.max_main_validators,
                    "min_validators": limits.min_validators},
        "param28_cell_hash": config[28].copy().to_cell().hash.hex(),
        "param28": {"type": catchain.type_,
                    "mc_catchain_lifetime": catchain.mc_catchain_lifetime,
                    "shard_catchain_lifetime": catchain.shard_catchain_lifetime,
                    "shard_validators_lifetime": catchain.shard_validators_lifetime,
                    "shard_validators_num": catchain.shard_validators_num,
                    "shuffle_mc_validators": catchain.shuffle_mc_validators},
        "param30_cell_hash": config[30].copy().to_cell().hash.hex(),
        "param30": selected,
    }


def validate(receipt: dict) -> None:
    require(receipt["param16"] == {"max_validators": 21, "max_main_validators": 21,
                                    "min_validators": 4}, "Param16 is not the 21/21/4 launch boundary")
    require(receipt["param28"] == {"type": "catchain_config_new", "mc_catchain_lifetime": 250,
                                    "shard_catchain_lifetime": 250, "shard_validators_lifetime": 1000,
                                    "shard_validators_num": 21, "shuffle_mc_validators": True},
            "Param28 is not the 21-shard launch boundary")
    expected = {"tag": 0x22, "flags": 0, "protocol_version": 2, "use_quic": True,
                "slots_per_leader_window": 4, "noncritical_params": {0: 400, 1: 1000, 10: 250}}
    cells = receipt["param30"]
    require(set(cells) == {"masterchain", "shard"}, "Param30 lacks both selected cells")
    for name, cell in cells.items():
        require({key: value for key, value in cell.items() if key != "cell_hash"} == expected,
                f"Param30 {name} is not the fixed Simplex v2 config")
    require(cells["masterchain"]["cell_hash"] == cells["shard"]["cell_hash"],
            "Param30 masterchain and shard cells differ")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zerostate", type=Path, required=True)
    parser.add_argument("--expected-boc-sha256", required=True)
    args = parser.parse_args()
    raw_sha = hashlib.sha256(args.zerostate.read_bytes()).hexdigest()
    if raw_sha != args.expected_boc_sha256:
        raise ValueError("zerostate BOC differs from precommitted SHA-256")
    receipt = decode(args.zerostate)
    validate(receipt)
    print(json.dumps({"schema": "tos.z01.genesis-boc-check.v1", "passed": True, **receipt},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
