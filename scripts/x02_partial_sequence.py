#!/usr/bin/env python3
"""Offline specification of X02 directed packet selection, not live evidence.

Indices count packets at one serialized decision point per direction. Replaying
the same input sequence repeats decisions; separate networks can reorder inputs.
No kernel rule, network, process identity or chain progress is verified here.
"""

from __future__ import annotations

import re

NODES = ("node1", "node2", "node3", "node4")
DIRECTIONS = tuple(f"{src}>{dst}/{transport}"
                   for src in NODES for dst in NODES if src != dst
                   for transport in ("adnl", "quic"))
SEED = "00000000000000000000000000000001"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def candidate_policy(source_commit: str) -> dict:
    require(isinstance(source_commit, str)
            and re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None,
            "fixed source commit is absent")
    return {
        "schema": "tos.x02.partial-sequence-policy.v1",
        "source_commit": source_commit,
        "algorithm": "ordinal-modulo-v1",
        "seed_hex": SEED,
        "rate": {"numerator": 1, "denominator": 4},
        "directions": list(DIRECTIONS),
        "index_origin": 0,
        "reset": "once-before-partial-phase",
        "selection": "(packet_index + seed_integer + direction_ordinal) % 4 == 0",
        "minimum_packets_per_direction": 8,
        "scope": "offline-selection-only",
        "phase": "partial_four_live",
        "chain_thresholds": {"progress_min_delta": 2, "progress_max_seconds": 120,
                             "recovery_min_delta": 2, "recovery_max_seconds": 180},
        "halt_claim": False,
    }


def validate_policy(policy: dict) -> None:
    require(isinstance(policy, dict), "policy is not an object")
    expected = candidate_policy(policy.get("source_commit"))
    # JSON booleans must not alias integer fields, or integer zero alias False.
    require(type(policy.get("index_origin")) is int, "index origin is not an integer")
    require(type(policy.get("minimum_packets_per_direction")) is int,
            "minimum packet count is not an integer")
    rate = policy.get("rate")
    require(isinstance(rate, dict)
            and all(type(rate.get(key)) is int for key in ("numerator", "denominator")),
            "rate is not an integer fraction")
    thresholds = policy.get("chain_thresholds")
    require(isinstance(thresholds, dict)
            and all(type(value) is int for value in thresholds.values()),
            "chain thresholds are not integers")
    require(type(policy.get("halt_claim")) is bool, "halt claim is not a boolean")
    require(policy == expected, "policy differs from the preselected candidate")


def selected_drop(policy: dict, direction: str, packet_index: int) -> bool:
    validate_policy(policy)
    require(direction in DIRECTIONS, "unknown directed UDP transport")
    require(type(packet_index) is int and packet_index >= 0,
            "packet index must be a nonnegative integer")
    offset = int(policy["seed_hex"], 16) + DIRECTIONS.index(direction)
    return (packet_index + offset) % 4 == 0


def verify_selection_trace(policy: dict, records: list[dict]) -> dict:
    """Check a declared input sequence. Producer authenticity is a separate gate."""
    validate_policy(policy)
    require(isinstance(records, list), "trace is not an array")
    counts = {direction: {"seen": 0, "dropped": 0, "passed": 0}
              for direction in DIRECTIONS}
    for row in records:
        require(isinstance(row, dict)
                and set(row) == {"direction", "index", "packet_sha256", "dropped"},
                "trace row shape differs")
        direction = row["direction"]
        require(isinstance(direction, str) and direction in counts, "unknown direction")
        count = counts[direction]
        require(type(row["index"]) is int and row["index"] == count["seen"],
                "direction sequence skipped, repeated or reset")
        require(isinstance(row["packet_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["packet_sha256"]) is not None,
                "packet digest is absent")
        require(type(row["dropped"]) is bool
                and row["dropped"] == selected_drop(policy, direction, row["index"]),
                "packet decision differs from fixed selection")
        count["seen"] += 1
        count["dropped" if row["dropped"] else "passed"] += 1
    for direction, count in counts.items():
        require(count["seen"] >= policy["minimum_packets_per_direction"],
                f"{direction}: insufficient per-direction traffic")
        require(count["dropped"] > 0 and count["passed"] > 0,
                f"{direction}: not partial loss")
    return {"scope": "offline-selection-only", "counts": counts,
            "live_packet_hits_verified": False, "chain_thresholds_verified": False}
