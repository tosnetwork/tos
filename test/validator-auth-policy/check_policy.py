#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
"""Independent model of the TIP-0002 validator authentication phases.

Vendored from tosnetwork/TIP assets/tip-0002/check-policy.py at the revision
recorded in policy-cases.json. test/test-validator-auth-policy.cpp evaluates
the same corpus through the production helpers in tos/quorum.h; the two
implementations must agree, which is what makes either of them evidence.

`ed_valid` and `pq_valid` are supplied verification outcomes, not signatures.
This has no cryptographic implementation, does not run TOS consensus, and is
not evidence that any phase beyond the classical one exists in this codebase.
See doc/tip-0002-p0-readiness.md for what is and is not implemented.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

MAX_TOTAL_WEIGHT = ((1 << 64) - 1) // 3
PHASES = {"classical", "shadow", "hybrid_required", "pq_required"}


def positive_weight(value: Any) -> bool:
    return type(value) is int and 0 < value <= MAX_TOTAL_WEIGHT


def evaluate(case: dict[str, Any], default_registry: dict[str, int]) -> str:
    """Return the modeled outcome, not a production consensus error code."""
    phase = case["phase"]
    if phase not in PHASES:
        return "reject_phase"
    if case.get("well_formed", True) is not True:
        return "reject_encoding"
    if case.get("policy_matches", True) is not True:
        return "reject_policy"
    if case.get("mandatory_suite_supported", True) is not True:
        return "reject_suite"
    registry = case.get("registry", default_registry)
    if not isinstance(registry, dict) or not registry:
        return "reject_registry"
    if not all(isinstance(k, str) and positive_weight(v) for k, v in registry.items()):
        return "reject_registry"
    total = sum(registry.values())
    if total > MAX_TOTAL_WEIGHT:
        return "reject_registry"
    signers = case["signers"]
    if not isinstance(signers, list):
        return "reject_encoding"
    seen: set[str] = set()
    signed = 0
    for record in signers:
        identity = record["validator"]
        if identity not in registry:
            return "reject_unknown_signer"
        if identity in seen:
            return "reject_duplicate_signer"
        seen.add(identity)
        # All key, role, network, committee and statement bindings must match.
        if record.get("context_matches", True) is not True:
            return "reject_context"
        ed = record.get("ed_valid", False) is True
        pq = record.get("pq_valid", False) is True
        if phase in {"hybrid_required", "pq_required"}:
            if record.get("registered", False) is not True:
                return "reject_registration"
        if phase in {"classical", "shadow"}:
            valid = ed  # Shadow results have no consensus authority.
        elif phase == "hybrid_required":
            valid = ed and pq
        else:
            valid = pq
        if not valid:
            return "reject_authentication"
        signed += registry[identity]
    return "accept" if 3 * signed >= 2 * total else "reject_quorum"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", nargs="?", type=Path,
                        default=Path(__file__).with_name("policy-cases.json"))
    args = parser.parse_args()
    try:
        corpus = json.loads(args.cases.read_text(encoding="utf-8"))
        cases = corpus["cases"]
        registry = corpus["default_registry"]
        if not isinstance(cases, list) or not cases:
            raise ValueError("Case corpus must be a nonempty list")
        identities = [case["id"] for case in cases]
        if len(set(identities)) != len(identities):
            raise ValueError("Duplicate case IDs")
        failures = 0
        for case in cases:
            actual = evaluate(case, registry)
            if actual != case["expected"]:
                failures += 1
                print(f"FAIL {case['id']}: expected {case['expected']}, got {actual}",
                      file=sys.stderr)
        if failures:
            print(f"{failures}/{len(cases)} policy cases failed", file=sys.stderr)
            return 1
        print(f"PASS: {len(cases)} policy-model cases (no cryptographic verification)")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Invalid corpus: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
