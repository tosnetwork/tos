#!/usr/bin/env python3
"""Pin the DNS governance vote to node-owned PQ authority, not local signing."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[1])
    source = (root / "scripts/dns-e2e.py").read_text(encoding="utf-8")
    required = {
        "Engine_validator_createProposalVoteRequest(": 1,
        "validator_node.engine_console.request(request)": 1,
        "Cell.one_from_boc(response.to_send)": 1,
        'check("ConfigParam 4 appears after the validator vote", activated)': 1,
        "prelaunch = await registration_receipt(": 1,
        "await governance_receipt(": 2,
    }
    for marker, expected in required.items():
        if source.count(marker) != expected:
            raise RuntimeError(
                f"DNS_PQ_VOTE_SOURCE_FAILURE: {marker!r} occurs "
                f"{source.count(marker)} times, expected {expected}")
    if "validator_key.key.sign(" in source:
        raise RuntimeError("DNS_PQ_VOTE_SOURCE_FAILURE: DNS still signs a vote locally")
    for path in (root / "scripts").rglob("*.py"):
        if path.name == Path(__file__).name:
            continue
        text = path.read_text(encoding="utf-8")
        if "0x566F7445" in text:
            raise RuntimeError(f"DNS_PQ_VOTE_SOURCE_FAILURE: local config-vote preimage tag in {path}")
    print("DNS_PQ_VOTE_SOURCE_OK: DNS requests a node-produced PQ vote; scripts contain no local config-vote signer")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
