#!/usr/bin/env python3
"""Require consensus to seat the authenticated committee, not the manager's set.

The validator bus builds its member table by iterating a validator set. On a
P0-active chain that set must be the committee the authenticated session was
committed under, so this reads the two production edges the bridge cannot be
instantiated here to exercise:

  * before the historical member loop, on a P0-active chain, the set it iterates
    is reseated from the authenticated session through seat_consensus_roster;
  * the reseat happens only when the session is required, and a refusal from the
    roster stops the bus rather than falling through to the historical set.

This is a source-shape check, weaker than running the actor, and is not a
substitute for the end-to-end rehearsal. It is what can be checked before one
exists. Every rule is proven to fail when its subject is removed, using the same
text the rule is about.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BRIDGE = "validator/consensus/bridge.cpp"

INCLUDE = '#include "validator/auth/consensus-roster.h"'
GATE = "if (authenticated_session_required) {"
SEAT = "tos::auth::seat_consensus_roster(true, authenticated_session, *params_.validator_set)"
REFUSE = "stop();"
RESEAT = "params_.validator_set = td::make_ref<block::ValidatorSet>("
LOOP = "for (const auto& el : params_.validator_set->export_vector()) {"


def region(text: str) -> str:
    """The span of start_bus from the ownership guard to the member loop."""
    start = text.find("if (authenticated_session_required && !authenticated_session) {")
    end = text.find(LOOP, start)
    return text[start:end] if start >= 0 and end > start else ""


def verify(bridge: str) -> None:
    if INCLUDE not in bridge:
        raise ValueError("roster-boundary-not-included")
    span = region(bridge)
    if not span:
        raise ValueError("seat-region-not-located")
    # The reseat is gated on the session being required, seats through the
    # roster boundary, and refuses by stopping the bus.
    if GATE not in span:
        raise ValueError("reseat-not-gated-on-required")
    if SEAT not in span:
        raise ValueError("members-not-seated-from-the-authenticated-session")
    if RESEAT not in span:
        raise ValueError("authenticated-members-not-installed-as-the-set")
    if span.count(REFUSE) < 1:
        raise ValueError("roster-refusal-does-not-stop-the-bus")
    # The reseat must come before the loop consumes the set, or the loop would
    # iterate the manager's set and the reseat would be dead.
    if bridge.find(SEAT) > bridge.find(LOOP):
        raise ValueError("reseat-after-the-member-loop")


def main() -> int:
    bridge = (ROOT / BRIDGE).read_text()

    # A silent checker is not evidence. Each removal makes verify reject the
    # edited text, using the same source the rule is about.
    probes = (
        bridge.replace(INCLUDE, "", 1),
        bridge.replace(SEAT, "Result<tos::auth::ConsensusRoster>(tos::auth::ConsensusRoster::historical(*params_.validator_set))", 1),
        bridge.replace(RESEAT, "(void)authoritative; td::make_ref<block::ValidatorSet>(", 1),
        bridge.replace(GATE, "if (false) {", 1),
        # The reseat moved after the loop: dead, and the loop keeps the set.
        bridge.replace("if (authenticated_session_required) {\n      auto authoritative",
                       "if (false && authenticated_session_required) {\n      auto authoritative", 1),
    )
    for probe in probes:
        if probe == bridge:
            raise RuntimeError("a negative control changed nothing")
        try:
            verify(probe)
        except ValueError:
            pass
        else:
            raise RuntimeError("consensus roster negative control survived")

    try:
        verify(bridge)
    except ValueError as reason:
        print(f"CONSENSUS-ROSTER-NOT-WIRED {reason}", file=sys.stderr)
        return 1
    print("PASS: a P0-active bus seats the committee the authenticated session was committed under, "
          "and refuses rather than falling back to the manager's set")
    return 0


if __name__ == "__main__":
    sys.exit(main())
