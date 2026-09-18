#!/usr/bin/env python3
"""Require the manager to hand group creation the authenticated validator set.

The consensus bus reseats its members from the committee, but that happens
inside the bridge -- after the bridge has already constructed its ManagerFacade
from the validator set the manager passed in. So making only the bus authentic
leaves the facade (collation, validation, accept, cache/broadcast) running on the
historical set that merely compared equal during admission. The fix is to
replace the manager's `val_set` with the committee-adapted set once, in
`update_shards()`, before `create_validator_group()` -- so both consumers inherit
one authenticated source.

This reads that production edge. The manager actor cannot be instantiated in the
focused test tree, so this is a source-shape check, weaker than the four-
validator rehearsal and not a substitute. Every rule is proven to fail when its
subject is removed, using the same text the rule is about.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANAGER = "validator/manager.cpp"

# The replacement edge, inside update_shards, on a P0-active creation path.
ADAPT = "tos::auth::authenticated_validator_set(*committed_session->second.owner, shard)"
REPLACE = "val_set = std::move(authoritative);"
REBIND = "validator_id = get_validator(shard, val_set);"
# The two refusals the ruling requires beside the replacement.
GROUP_ID_CHECK = "get_validator_set_id(shard, authoritative, opts_hash, key_seqno, opts) != val_group_id"
LOCAL_CHECK = "get_validator(shard, authoritative).is_zero()"
# The set is passed to group creation after being replaced, so the facade and
# the bus both receive it.
CREATE = "get_or_make_next_group(shard, val_group_id, val_set)"


def region(text: str) -> str:
    """update_shards, from the P0 admission block to the group lookup."""
    start = text.find("const bool validator_auth_active =")
    end = text.find("auto find_or_create_validator_group = [&]", start)
    return text[start:end] if start >= 0 and end > start else ""


def verify(manager: str) -> None:
    span = region(manager)
    if not span:
        raise ValueError("update-shards-region-not-located")
    if ADAPT not in span:
        raise ValueError("val-set-not-adapted-from-the-committed-session")
    if REPLACE not in span:
        raise ValueError("manager-val-set-not-replaced")
    if REBIND not in span:
        raise ValueError("local-validator-not-rebound-to-the-authenticated-set")
    if GROUP_ID_CHECK not in span:
        raise ValueError("authenticated-group-id-not-verified")
    if LOCAL_CHECK not in span:
        raise ValueError("local-membership-not-checked-against-the-committee")
    # The replacement must precede the group creation that hands the set to the
    # facade and the bus, or both would receive the historical set.
    if manager.find(REPLACE) > manager.find(CREATE):
        raise ValueError("val-set-replaced-after-group-creation")


def main() -> int:
    manager = (ROOT / MANAGER).read_text()
    span = region(manager)
    if not span:
        raise RuntimeError("the region this checker is about cannot be located")

    def without(old: str, new: str = "") -> str:
        # Edit inside the region and splice it back: REBIND and the get_validator
        # call also appear before this region (the historical val_set path), so a
        # whole-file replace would remove the wrong one and leave the rule intact.
        edited = span.replace(old, new, 1)
        if edited == span:
            raise RuntimeError(f"a negative control changed nothing: {old!r}")
        return manager.replace(span, edited, 1)

    probes = (
        without(REPLACE, "(void)authoritative;"),
        without(ADAPT, "seat_consensus_roster(false, nullptr, *val_set)"),
        without(GROUP_ID_CHECK, "false"),
        without(LOCAL_CHECK, "false"),
        without(REBIND, ""),
    )
    for probe in probes:
        if probe == manager:
            raise RuntimeError("a negative control changed nothing")
        try:
            verify(probe)
        except ValueError:
            pass
        else:
            raise RuntimeError("manager authenticated-set negative control survived")

    try:
        verify(manager)
    except ValueError as reason:
        print(f"MANAGER-AUTHENTICATED-SET-NOT-WIRED {reason}", file=sys.stderr)
        return 1
    print("PASS: the manager replaces its validator set with the committee-adapted set before group "
          "creation, verifies the session id and local membership, and both facade and bus inherit it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
