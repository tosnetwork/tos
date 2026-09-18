#!/usr/bin/env python3
"""Require every new P0 validator group to be created from its committee.

`create_validator_group()` has exactly one call site, inside the
`get_or_make_next_group` helper. That helper is the unique boundary before a
group is created, and both callers -- the current-shard path and the
future/tentative-shard path -- route through it. So the authenticated-set
enforcement lives there, once: on a P0-active chain the helper replaces the
candidate validator set with the one adapted from the group's committed session,
verifies the recomputed session id, and refuses a non-member rather than letting
create_validator_group's own membership CHECK abort.

The manager actor cannot be instantiated in the focused ROCKSDB=OFF tree, so
this is a source-shape check with negative controls, weaker than the four-
validator rehearsal and not a substitute. Every rule is proven to fail when its
subject is removed, using the same text the rule is about.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANAGER = "validator/manager.cpp"

HELPER = "auto get_or_make_next_group = [&](ShardIdFull shard, ValidatorSessionId id, td::Ref<block::ValidatorSet> val_set) {"
CREATE = "create_validator_group("
# Inside the helper, on a P0-active chain:
ADAPT = "tos::auth::authenticated_validator_set(*committed->second.owner, shard)"
REPLACE = "val_set = std::move(authoritative);"
GROUP_ID_CHECK = "get_validator_set_id(shard, authoritative, opts_hash, key_seqno, opts) != id"
LOCAL_CHECK = "get_validator(shard, authoritative).is_zero()"
MISSING_REFUSE = "committed == validator_auth_sessions_.end() || !committed->second.owner"
CREATE_USES = "create_validator_group(id, shard, val_set, key_seqno, opts, started_)"
# Both callers route through the helper.
NEW_SHARDS_CALL = "get_or_make_next_group(shard, val_group_id, val_set)"


def helper_region(text: str) -> str:
    """The get_or_make_next_group lambda body, up to its create_validator_group."""
    start = text.find(HELPER)
    if start < 0:
        return ""
    end = text.find(CREATE_USES, start)
    return text[start:end] if end > start else ""


def verify(manager: str) -> None:
    # create_validator_group has exactly one call site: inside the helper. A
    # second call site would be a group-creation path that could bypass the
    # boundary. Exclude the definition (preceded by "::") and the unrelated
    # find_or_create_validator_group lambda (preceded by a word character).
    import re
    call_sites = [m.start() for m in re.finditer(r"(?<![\w:])create_validator_group\(", manager)]
    if len(call_sites) != 1:
        raise ValueError(f"create-validator-group-not-a-single-boundary ({len(call_sites)})")

    span = helper_region(manager)
    if not span:
        raise ValueError("helper-region-not-located")
    if ADAPT not in span:
        raise ValueError("set-not-adapted-from-the-committed-session")
    if REPLACE not in span:
        raise ValueError("candidate-set-not-replaced")
    if GROUP_ID_CHECK not in span:
        raise ValueError("recomputed-session-id-not-verified")
    if LOCAL_CHECK not in span:
        raise ValueError("local-membership-not-checked")
    if MISSING_REFUSE not in span:
        raise ValueError("missing-session-not-refused")
    # The replacement precedes the create the helper performs.
    if span.count(REPLACE) < 1:
        raise ValueError("candidate-set-not-replaced-before-create")

    # Both production callers route through the protected helper.
    if manager.count(NEW_SHARDS_CALL) < 2:
        raise ValueError("not-every-caller-routes-through-the-helper")


def main() -> int:
    manager = (ROOT / MANAGER).read_text()
    span = helper_region(manager)
    if not span:
        raise RuntimeError("the helper this checker is about cannot be located")

    def without(old: str, new: str = "") -> str:
        edited = span.replace(old, new, 1)
        if edited == span:
            raise RuntimeError(f"a negative control changed nothing: {old!r}")
        return manager.replace(span, edited, 1)

    probes = [
        # the helper passes its candidate set straight to create
        without(REPLACE, "(void)authoritative;"),
        # authenticated adaptation removed
        without(ADAPT, "seat_consensus_roster(false, nullptr, *val_set)"),
        # missing session falls back to the candidate set instead of refusing
        without("if (committed == validator_auth_sessions_.end() || !committed->second.owner) {",
                "if (false) {"),
        # canonical group-id equality removed
        without(GROUP_ID_CHECK, "false"),
        # local membership check removed
        without(LOCAL_CHECK, "false"),
    ]
    # A future_shards caller that bypasses the helper: drop one of the two calls.
    probes.append(manager.replace("\n      " + NEW_SHARDS_CALL + ";", "", 1))
    # Another create_validator_group call site outside the helper.
    probes.append(manager.replace("auto G = create_validator_group(id, shard, val_set, key_seqno, opts, started_);",
                                  "auto G = create_validator_group(id, shard, val_set, key_seqno, opts, started_);\n"
                                  "    if (false) create_validator_group(id, shard, val_set, key_seqno, opts, started_);",
                                  1))

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
    print("PASS: get_or_make_next_group is the single group-creation boundary; on a P0-active chain it "
          "creates from the committee-adapted set, verifies the id and local membership, and both callers "
          "route through it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
