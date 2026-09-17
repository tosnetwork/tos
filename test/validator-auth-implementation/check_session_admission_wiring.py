"""Require the manager's session gate to derive a committee from its own anchor.

The manager decides whether a validator group may be created at all. Before it
seats one, the committee that group would run under has to derive -- from the
state the group's validator set was computed from, under an anchor this node
established itself, against the chain context it read from its own zero state.

Each of those is load-bearing, and each has a way of quietly going missing:

* Without the call there is no gate at all, and a group is seated on whatever
  the validator set says. What the call then applies is not visible from here --
  it is in the confirmation, and its own suite and mutations pin that it derives
  rather than describes. This file pins that the manager asks, asks once, asks
  inside the activation gate, and hands over its own anchor and context; what
  it must not do is answer the question itself, which is why reaching the
  state-only admission from here fails even with the call still in place. That
  subset was the actual state of this path for a while, and it admitted rosters
  derivation refuses: the chain would not have run unauthenticated, it would
  have stalled, with two admissions giving opposite answers about one set.
* Without an independently established anchor the registry read is filed under
  a coordinate somebody else chose. The anchor here is the node's own applied
  masterchain block, which is why the fields are copied out of it rather than
  assembled from anything a peer sent.
* Without the node's own chain context the domain check confirms its own name,
  because a context taken from the registry under inspection says whatever that
  registry says.
* And a gate that logs instead of refusing is not a gate. Both refusal paths
  have to leave the shard unvalidated rather than continue into group creation.

This file cannot be instantiated by any test here -- it is a member function of
an actor that needs a database, a network and a chain -- so this reads it. That
is weaker than executing it and is not a substitute for an end-to-end run; it is
what can be checked before one exists.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANAGER = "validator/manager.cpp"

CONFIRM = "native_session_identity_confirms("
# The established context, passed rather than constructed here.
CONTEXT = "validator_auth_chain_.value()"
CONTEXT_GUARD = "if (!validator_auth_chain_) {"
# The anchor's fields, each read out of the node's own applied block, plus the
# state root's own hash. A peer-supplied anchor would not name these.
ANCHOR_SOURCES = (
    "auth_anchor.seqno_ = last_masterchain_block_id_.id.seqno;",
    "last_masterchain_block_id_.root_hash.as_slice()",
    "last_masterchain_block_id_.file_hash.as_slice()",
    "state_root->get_hash().as_slice()",
)
# The subset this gate used to apply. Reaching it here again is the regression,
# and it is a regression whether or not the derivation stays beside it.
SUBSET = "admit_masterchain_state("
REFUSAL = "continue;"
STAND_DOWN = "--(shard.is_masterchain() ? active_validator_groups_master_ : active_validator_groups_shard_);"


def gate(text: str) -> str:
    """The region from the activation gate to the group lookup that follows it."""
    start = text.find("if (tos::auth::native_session_binding_active(")
    if start < 0:
        return ""
    end = text.find("if (destroyed_validator_sessions_.contains(", start)
    return text[start:end] if end > start else ""


def verify(files: dict[str, str]) -> None:
    text = files[MANAGER]
    if text.count(CONFIRM) != 1:
        raise ValueError("the manager does not confirm a session exactly once")
    region = gate(text)
    if not region:
        raise ValueError("the manager's session gate cannot be located")
    if CONFIRM not in region:
        raise ValueError("the session confirmation is outside the activation gate")
    if SUBSET in text:
        raise ValueError("the manager admits a state beside the committee it derives")
    if CONTEXT not in region:
        raise ValueError("the confirmation is not given this node's own chain context")
    if CONTEXT_GUARD not in region:
        raise ValueError("a missing chain context does not stop the session")
    for source in ANCHOR_SOURCES:
        if source not in region:
            raise ValueError(f"the anchor is not built from {source}")
    # Two refusals: no context, and a committee that does not derive or confirm.
    # Each has to stand the shard down and leave, not log and carry on.
    if region.count(REFUSAL) < 2 or region.count(STAND_DOWN) < 2:
        raise ValueError("a refused session does not leave the shard unvalidated")


def main() -> int:
    files = {MANAGER: (ROOT / MANAGER).read_text()}

    # A silent checker is not evidence: prove each rule fails when its subject
    # is removed, using the same text the rule is about.
    #
    # Every probe edits inside the gate and splices it back. Editing the whole
    # file instead removes the first match wherever it happens to be -- there
    # are twenty-four `continue;` statements in this file and two of them are
    # this gate's -- so a probe that looks like a removal changes nothing here
    # and survives, which reads exactly like a rule that cannot be broken.
    region = gate(files[MANAGER])
    if not region:
        raise RuntimeError("the gate this checker is about cannot be located")

    def without(old: str, new: str = "", count: int = 1) -> dict[str, str]:
        edited = region.replace(old, new, count)
        if edited == region:
            raise RuntimeError(f"a session admission negative control changed nothing: {old!r}")
        return {MANAGER: files[MANAGER].replace(region, edited, 1)}

    probes = (
        # The confirmation disappearing, which is the gate disappearing: what
        # remains is a group seated on whatever the validator set says.
        without(CONFIRM, "skipped("),
        # The context built here instead of established from the zero state, so
        # the domain check confirms whatever the registry under inspection says.
        without(CONTEXT, "tos::auth::ChainContext{}"),
        # The window right after startup becoming a hole instead of a refusal.
        without(CONTEXT_GUARD, "if (false) {"),
        # The subset returning, beside the derivation rather than instead of it.
        without(CONTEXT_GUARD, f"if (tos::auth::{SUBSET}last_masterchain_state_->root_cell()).ok()) {{"),
        # Each anchor field taken from somewhere other than this node's block.
        *(without(source, "/* removed */") for source in ANCHOR_SOURCES),
        # And the refusals turning into log lines.
        without(STAND_DOWN, "", 2),
        without(REFUSAL, "", 2),
    )
    for probe in probes:
        if probe[MANAGER] == files[MANAGER]:
            raise RuntimeError("a session admission negative control changed nothing")
        try:
            verify(probe)
        except ValueError:
            pass
        else:
            raise RuntimeError("session admission negative control survived")

    try:
        verify(files)
    except ValueError as reason:
        print(f"SESSION-ADMISSION-NOT-WIRED {reason}", file=sys.stderr)
        return 1
    print("PASS: the manager derives the committee a session would run under, from its own applied block and "
          "its own chain context, and refuses the shard when it cannot")
    return 0


if __name__ == "__main__":
    sys.exit(main())
