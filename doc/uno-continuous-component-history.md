# Continuous component history prerequisite

This fixture advances the existing NoteState through five blocks, two fresh
nullifiers and two commitments per block. Each block is serialized, decoded
into a new Cell arena, and restored before the next event. This is a reachable
component event sequence, not proof-bearing transactions, authorized minting,
Reserve settlement, a production candidate source or a storage schema.

Unlike the earlier envelope pilot's repeated-root anchor window, each event
produces a distinct real tree root. A three-entry window is checked against
all prior roots after every restoration, including exact eviction. The tree
root is cross-checked against rebuilding the full commitment prefix rather
than merely repeating the incremental call. Every old nullifier remains used;
replaying an event against the current anchor fails without changing the source
state. Position and used counts match the independent accumulated inputs.

`test-uno-note-continuous-history` is registered in CTest, fails on a zero-test
filter, and uses the existing all-tests dependency and opt-in Rust component
build. It needs no environment variables or external service. Counter updates
are checked; narrowing has an explicit bound; the history-distance subtraction
uses an index proven not greater than the vector size. No new production error
classification or exception handler was introduced.

Source base `3d18fb8bb` plus the final source patch in
`measurements/uno-continuous-component-history.tar.gz`. Removing the event from
the actual apply call (an otherwise valid empty block) makes the root comparison
fail and CTest exit 8. The restored continuous test and earlier component smoke
pass. Logs and the exact mutant are archived; this is a manual historical
mutation, not an automated mutation pipeline. External milestone review remains
pending under the current cadence.

This closes only a history-generation prerequisite. Commitments and nullifiers
are synthetic; no prior Note ownership, spend witness, signature or proof is
established. No latency or capacity conclusion follows from this small fixture.
It does not replace the required continuous proof-valid sample, mixed pending
and terminal history, large-state experiment or persisted directory comparison.
No partition, accumulator, Reserve or wire implementation is authorized by it.

## Delayed refund follow-up

Source base `9b3133d0f` plus the patch in
`measurements/uno-delayed-refund-history.tar.gz` extends the same registered
test. A two-key reservation exists before the five intervening blocks and is
restored with each state. Ordinary actions targeting either reservation are
not authorized by this model; the test probes one of the reserved keys at each
height and requires rejection without a source-state change. Both keys remain
reserved and unused throughout the intervening history.

At height six the test driver invokes the existing refund primitive, appends
its two commitments and advances the anchor. After another BoC restoration,
used count and tree position are twelve, reserved leaves are zero, both refund
keys are permanently used, and repeating the refund fails. The pending source
root remains unchanged. This models component ordering, not a verified Failed
Ack, authenticated refund bundle, money movement or a new settlement protocol.

Removing the production reserved-key guard temporarily makes the ordinary
collision event succeed, failing the rejection assertion (CTest exit 8).
Restoring it and separately omitting the refund tree append fails the paired
used-count/tree-position invariant (exit 8). All temporary production changes
are restored; only test and evidence changes remain. The restored continuous
test and previous envelope smoke pass. Exact patches and diagnostic logs are
archived; external review remains pending at the milestone.

This is a small mixed sequence, not the large/mixed owner population, full
capacity reservation, root-only witness refresh or partition split experiment.
It supplies no production storage limit or timing claim.
