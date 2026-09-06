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
