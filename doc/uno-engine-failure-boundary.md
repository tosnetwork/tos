# Block-engine failure boundary

The resolved execution boundary contains `VmError`, `VmVirtError`, `VmNoGas`,
`CellCreateError` and `CellWriteError`. An escaped exception has no authenticated
provenance: it can have originated in candidate decoding, previous-state access,
or an engine defect. It is therefore reported as `LocalUnavailable`, **not** as
proof that the candidate is invalid. Allocation failures are not reclassified.
The validator's batch replay consumer preserves this code and invokes its local
failure path, rather than voting to reject the candidate. A recognized corrupt
authenticated engine state uses the separate `AuthenticatedStateCorrupt` code
and likewise cannot become a negative candidate vote. These codes are local
control flow, not new wire tags or consensus parameters.

Engines must explicitly validate the representation allowed by each input's
profile, using `load_cell_slice_special` rather than implicit library resolution.
The Counter reference engine accepts an ordinary candidate root only. A
library-ref, pruned branch or Merkle proof candidate root is a deterministic
candidate error; a special root in its authenticated counter state is a distinct
state-corruption error. Native message bodies do **not** inherit that
ordinary-only rule. This change does not connect structural preflight or invent
a production engine profile.

## Merkle updates are not engine-schema validation

`StateInit.data` in `block.tlb` is `Maybe ^Cell`; the executor wrapper also keeps
the engine state as an opaque cell reference. Native Merkle update processing
does not add a counter/UNO schema check. The regression constructs a valid shard
state containing a library cell under executor data, validates and applies its
Merkle update, extracts the identical library-cell hash, and observes the explicit
authenticated-state error from Counter. Thus library cells can be carried by
this transport; this is not evidence that such a state can pass full engine replay
or that an attacker can overwrite authenticated state. No assertion is made that
unresolved pruned branches are valid complete persistent state.

## Scope

This boundary does not retroactively type every legacy host `Status::Error`.
In particular, input acquisition still needs the frozen admission factories and
source-aware classification before preflight can enter consensus paths. Exceptions
must not be used as normal candidate parsing: a candidate-controlled malformed
input reaching the conservative local fallback remains an availability bug in
that engine's parser. No production UNO engine is registered by this patch.

## Regression evidence

`EngineSpecialInputClassification` checks all three special candidate roots,
ordinary success, and the real Merkle-update state path. Replacing the candidate
loader with the former implicit loader terminates with `VmError`. Removing the
authenticated-state category fails the numeric-code assertion (0 versus -7202).
`EngineExceptionIsNotCandidateInvalid` invokes the engine exactly once for each
of the five exception kinds, checks the local category, and verifies preservation
through replay-style error prefixing. Replacing the VM exception's local category
with a generic error fails its numeric-code assertion (0 versus -7201). These are
not assertions on diagnostic text. Validator routing is compile-checked; these
unit tests do not claim an actor/network failure-injection run.
