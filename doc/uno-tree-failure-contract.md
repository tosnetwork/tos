# Tree transition failure contract

The unactivated `NoteTreeState` adapter keeps `td::Result<NoteTreeState>` so
existing `TRY_RESULT` calls preserve errors. `tree-error.h` maps its typed
classifier to the shared `WorkchainExecutionFailure` codes; error text is
diagnostic, not a decision input. The host's local-failure predicate recognizes
both local failures and authenticated-state corruption after propagation.

| Failure | Meaning | Decision constraint |
| --- | --- | --- |
| `CandidateInvalid` | Invalid candidate frontier/commitment encoding or append capacity | May reject the candidate |
| `AuthenticatedStateCorrupt` | Explicitly authenticated frontier violates its structural or tree invariants | Do not blame or vote against the candidate |
| `LocalFailure` | Panic, ABI contract mismatch, unknown status, missing cell/proof, or execution-budget exception | Do not turn local unavailability into consensus rejection |

`from_cell` decodes candidate bytes. `from_authenticated_cell` is a separate,
explicit entry for a caller that has already authenticated the enclosing state;
it does not authenticate a hash or establish data availability itself. Existing
aggregate state decoders still use candidate decoding. A future authenticated
loading path must retain provenance and select the corresponding entry rather
than infer it from a successful parse. This change does not wire a production
engine or admission entry.

The tree ABI uses the same `DECODE` status for a bad frontier and a bad append.
Consequently `append` first validates its immutable prestate with an empty append.
A `DECODE` in that call is state corruption; only after successful prestate
validation can `DECODE` be attributed to the new commitments or reservation.
The additional bounded frontier/root recomputation must be included in D-3
measurements. It is not free or hidden by a proof-verification cost estimate.

`empty` is internally constructed, so even its `DECODE` is local failure. Panic,
arguments, key, unexpected verification and unknown statuses are local in every
entry. No failure publishes a new state. Unknown propagated Status codes are
conservatively local, never evidence that a candidate is invalid.

The independent `test-uno-tree-errors` target supplies an ABI stub, not the Rust
archive. It exercises each returned status at the real adapter call boundary.
The three new tests were each observed failing after removing their respective
property: local-status classification, authenticated-source distinction, and
prestate-before-candidate validation. Assertions inspect classification and ABI
invocation counts, not error strings. The separate `test-uno-tree-cell` target
continues to use the real Rust archive and validates tree transitions/round trips.

A further host-boundary test checks classifications after `TRY_RESULT`, including
both CellBuilder exceptions during encoding. These exceptions also use the shared
local-failure code; a generic Status would not preserve their decision category.
Removing the shared local-code mapping and separately returning a generic Status
for CellCreateError both made this test fail at the host predicate assertion.
