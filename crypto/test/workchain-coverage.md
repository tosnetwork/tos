# Private I13c / I13d coverage and read-phase mechanism

Implementation companion to `doc/uno-v2-i13cd-live-integration-shape.md`.
Live collator/validator call sites are not connected by this unit. No activation
or publication permission is created. Ordinary regression does not run this
opt-in harness; the manual private-I13 workflow includes it as the sixth check.

## Independent inputs and outputs

`check_workchain_coverage` consumes immutable old/new ShardAccounts and physical
AccountBlocks roots. It reconstructs both sets anew for each call, then compares
them separately with admitted writes. Success exposes both reconstructed sets;
failure exposes no partial vector. Calling lower-level comparison on hand-built
vectors is a unit check of comparison only, not a root reconstruction claim.

The physical extractor checks the Native AccountBlock frame and key/address
binding, not transaction semantics. Full Native transaction/augmentation
validation and I13a identity/record validation remain separate prerequisites.
It does not consume the I13a count or the overlay construction-loop vector.

The delta walker expands compressed binary prefixes while retaining the source
of each loaded edge. Equal, position-aligned subtree commitments skip unchanged
content; unequal leaves compare the augmentation plus complete ShardAccount
slices, including metadata and account references. It never loads an Account
body to establish a difference.
This is a new structural walker, not a call to the existing mixed-source
`scan_diff` catch boundary. The test cross-checks it against Native scan_diff for
metadata changes and 64 insertion/deletion/prefix-shape combinations.

Native augmentation arithmetic is **not** duplicated or independently verified
by this walker. Callers must retain that validation; a coverage result is not a
general dictionary-validity certificate. In particular, an empty delta is not
proof of equal roots when invalid fork augmentation has not been ruled out.
A deliberately altered leaf extra has its own changed-key control; this does
not waive the independent Native augmentation check. Shared meters are supplied by the
authenticated admission context and are not reset by the mechanism. The private
fixture uses synthetic meter capacities, not production configuration defaults.

Logical key recursion has depth at most 256. Before collecting the next changed
key/participant, the authenticated write bound is checked. Different-subtree
enumeration stops at the first excess key; equal subtrees do not expand. Physical
cells/bits are charged by the shared meters without caching LoadedCell. Temporary
edge frames and vectors are auxiliary work; this unit does not close M6 sizing.

## Representation and classification

Two independent enums are explicit and have no defaults. Representation source
is ReceivedCandidate or AcquiredView, reusing the I13a contract. The checked
object is CandidateClaim, AuthenticatedState, or HostRebuilt. The old root is
always authenticated acquired state. A complete mismatch in an acquired
candidate view is still CandidateInvalid; acquisition provenance controls missing
or pruned representation, not the truth of a completed comparison. Explicit
malformed framing retains the object being parsed. A general provider loading
exception is not evidence of candidate malformation; fault-cell controls exercise
that distinction on the same otherwise valid received representation.
An explicitly observed pruned encoding has source-dependent disposition.
The combined call requires independent source/object pairs for the new state
and AccountBlocks. A host-rebuilt state does not turn candidate AccountBlocks
into host data. The final set comparison preserves each artifact's ownership.

Completed candidate delta/participant mismatches are CandidateInvalid. Local
reconstruction-contract failures are LocalUnavailable. BudgetExceeded and actual
AllocationFailure have different reasons and dispositions. The result is a
private typed outcome, not a new live numeric error-code mapping.

## Synchronous observation

`run_workchain_read_phase` borrows a completed admitted footprint and uses the
original live tree. It installs an observer for the synchronous callback only,
counts repeated and forbidden attempts, retains a sticky footprint failure even
if the callback catches the refusal, and removes the observer before returning.
Message-only callback errors remain errors even when their numeric code is zero.
Unexpected thrown callback exceptions are local observation failures, not
candidate verdicts. Semantic validation must return its established typed Status.

The fixture proves allowed reads occur, forbidden reads are observed, a later
unguarded read is not affected by the destroyed observer, and proof bytes agree
with observation on/off. That last comparison is a private MerkleProof over a
controlled tree, **not** a live collator block-state-proof acceptance claim.
The real block-state-proof comparison remains a live-integration obligation.

## Evidence status

Checkpoint only (coordinator instruction, 2026-09-10): the complete private unit
is not accepted. Eight revised-source controls completed; the ninth was restored
after an interrupted restoration tool lookup. The planned 24 controls remain
incomplete. The coordinator additionally requires preserving exception kinds
through the read-phase result before live reuse; the current catch-all contract
is explicitly not approved for live callers. Commit this state before that edit.

The first positive build/test and static six-test registration have run locally.
Mutation/restoration evidence, final-source review, and full regression are still
pending; no earlier I13c/I13d harness evidence is counted as evidence for this
new implementation. Replace this paragraph only after the final-source controls
and explicit restored-target rebuilds have actually completed.

## Review dispositions in progress

The follow-up review identified separate artifact provenance in the combined
call and source-aware host-rebuild bound failures. Both changes are implemented;
their final-source controls and re-review are required before this unit closes.
Budget provenance is the operation being audited, not the old state's ownership:
candidate-driven work exceeding the authenticated, consistently charged budget
is a candidate violation; a host reconstruction exceeding that same contract
is local. Neither rule permits caller-selected capacities or a node-local charge
history in live acceptance. The private synthetic shared-meter test establishes
charge retention, not that future live callers have supplied canonical charges.
Declared writes must already come from authenticated admission of the candidate;
their order/bound violations are not converted to host-produced declarations.

Other suggestions are not adopted mechanically. `LabelParser` with auto-check
mode zero still executes `parse_label`: `dict.cpp:284` bounds each decoded label
by the supplied remaining width and checks encoded availability; failure clears
`l_offs`, which `is_valid()` tests. The mode suppresses automatic throwing, not
parsing. A duplicate length predicate cannot be triggered independently and is
not added. The maximum remaining width is 256 at entry and decreases per edge.
Likewise `NativeStateReadMeter::read` explicitly maps a null cell to
CellUnavailable before reading it; the null-root control exercises that code,
so a second null predicate is not needed to establish the outcome.

No catch-all is added around boolean slice decoders merely on speculation that
they might throw a VM error. Provider calls are bounded by the explicit reader
catch inventory; allocation failures remain separately caught. The parser is
constructed from an already-loaded slice without automatic throwing validation.
Any additional throwing operation requires a reachable input and its own
source-aware boundary rather than a fabricated failure control.

The synchronous observer permits a genuine no-read callback and therefore does
not require a positive count universally. Positively measured reads and proof
shape controls establish the particular tested path; a zero count alone is not
a no-bypass certificate. Counter saturation is defensive, not a live budget or
a newly assigned consensus classification. It is not claimed as a reachable
admission guard.
