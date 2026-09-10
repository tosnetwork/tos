# Binding-owner preparation checkpoint

Seam preparation based on `99160542e`. This is not completion of
the coroutine execution seam, nor live suspension/cancellation evidence.

The owner factory publishes the resolved binding and configured adapter as one
object. Its constructor and fields are private; it cannot be copied or moved.
The actor moves only its unique owner. Explicit release consumes that owner,
destroys the adapter before sampling configuration ownership, then destroys the
binding. Ordinary object destruction also destroys both halves in that order.

Two earlier checkpoint behavioral controls compiled and failed at their named
direct assertions: omission of adapter release, and unconditional factory
rejection. Each restored all four measured source files exactly, explicitly
rebuilt both test-workchain-settlement-continuation and test-tos-collator, then
passed the full continuation executable. The normal registered continuation
CTest also passed before mutation. These records do not count compile-time
constructor-access assertions as runtime mutations. They remain historical in
`checkpoint-owner-only`, not evidence for the final source.

The final cohort in `final-controls` contains five controls on the final seven
source files: omitted adapter reset, unconditional bind rejection, swapped
candidate/declarations roots, and independently fabricated defaults for either
missing root. Each compiled and failed at its named assertion, then restored
all seven hashes and passed the rebuilt continuation executable. Run
`verify-restore.py` to reconstruct the mutants without applying them.

The continuation fixture manually supplies authenticated-policy stand-ins and
separate candidate/declaration roots. It does not establish a production input
source. The existing singleton CollatorOptions callback supplies only an opaque
candidate root; no candidate-plus-declarations carrier was found in either
branch (B independently confirmed at `535cc909b`). Extending the host source API
must preserve singleton callback meaning and must not infer declarations from
an engine-specific payload. This unit adds the shared
`block::WorkchainAccountCandidate` in `crypto/block/workchain-account-candidate.h`:
an explicit two-root constructor and candidate()/declarations() accessors only.
It preserves missing roots, performs no parsing and carries no derived identity,
count, coverage, admission token or verdict. The optional CollateParams field
and separate CollatorOptions callback are transport interfaces, not active
acquisition or admission call sites yet. No execution or activation gate has
moved here. Validator reconstruction must not consume collator conclusions;
shared transport is not shared I13 interpretation or judgement.

Failure, completion and cancellation on the actual collator coroutine, and
same adapter identity across real suspension, still require independent live
controls. The two controls here do not substitute for them. This checkpoint is
not a full-regression or completed-review claim.

Explicit release timing is unchanged: fatal_error releases before deciding to
launch a retry and before moving stats; return_block_candidate releases before
finalizing and moving successful stats. Destruction is only the fallback and
does not write telemetry into a moved-from stats object. Live controls must
observe the old owner gone when a new attempt starts, and inspect the delivered
stats for account_adapter_released, not merely read a field after destruction.
The private owner-destructor test establishes neither of those timing claims.

Review disposition: the intermediate count assertion checks the sampled value,
not an independently observed adapter-destructor event. A replacement that
fabricates that count can pass; no claim of independent midpoint destruction
measurement is made. The adapter owns a configuration reference itself, so
member ordering is not a memory-safety dependency. Public accessors produce
borrows which must not outlive the owner; indivisible ownership is not a general
C++ borrow checker. Negative bind tests exercise the delegated existing adapter
validation, not newly introduced guards. A production-shaped move case now
checks consumption and reference accounting separately from copied fixtures.

The review also compiled while reading the mutable tree. An in-flight compiler
can finish after a header mutation and leave a stale object with a newer mtime.
Earlier incremental controls are therefore checkpoints only. The final cohort
runs after that review exits, deletes only the exact compiler object paths
which Ninja records as dependent on the mutated header, then explicitly builds
the two executable targets. Each forced-object list is archived. Restoration
uses the same procedure. No source files are deleted by this step.

The review's description of fatal_error as always a local verdict is not the
host contract: it preserves the supplied typed Status into stats and the final
promise. This preparation adds only a local allocation failure; later candidate
failures must not be recategorized merely because that delivery function is
called fatal_error.

Submission boundary: the coordinator accepted the owner preparation and
requested this checkpoint be committed before connecting the coroutine branch.
The complete default build (`cmake --build build -j32`) and registered
continuation test passed. The ordinary 130-test regression was still running
at this checkpoint; no full-regression pass is claimed. Five final mutations
reconstruct and all seven measured source hashes match their restored hashes.
The remaining refusal-string counts are collator 1 and validator 3, plus the
separate registry readiness boundary. No execution seam is closed here.

The combined acquisition callback is an unused draft, not a frozen acquisition
contract: it does not structurally deny its producer access to the candidate
while obtaining declarations. Connection must separate that acquisition; merely
holding two distinct roots is not evidence for this additional requirement.
The shared two-root carrier API itself is transport-only and ready for reuse.
