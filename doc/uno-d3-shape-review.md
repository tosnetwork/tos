# Semantic shape witness coverage

This unit extends the test-only meter in `uno/crypto/tests/abi-cost.cpp`, not
production preflight or the ABI. Source base: `9d5f72bf5`; the evidence archive
contains the unit diff and individual guard-removal patches.

Nine isolated cases cover null request, ABI version, profile, null Actions,
null proof, zero Action count, Action limit, proof limit and canonical proof
length. All unrelated metadata remains admissible. In particular, zero count
uses the corresponding 2720-byte canonical proof size, so deleting the count
guard cannot be hidden by the proof-shape guard. Metadata is never passed to the
real ABI; the backend is a non-dereferencing call-count stub.

Each rejection checks the exact Shape result, zero backend calls and unchanged
output. Limits are representable size_t maxima; backend counting uses checked
addition. The fixed loop index and bit flips are fixture selection, not money or
resource accounting. No exception catch or production error mapping is added.

Observed independent mutations: null-request guard removal exits 139 after
printing the case name; the other eight guard removals return Ok and call the
backend once, then the self-test exits 1. Every mutant was built successfully.
All guards were restored and the registered CTest self-test passed. These are
manual historical observations, not a recurring CI mutation facility. The
regression tests themselves run through the existing opt-in crypto CTest gate.

Evidence: `measurements/uno-d3-shape-mutations.tar.gz` includes nine patches,
nine build logs, nine red logs with explicit exit status, the final unit diff,
and restored build/CTest logs. The null-request case was rerun after adding its
pre-call diagnostic; the other eight were run before that diagnostic-only edit.
No performance samples or production limits follow from these fixtures.

Read-only unit review found no blocking issue. Its two suggestions were applied:
the fixture name has a safe fallback and zero-count proof size shares the meter's
base-size constant. The zero-count guard mutation was rerun after that change
and again returned Ok with one backend call and exit 1. The archive also retains
that extra build/red pair and the final reviewed unit diff; restored build/CTest
logs refer to this final source. The original diff remains for interpreting the
earlier eight observations. Review transcript: `~/memo/reviews/uno-d3-shape-review.txt`.
