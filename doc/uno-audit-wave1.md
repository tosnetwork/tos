# Audit wave 1: failure provenance and exception boundaries

This wave covers B5-2, B3-2, B5-5 and the D-2 type boundary. No production
preflight admission, partition schema, participant transaction format or
Reserve implementation is added.

- Tree and host share a local error-code domain. CandidateInvalid,
  AuthenticatedStateCorrupt and LocalUnavailable survive Result/TRY_RESULT;
  the validator's batch replay consumer routes the latter two to local failure,
  never a candidate rejection. Tree PANIC and unknown ABI statuses are local.
  Frontier restoration and new commitments are checked separately because the
  ABI's DECODE status alone cannot identify which input failed. The extra tree
  recomputation is a D-3 measurement cost, not a free optimization.
- Counter explicitly inspects special cells. A valid Native MerkleUpdate can
  carry a library cell in opaque engine_state; that is not evidence that full
  batch replay accepts it. Unclassified engine VM/Cell exceptions are contained
  conservatively as local failures, not automatically treated as invalid input.
- Nullifier low-level bool queries retain a documented throwing contract.
  `try_contains`, `try_is_used`, `try_is_reserved` are exception-containing
  Result<bool> boundaries. An unavailable lookup never means absence; the caller
  still owns provenance classification.
- The isolated candidate admission factory exposes a variant result with a
  privately constructed, fully detached AdmittedInput. It preserves the first
  typed result and does not trust is_loaded(). ConfigInvalid is independent;
  an unsupported resolved admission version is local inability, not evidence
  against a candidate. Full inbox/root/session adapters remain unimplemented.

Regression instruments were deliberately broken and restored: tree status and
source classification, prestate ordering, shared host-code propagation,
CellBuilder classification, Counter special parsing, engine exception category,
authenticated-state category, lookup failure-as-false and missing catch,
candidate ownership, sticky acquisition, special classification, and zero-limit
configuration validation. Failures inspect enums, load counts, usable detached
children or actual exception escape, not diagnostic strings. Detailed logs and
scope are in the three boundary notes and the wave1/b5-5 build logs.

The validator branch is compiled in the production validator-engine. This wave
does not claim an actor/network failure-injection acceptance run, nor that every
legacy acquisition helper has been provenance-typed. Those earlier input paths
must be audited when D-1/D-2 adapters are wired. Native message bodies do not
inherit the ordinary-only candidate restriction.
