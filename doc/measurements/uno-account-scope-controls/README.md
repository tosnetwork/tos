# Distinct account-batch candidate pairing

Base checkpoint: `98508fcfe`. This is the candidate-family check required by
the coroutine connection, not an execution-seam or activation claim.

The old checker accepts any non-null single root as BlockTransition. The
positive `scope.legacy_nonnull_positive` reproduces that exact property with
the same candidate used in a two-root account carrier. Input admission requires
both candidate and declarations (`BatchInputAdmissionSession::admit` rejects
either missing root), so a single-root check cannot establish account pairing.

`AccountBatch = 2` is additive; the existing enum values and single-root
overload are unchanged. The new carrier overload requires AccountBatch and
both roots. It rejects BlockTransition even when candidate is non-null. It
performs no parsing, resource admission, provenance inference or classification.
A host acquiring unavailable declarations must apply its source-specific local
failure policy; a validator must independently classify kind and source.

The final-source cohort is in `final/`; root-level records are the earlier
pre-review checkpoint, not final-source evidence. Three controls compile, fail at their exact direct assertions, restore all
three source files byte-for-byte, explicitly rebuild both the continuation
executable and the disk collator tool, and pass the restored continuation run:

- `singleton-fallback`: reintroduce legacy candidate-only validation for
  BlockTransition; fails at `scope.account_not_singleton`.
- `missing-candidate`: omit candidate presence; fails at `scope.missing_candidate`.
- `missing-declarations`: omit declarations presence; fails at `scope.missing_declarations`.

Positive controls accept a complete AccountBatch and retain legacy singleton
and ordinary pairing. The complete continuation run also executes the existing
private settlement scenarios. This is not the requested legacy live callback
execution control, which belongs to connection acceptance.

Information erasure remains explicit: passing only `carrier.candidate()` to
the legacy overload still passes, because no single cell identifies its host
execution family. The eventual account-binding call site must pass the carrier
and explicitly select AccountBatch; these private checks do not prove that
not-yet-connected call site does so.

Registry `execution_scope()` still groups block and account engines under
BlockTransition to describe whole-block execution. Its current documented
meaning and resolver fallback are unchanged here. Do not use that registry
value to infer this candidate pairing. Transaction description validation is
also unchanged; adding a candidate scope does not authorize a wire constructor.

The collator and validator refusal-string counts remain 1 and 3. No gate moved,
no private result was substituted for a live candidate, and no failure,
cancellation or completion lifetime evidence is claimed by this unit.

Related regression: both `test-workchain-block` and
`test-workchain-settlement-continuation` were explicitly rebuilt, then their
registered CTests passed (2/2, zero skips). Raw output and JUnit are retained.
This is not a new complete-default-build or whole-suite regression claim.
Independent read-only review completed. The comment now states that no
relationship between the roots' contents is established. The stripping
demonstration literally passes `batch.candidate()`; the legacy overload is
tested rejecting AccountBatch for both non-null and null roots. After these
changes, the controls and regression are repeated in `final/`.

Review dispositions and compile-time limit:

- Preserving the legacy `(Ref<Cell>, scope)` API and the carrier's public
  root accessors necessarily preserves the stripped-root call. Its static type
  is indistinguishable from a legitimate singleton root. Deleting AccountBatch
  support from that overload cannot prevent a caller choosing BlockTransition.
  Hiding roots or introducing non-convertible root capabilities would change
  acquisition/admission consumers, not just this checker. No such redesign is
  included. Keeping the whole carrier at the future account call site remains
  explicit discipline, guarded here by `singleton-fallback`; this does not
  replace a future mutation at the real call site.
- The carrier's no-default-constructor contract is already statically tested;
  it also preserves overload resolution of existing bare `{}` legacy calls.
- The two existing transaction-scope loops enumerate the legacy wire scopes,
  not the new carrier scope. No transaction description gains AccountBatch
  acceptance: the decoder's assigned expected values remain the two legacy
  values. Those tests and the registry source are unchanged, not claimed as
  evidence of a new account transaction validator.
- Status messages are diagnostics, not a source classification API. This
  checker makes no CandidateInvalid/LocalUnavailable decision. Live callers
  must keep their acquisition provenance; no new message-based classifier is
  authorized by these tests.

Final validation: 3/3 mutations reconstructed from the final source, both
relevant registered CTests passed (2/2, zero skips) after explicit rebuilds.
The separate removed-domain scan exits 1 with the same five Counter fixture
tag-comment path hits present before this unit. Its raw output is retained;
no exception or fixture was changed and no all-gates-green claim is made.
Raw CTest JUnit is retained without whitespace normalization; its tab-indented
XML triggers the repository's tab-in-indent diff check. Source-only diff check
passes. No ignore or whitespace rule was broadened for these artifacts.
