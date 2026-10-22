# Queue and codec follow-up repair, 2026-10-22

Source parent: `a5c4834e833a1ee15d2ca95be6facea7ae078655`. This report supersedes
the conditional acceptance of the corrections in
[the initial review](a-class-review-20261022.md). The adjacent JSON records
source hashes, test commands, and bounded failure receipts for this repair.

## Queue admission: speculative pass withdrawn

`b687d122d` replaced the strict transit admission of `c93b956aa` with a
speculative pass: transits could borrow capacity, an oversized final queue
failed the collation, and the repeated collation used strict admission. That
design is withdrawn by owner decision; the strict admission of `c93b956aa` is
restored unchanged.

The repeated collation copies the original `CollateParams`, whose deadlines are
absolute. A shard block producer sets `soft_timeout` and `wait_externals_until`
to the slot start, so the collator's internal-message and queue-cleanup
deadlines are that instant. A retry starts after the speculative pass has used
the slot, so its inbound loop stops before the first message and its cleanup
before the first entry. It produces an almost empty block that does not shrink
the queue, and the next slot repeats the overflow from nearly the same state.
The speculative tests gave both passes 60-second deadlines and so could not
reach this path.

Strict admission stops at the first foreign transit that would need a slot
when the queue, plus messages reserved for dispatch, is at the configured hard
limit. It never advances the merger or the processed frontier past that
message. Final deliveries, own requeues and already processed messages do not
grow the queue and remain admitted. The known cost is head-of-line blocking: a
later delivery that would free a slot waits until neighbours consume part of
this shard's queue. That limitation is follow-up 1 of the initial review.

The real-collator harness is kept, with expectations for strict admission:
transits postponed at capacity (including 18000 entries), imported below it
(the last free slot taken, the next transit postponed), block-size and timeout
budgets, dispatch reservations, a recorded oversized queue that may not grow,
neutral imports at capacity, and the head-of-line stop. Every case also checks
that the final size satisfies the validator's hard-limit rule.

Local receipt (Linux x86-64, `tos-builder-local:24`, Release, clang 21): the
`queue-codec` inventory and its three CTest entries pass, with 15 cases in
`test-out-msg-queue-limits`. Three collator mutations, each rebuilt and run
alone, fail the expected case: skipping the admission check
(`RealCollatorPostponesTransitAtCapacity`), ignoring dispatch reservations
(`RealCollatorReservesDispatchedMessages`), and advancing the processed
frontier past a postponed transit (`RealCollatorPostponesTransitAtCapacity`).
The restored source passes again. Remote x86-64, arm64 and ASan CI must still
pass on the pushed commit.

## Codec: one balance interpretation

`b687d122d` added a two-pass decoder that retried with a numeric interpretation
of leading-zero balances, and an encoder that elided only where both
interpretations agreed. That compatibility path is withdrawn by owner decision:
the network is pre-launch and keeps no old encodings.

The native codec reads a balance through `VarUInteger::as_integer_skip`, which
rejects a leading-zero length-prefixed encoding. A noncanonical DepthBalanceInfo
therefore has no balance there: it contributes no delta and is never elided, in
encoding and in decoding. The numeric interpretation came only from the earlier
Rust implementation and was never the native behaviour. The Rust codec returns
to the single canonical interpretation of `fddbcbc2e`, the same as the native one.

The frozen native fixture `native_noncanonical_child_ct9.boc` stays: it decodes
to the expected tree, and re-encoding makes the same single elision. The mixed
encoding test now expects the parent to be elided exactly when its own balance
is unchanged. The two legacy fixtures and their tests are deleted.

Local receipt (Linux x86-64): `run-boc-compression-tests.py --rust` passes 66
cases with the required selection. Making the extractor accept leading-zero
balances (the numeric interpretation) fails the native fixture, the
noncanonical non-elision and the mixed encoding tests; the restored source passes.

## Execution and scope

Reproduce the native selection after configuring the normal build:

```sh
cmake --build build --target test-out-msg-queue-limits test-validate-query-rules test-db
python3 scripts/check-ctest-inventory.py --build-dir build --label queue-codec \
  --exact test-out-msg-queue-limits test-validate-query-rules boc-compression
ctest --test-dir build -L queue-codec --no-tests=error --output-on-failure
python3 scripts/run-boc-compression-tests.py --rust
```

These native suites are now executed by strict-build, the existing x86-64/arm64
native matrix, and the instrumented network-safety build. The Rust workspace job
executes the compression module rather than only compiling it. Inventory and
runner checks reject missing, empty, ignored, incomplete or failed selections.
CI success must be checked on the final pushed commit; local results are not a
claim that those remote gates have passed.

No persistent collection, cache, actor, thread, file or timer is added. Strict
queue admission adds no state beyond a per-message flag and retains the existing
input-work, block/proof-size and deadline bounds. Decoding is a single pass with
its configured maximum allocation unchanged.

The real-collator tests are not a complete historical-state or serialized
candidate-to-ValidateQuery replay. They do not prove general network liveness.
The routing example needs deeper splits than the canonical genesis permits.
The upstream-shared narrow hard/soft-gap limitation remains an explicit
deployment/configuration constraint; this repair does not change deferral
consensus rules. [The parameter checklist](../ConfigParam.md#queue-limit-proposals-and-collator-settings)
records the coupled assumptions and recovery prerequisites. Fresh epoch-5/global-16
deployment remains the scope; epoch-4 replay is still manual pending a new corpus.

## Instrumented-link follow-up

The [Linux ASan job for `b687d122d`](https://github.com/tosnetwork/tos/actions/runs/39782207748/job/119836050755)
passed all 26 network-safety tests, then failed to link `test-out-msg-queue-limits`
and `test-validate-query-rules`: `fabric.cpp.o` referenced the `ApplyBlock` vtable,
but neither test linked its implementation in the `validator-common` object
library. The normal optimized build had discarded that unused factory path.

Both test targets now link `validator-common` explicitly, following the existing
external-message tests. Production sources, sanitizer options and test selections
are unchanged. The normal build and all three `queue-codec` CTest entries pass.
A local link control retained the actual `run_apply_block_query` factory:
both original link dependency sets failed with the missing `ApplyBlock` vtable,
and both corrected dependency sets linked successfully. This control is evidence
for dependency closure only; mixed instrumented and uninstrumented objects are
not a valid ASan runtime test. The full homogeneous Linux ASan job must pass on
the new commit before this gate is considered cleared.

### Homogeneous Debug and Release verification

A clean Debug build with `TOS_USE_ASAN=ON` reproduced both original vtable
failures. Adding `validator-common` alone then exposed unresolved
`PersistentStateImportResult` and `CellDbGcPauseLease` symbols: its downloader
objects also require the production `validator-db` objects. Both test targets
therefore link both object libraries directly, following the existing
integration-test pattern.

In the builder image, Debug with ASan and Release each built all three targets
and passed the exact `queue-codec` inventory and all three CTest entries
(14 queue, four validation-rule and 13 codec cases). The source-guard selection
passed all 58 entries. Sanitizer options, test assertions and production sources
are unchanged. These are local receipts; remote CI must still pass on the final
head. The earlier review of `a5c4834e8` does not cover the substantive queue and
codec repair in `b687d122d`, which requires fresh independent review.
