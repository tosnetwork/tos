# Queue and codec follow-up repair, 2026-10-22

Source parent: `a5c4834e833a1ee15d2ca95be6facea7ae078655`. This report supersedes
the conditional acceptance of the corrections in
[the initial review](a-class-review-20261022.md). The adjacent JSON records
source hashes, test commands, and bounded failure receipts for this repair.

## Ordered queue admission

The state limit applies to the final queue, not each intermediate insertion.
Stopping at a full queue's earliest foreign transit also blocked a later local
delivery that could release capacity. For example, `18000 -> 18001 -> 18000`
is valid at the final capacity boundary and must remain available in input order.

The initial collation pass now keeps that order and the existing block, proof,
time and cancellation limits. It records whether a transit borrowed capacity,
including capacity reserved for dispatched messages. After inbound processing,
and again after all generated and tock messages are handled, the collator checks
the same final-size predicate as the validator. The effective cap is the greater
of the configured hard limit and the previous size **recorded in state**. The
check is enabled under the same queue-size storage capability as validation.

An oversized result is discarded before state/block serialization or candidate
publication. The existing retry mechanism starts a new collator from the previous
state; any pass that borrowed capacity makes subsequent retries use strict
admission. This also applies if the speculative pass fails for another reason.
Strict admission includes pending dispatch reservations, and never advances the
merger or processed frontier past a postponed message. Existing attempt limits,
deadlines, cancellation and hardfork restrictions are retained.

The early final-size check is safe because later stages cannot delete an old
outbound queue entry. It checks the actual size, not size plus pending dispatch:
when inbound queues are empty, a pending dispatch can still be delivered locally.

The new tests call the real collator's ordered inbound loop, ordinary transaction
commit, queue dictionary operations, dispatch extraction/flush, processed-frontier
update, final-size check and retry-parameter construction. Cases cover:

- One or multiple transits followed by local drains, including 18000 actual entries.
- Unrepaid capacity, strict retry without frontier advancement, and dispatch reservations.
- Block-size exhaustion, timeout, recorded old-size allowance and absent size records.
- Queue-neutral own requeues and foreign final deliveries at capacity.

Four independently compiled production mutations must fail: restoring the
unconditional queue-head stop, removing the final cap, losing strict retry state,
and ignoring dispatch reservations.

## Lossless codec compatibility

Canonical balance detection belongs to the encoding optimization. A shared
extractor had also narrowed decoding, rejecting earlier streams that used a
leading-zero left balance. Simply restoring numeric parsing is insufficient:
canonical and earlier numeric decoders accumulate noncanonical child deltas
differently, so either interpretation alone rejects valid historical output.

Decoding first uses canonical deltas. Only if that pass actually observes a
noncanonical balance and fails does it retry the earlier numeric interpretation.
There are at most two complete passes, with the first graph released before the
second. Both passes retain the same size, graph and cell/MerkleUpdate hash checks.
The fallback has dedicated size-limit and corrupted-hash rejection tests.

Encoding tracks both child-delta interpretations per edge. It elides a canonical
node only when both reconstruct exactly the original value. Otherwise it retains
the original payload. Three frozen compressed fixtures (401 bytes total) preserve
the two historical interpretations independently of the current encoder.

The compression module has 68 passing cases, including mixed encodings and
repeated edges. Removing the fallback, selecting numeric-only decoding, or
dropping either encoder delta comparison fails the respective regression test.
An additional local probe checked 162 shapes in both native directions; its 150
mixed cases also decoded with the earlier numeric Rust implementation.

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

No persistent collection, cache, actor, thread, file or timer is added. Queue
speculation adds two booleans across the request/actor and retains the existing
input-work, block/proof-size and deadline bounds; failed state is released with
the old actor. Retry count is unchanged. Codec work can double only on the
specified compatibility path; its configured maximum allocation is unchanged.

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
