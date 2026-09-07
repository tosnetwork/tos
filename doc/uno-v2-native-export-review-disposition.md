# Shared Native export encoder: boundary review disposition

The production collator and private multi-account queue constructor now share
the MsgEnvelope / OutMsg / EnqueuedMsg encoder. Routing, deferral choices,
metadata selection, queue ownership, resource accounting and both existing
source-equals-transaction checks remain unchanged. This is not V2 activation.

The read-only boundary review found no demonstrated defect in the encoding
refactor. It checked tags, widths, reference order, uint64 LT bit preservation,
builder reset behavior, dictionary insertion semantics and queue-key parity
against source. This is source-level evidence, not exhaustive runtime proof.
Verbatim review: `~/memo/reviews/uno-v2-native-export-codec-review.txt`.

## Accepted and addressed

- Added a fixed-field envelope wire oracle independent of the hand-written
  envelope pack/unpack pair. Generated OutMsg and EnqueuedMsg packers remain
  independent record oracles. The sweep covers both tags, metadata absent or
  present, and LT 0 / 22 / UINT64_MAX. Address zeroing is explicitly caller
  policy; the encoder does not decide it.
- Check Result success before extracting the test value. Assert the ordinary
  queue's Native minimum-LT augmentation (22), not only export-value totals.
- Replace the unreachable fresh-builder capacity-error branch with an explicit
  missing-transaction check. Fixed bit/ref capacities are documented as
  structural invariants. Null transaction behavior has a direct negative case.
- Exercise both ordinary and deferred production-collator calls with rebuilt
  disk controls, not only the private queue helper. The disk harness remains
  an offline-manager test, not distributed-consensus evidence.

## Disputed or deliberately retained

**Result does not imply noexcept.** Do not fold Cell construction exceptions
into a plain Status merely to make the signature look exception-free. The
existing contract explicitly preserves exception class and input provenance.
In addition, `finalize_novm_nothrow` is not a drop-in replacement for `finalize`:
it bypasses active VM-state hooks. No catch or voting error category is added.
The collator retains its prior CHECK boundary for local encoding invariants.

**The surrounding VmError catch is not broadened here.** CellCreateError and
CellWriteError remain distinct non-VmError types. The previous code did not
catch them either. Their source-aware handling at the full V2 execution boundary
remains required; this refactor does not claim to close that obligation.

**One extra temporary Cell per deferred enqueue is accepted explicitly.** The
plain dictionary previously appended a builder directly. The shared encoder
materializes its 64-bit/one-ref record first. No extra persistent Cell is
introduced in the queue layout; non-deferred augmentation already materialized
the same temporary Cell. This is a bounded allocation/hash cost, not a measured
performance improvement. Avoiding it can be revisited with profiling, without
inventing a new consensus policy now.

## Evidence and limits

Exact rebuilt controls, runtime output, source/binary hashes and restored
regressions are in `measurements/uno-v2-native-export-evidence.json`. Manual
removal controls are not recurring mutation CI. Neither this review nor the
disk harness proves live multi-account validation, source exceptions, DA,
configuration binding or atomic full-block publication. M1 remains incomplete.
