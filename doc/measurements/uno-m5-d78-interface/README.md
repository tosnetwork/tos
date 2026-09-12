# D78 encoding interface handoff

Current applicability: memo a131b9bb, SHA256 prefix 187dbc79290d6816.
Implementation began against f3f3b0d7/ad40640086c95b78; the subsequent anchor
updates did not change D78. Baseline: 2e2738c79.

Committed total is checked x+q, never x+q+f. Debit remains a separate host
obligation. SEND equations, witnesses and ranges are unchanged. No V_max
constructor gate was added. There is no reserve field or migration branch.
Withdrawal ABI is WithdrawalVerifyRequestV2 / uno_crypto_verify_withdrawal_v2,
abi_version=2. The old symbol is absent: an old host must fail to build rather
than silently call a changed statement. TL-B Withdrawal data/context/record/
control and account root use v2; account schema is 4. Identity/Attempt identity
and timing keep their unchanged v1 forms. Old data, record, control and full
account fixtures are rejected, not reinterpreted. Dictionary ID keys, explicit
created_lt uniqueness, independently enumerated count and nonempty-close
rejection remain in force.

**Context unchanged at 566, confirmed independently.** The C++ encoder measures
566; the Rust final statement wrapper measures 684. Inline amounts occur in
the wrapper, not the common host envelope. No host context metering length or
boundary length registration was changed. A owns wrapper/ABI registrations
and host integration and has been told the exact interface before switching.

## Fresh evidence and limits

- Crypto library: 28/28 passed in this work session (tool output; no archived
  raw log). Relevant changes are the constructor and dedicated ABI.
- Real prover Withdrawal tests: 5/5, prover-final.log; includes frozen v2 proof
  verification, wrong generated points, malformed version, public-total
  overflow and the existing smaller-debit adversarial proof.
- C++ complete codec test translation unit: 11/11, cpp-final.log. Compiled the
  new generated block-auto.cpp explicitly and linked Native dependencies.
  This is a focused executable, not the complete Native/default CTest suite.
- fee-in-total.log: adding f to T fails the expected 154 total assertion
  (165 observed). unchecked-total.log: replacing checked sum by wrapping
  fails the overflow rejection assertion. Both are exit 101.
- record-mutant.log: removing only record checked-total validation fails
  encode_workchain_withdrawal_record(value).is_error(), exit 1. Restoration
  passes; final 11/11 includes old-tag rejection and exact new BOC vectors.

Controls identify a semantic change and its intended assertion, never an error
message string. A mutation must be shown applied and must reach that assertion;
an earlier setup/compiler failure is not evidence. The isolated Rust controls
initially lacked fixture includes and the old-account build initially mixed two
generated headers; those setup failures were corrected and are not counted red.

Version-separated vectors live in crypto/test/workchain-m5-d78-vectors. Their
README distinguishes old samples and freshly generated proof/BOC inputs. Prior
live greens remain valid only for their original code and scope; none is
relabeled as D78 validation. Historical predictions and measurement parameter
sources have not been rewritten.

## Handoff boundary

This is a tested encoding/crypto interface checkpoint, not a full host build.
A must switch the backend overloads, authorized host reconstruction, callers,
configuration, metering/ABI registration and structural guard fields to this
interface before integrated execution. Full Native compilation is not claimed
at this intermediate interface commit. No post-D78 live run is claimed. B's
D78 contract and prediction updates are a separate remaining deliverable.

## Additional independent relation replay

`crypto/test/workchain-d78-independent-review.py` archives c7a6f62e8 and injects
its companion test source. The original `workchain-d64-independent-review.py`
still archives 5f628635d and therefore correctly keeps its old b fixture; it is
not a current-interface consumer. Both old files are preserved byte-for-byte.
The new replay changes only the public fixture total 140 -> 117 and overflow
inputs. Its dense 8x6 matrix, targets and six active range objects are unchanged.
Baseline 2/2; witness-index mutation exit101 at the matrix test; range-object
mutation exit101 at the same test; restored2/2. See matrix-replay.log. These are
independent matrix-construction checks, not a proof-system audit or Native run.
