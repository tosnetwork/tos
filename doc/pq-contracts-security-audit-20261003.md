# PR #128 security review — 2026-10-03

## Scope and revision

Repository: `tosnetwork/tos`. PR: #128, **Add ML-DSA-44 quorum signatures and a
relayer-funded post-quantum high-volume wallet**. Reviewed input revision:
`5195571a49b40153823669b234ea5597a8af76da`, branch `pq-quorum-and-highload`,
base `bc9ca41d9357a02ef614df8711cbaf27dd3e6495`.

The review follows the FunC and Tol quorum implementations, the wallet's request,
message and signature parsing, replay-guard integration, relayer funding/refund,
deployment checks, test harnesses and relevant C++ action-phase behavior. This is a
source-level security review, not a new independent audit of ML-DSA's mathematical
construction or a production network/load certification.

Two findings were patched directly on the existing PR branch. No merge or deployment
was requested or performed. The quorum libraries, signature contexts, signed request
layout, stored state layout and native ML-DSA implementation are unchanged.

## F1 — Medium: reserved extra_flags silently skip a signed payment and consume its id

### Observation and cause

The original `require_valid_message` reads the VarUInteger 16 between the extra-currency
map and `fwd_fee` as `m~load_coins(); ;; ihr_fee`, discarding it without validation.
Since global version 12 this field is `extra_flags`; both supported PQ versions (16
and 18) use that interpretation.

The executor's `try_action_send_msg` checks `extra_flags_within_valid_mask`. The active
mask is **3**, defined by `tol/extra-flags-constants.h`: bits 0 and 1 are permitted,
while bits 2 and above are reserved. Invalid flags reach `check_skip_invalid(45)`.
Because the wallet forces send mode +2, an invalid-flags payment is skipped rather
than aborting the action phase. The refund and other valid payments may still succeed,
so the wallet persists the query id even though the flagged payment was not sent.

This contradicts the wallet policy of refusing statically invalid batch entries whole
before verification, analogous to its existing reserved-send-mode checks.

### Trigger and impact

An owner-signed batch containing a payment with `extra_flags=4`, `8`, or another
reserved bit passes the former compute-time message check. Submission can therefore
complete with that payment absent and the original query id consumed. A mixed batch
can execute only its other payments.

This is a signed-message validation / payment-reliability defect, **not an
unauthenticated signature forgery or arbitrary-funds theft**. The relayer cannot alter
flags in an otherwise valid signed request without invalidating its signature. A
signing client or owner must have produced the malformed signed payment.

### Patch

`crypto/smartcont/pq-highload-wallet-code.fc` now declares
`MESSAGE_EXTRA_FLAGS_ALLOWED = 3`, naming the matching executor constant, and checks:

```func
int extra_flags = m~load_coins();
throw_unless(error::invalid_message,
             (extra_flags & MESSAGE_EXTRA_FLAGS_ALLOWED) == extra_flags);
```

The check executes inside `checked_batch`, before ML-DSA verification, replay recording,
state persistence or queuing any refund/business action. Values 0, 1, 2 and 3 remain
accepted, matching the executor exactly. A rejected batch leaves its query id usable;
a corrected batch must be signed again because its request hash changes.

Source references at the reviewed revision:

- [Wallet parser and request order](https://github.com/tosnetwork/tos/blob/5195571a49b40153823669b234ea5597a8af76da/crypto/smartcont/pq-highload-wallet-code.fc)
- [Executor extra_flags validation and skip behavior](https://github.com/tosnetwork/tos/blob/5195571a49b40153823669b234ea5597a8af76da/crypto/block/transaction.cpp)
- [Active flag mask](https://github.com/tosnetwork/tos/blob/5195571a49b40153823669b234ea5597a8af76da/tol/extra-flags-constants.h)

## F2 — Low: fee getter quotes unsupported batch counts

`get_required_value` formerly forwarded an unrestricted integer to the linear fee
calculation, although accepted batches contain exactly 1..254 actions. In particular,
zero, -1 and 255 could receive a plausible positive fee quote for a request the wallet
will never accept. Extreme inputs could instead fail incidentally in fee arithmetic.

This is a public API validation/integration defect, not a demonstrated wallet-balance
drain. The getter now rejects every count outside 1..254 using
`error::invalid_action` before fee arithmetic. The internal `required_value` calculation
is unchanged; the transaction path already validates its action count. Valid quotes
and the funded-entry protocol are unchanged.

## Regression and mutation coverage added

`test/pq-contracts/test_pq_highload_policy.py` reuses the existing real-executor helpers,
compiler and deterministic TEST ONLY signer. It does not mock transaction outcomes.
The existing quorum and wallet suites and their 61 mutations are retained.

Seven new test methods cover:

1. The wallet's active flag mask matches the executor header; policy drift requires
   an explicit vector update.
2. Reserved flags, including high bits of VarUInteger 16, fail before verification
   with unchanged data and an unused query id at versions 16 and 18.
3. All four active values (0..3) still send the intended amounts in signed order at
   both versions.
4. A good/bad/good batch is rejected whole; a corrected, newly signed batch using
   the same query id subsequently succeeds at both versions.
5. Changing one allowed flag value to another without re-signing still fails the
   ML-DSA check at both versions.
6. The real fee getter rejects -1, 0, 255, 256 and the maximum positive TVM integer,
   while the valid endpoints 1 and 254 return positive quotes.
7. A 254-action batch with active flags, dense replay state and exactly the quoted
   funding completes with its refund at both versions.

The runner first requires a passing seven-test baseline. It then removes each new
guard independently in a temporary sibling FunC source, recompiles, and requires an
actual assertion failure in the corresponding behavioral test. Compiler errors,
emulator errors and zero tests do **not** count as kills. It restores the original
compiled code and requires another passing baseline. The checked-in source is never
overwritten by these two additional mutation checks.

The existing `pq-contracts` workflow now invokes this runner before its original
mutation suite:

```sh
python3 test/pq-contracts/test_pq_highload_policy.py --build build \
  --signer build-pq-signer/test-pq-contracts-sign
```

## Evidence and merge gate

The pre-patch `pq-contracts` run
[37083845884](https://github.com/tosnetwork/tos/actions/runs/37083845884), associated
with input HEAD `5195571a49b4`, was observed successful. It is baseline evidence only,
not evidence that these newly added regressions pass.

Local checks available during review verified the captured original wallet against
its Git blob SHA (`c63ec95c9382a729fed9ec248f9fc0948bccf60b`), the patched source
against its returned Git blob SHA, Python syntax of the new test runner, and all
65,536 flag values in a bounded predicate truth-table check. The latter is **not**
a substitute for compilation or real TVM execution. This review environment has no
local TOS compiler/emulator build and cannot clone the repository through its shell.

**Merge gate:** require a successful latest-head `pq-contracts` run including the new
message-policy step, existing FunC/Tol/wallet suites, original mutation suite, gas
profile and deployment/code-hash checks. The PR review comment records the exact
observed post-patch revision/run and whether that gate has completed; this document
does not turn an in-progress run into a passing result.

## Boundaries retained

- The M-of-N API still requires configuration produced by its validated constructors
  and persisted unchanged. Caller-supplied unvalidated tuples are not safe configs.
  Expiry, operation domain, target address and nonce consumption remain caller duties.
- No additional authentication bypass was identified in the examined request paths.
  This is not a claim that all possible bugs or exotic-cell inputs have been ruled out.
- Mode +2 is best-effort per-message delivery, **not atomic all-or-nothing payment
  execution**. Owners/relayers must inspect outbound results and reconcile skipped
  payments. A successful compute phase alone does not establish delivery.
- The wallet's preflight parser does not recursively validate every referenced
  extra-currency structure. Executor validation/state limits remain authoritative;
  do not interpret the earlier design's "no input reaches a whole action-phase
  failure" sentence as a proof that every malformed cell graph is excluded.
- Replay safety depends on retained account state and the signed freshness interval.
  Disallowing send mode +32 is not a general guarantee against storage-rent-driven
  account deletion. Keep the wallet funded for storage and do not assume deletion
  and redeployment preserve replay history. No new rent-deletion exploit is claimed
  as reproduced in this review.
- The patch changes compiled wallet code and therefore deployment StateInit/address.
  Regenerate deployment artifacts from this build; do not reuse an old code/address
  pair. There is no state-layout migration and no change to the ML-DSA signature suite.


## Round 2 — ExtraCurrencyCollection preflight hardening

Second-round review started from the post-round-1 HEAD and focused on differences
between the wallet's compute-time parser and the executor's action-phase acceptance
rules. The round-1 CI for HEAD `eb64996e857f` completed successfully before these new
changes were made.

### F3 — Medium: invalid or over-limit ExtraCurrencyCollection can be skipped after replay consumption

The wallet previously parsed the native value and then used `skip_dict()` for the
`ExtraCurrencyCollection`. That checks only the HashmapE presence/root shape enough to
advance the slice; it does not validate each `HashmapE 32 (VarUInteger 32)` value and
does not enforce the executor's configured `max_msg_extra_currencies` limit.

The executor validates and unpacks `CurrencyCollection` in action phase. With
`extra_currency_v2`, it removes zero-valued extra currencies and then rejects a
message whose remaining non-zero currency count exceeds ConfigParam 43
`max_msg_extra_currencies`. The canonical configuration used by the PQ test executor
sets this limit to **2**. These errors are subject to `check_skip_invalid`; because the
PQ wallet forces send mode +2, the affected business message can be skipped while the
transaction succeeds and the query id remains consumed.

The repository's existing classic-highload action-phase fixture independently documents
the same class of behavior for malformed extra-currency dictionaries: IGNORE_ERRORS can
turn an action-phase message defect into a skipped send with replay state retained.

Impact is payment reliability / replay semantics, not an authentication bypass: the
owner must have signed the malformed or over-limit message. A relayer cannot alter the
signed action list without invalidating ML-DSA.

### Patch

`pq-highload-wallet-code.fc` now preflights `ExtraCurrencyCollection` before signature
verification:

- walk the dictionary as unsigned 32-bit currency ids;
- require each leaf to be exactly a canonical `VarUInteger 32` value;
- count only non-zero amounts, matching executor filtering semantics;
- reject when more than two non-zero currencies are present.

This runs before verification, replay recording, state persistence, refund queuing and
business sends. The current constant mirrors the active canonical ConfigParam 43 value,
and the policy test is intended to fail if configuration changes without an explicit
wallet-policy update.

Commits in this round:

- `667c9c437507` — add bounded extra-currency preflight;
- `a5c13c1f024b` — add real-executor regression and mutation coverage;
- `ce6798dbdb92` — mirror zero-value filtering semantics;
- `366475ce776d` — add zero-valued extra-currency regression.

### New regression coverage

The policy suite now exercises versions 16 and 18 and checks:

1. three non-zero extra currencies are refused before verification and leave the query id unused;
2. malformed `VarUInteger 32` leaf encoding is refused and leaves the id unused;
3. exactly two non-zero extra currencies remain usable;
4. more than two zero-valued entries remain usable, matching executor filtering;
5. removing the new preflight call must cause an assertion failure rather than a build/test error.

### Status

The previous round's latest-head CI (`eb64996e857f`) was observed fully green, including
the dedicated PQ contracts workflow and all related PQ/authentication checks.

The round-2 HEAD is `366475ce776dc78d9f659fd44c6edea33e1fd989`. At the time this
section was written, GitHub had not yet published workflow-run records for this newest
commit. Therefore round 2 remains gated on a successful latest-head CI run; the report
does not claim the new patch has passed the real executor until that run completes.
