# PR #128 security audit and CI correction — 2026-10-03

## Current conclusion and provenance

Repository: `tosnetwork/tos`; PR #128; branch `pq-quorum-and-highload`.

**The previous zero-amount acceptance claims are superseded.** In this executor,
`try_action_send_msg` validates `CurrencyCollection` before calling the zero-filter
helper. `ExtraCurrencyCollection::validate` uses `VarUIntegerPos_32`, which requires
positive, minimally encoded amounts. A dictionary entry with amount zero is not a
valid outbound extra-currency entry, even when its count is below ConfigParam 43's
limit. Clients must omit zero entries. This restriction does not prohibit a native
TOS value of zero or an empty extra-currency dictionary.

Earlier complete reports remain available in history:

- [Rounds 1–2](https://github.com/tosnetwork/tos/blob/831ff96207b447e1ff8508d74f6586cc64888a0c/doc/pq-contracts-security-audit-20261003.md)
- [Initial round-3 report](https://github.com/tosnetwork/tos/blob/3d225ff43e06054a34be2488220ac80647951002/doc/pq-contracts-security-audit-20261003.md)

The source/test revision investigated for this CI correction was
`3d225ff43e06054a34be2488220ac80647951002`. Diagnostic commit
`2a4f394b03a8f2c2adf2e6e718d0df290eff9f47` changed only the workflow, not the contract
or test assertions. It reproduced the failure on the real executor in run
[37096711082](https://github.com/tosnetwork/tos/actions/runs/37096711082).

This report covers source-level security review, regression tests and their acceptance
criteria. It is not a proof of ML-DSA's mathematical security or a production network
certification. No merge, deployment or main-branch code change is part of this work.

## CI failure: observed result, cause and correction

The dedicated workflow originally reported only that the combined policy/mutation
step failed. The redirected-log connector itself failed to import
`opentelemetry.exporter.otlp`; that was a log retrieval problem, not the test failure.
The diagnostic workflow now retains the process exit code and publishes failing test
names and exception details in the Actions summary and bounded diagnostic job names.
It has read-only permissions, does not post PR comments or write repository data from
test code, and does not use `continue-on-error` or override the contracts job result.

### Reproduced failures

Run 37096711082 compiled successfully and passed the original FunC quorum, Tol quorum,
and wallet/deployment suites. Its policy baseline failed in these four test methods:

| Method | Failure exposed by real execution |
| --- | --- |
| `test_extra_currency_collection_is_preflighted` | The purported positive zero-entry send aborted in action phase. |
| `test_extra_budget_is_shared_across_the_batch` | The supposedly valid shared zero dictionary did not produce payments. |
| `test_live_config_limits_and_defaults` | Under-limit zero dictionaries were incorrectly expected to send across multiple configuration cases. |
| `test_maximum_extra_work_at_exact_quote` | The packed worst-work case included six zero entries and aborted despite sufficient compute gas. |

The diagnostics consistently showed `exit=0`, `compute_success=true`,
`aborted=true`, `action.success=false`, `action.code=34`, `data_changed=false`, and
`out=[]`. Examples include 90,657 gas for the one-action worst-work case and 884,065
gas for the full-batch packed case. These are measurements of failed transactions,
not successful-send gas profiles. The original code had already passed verification
and compute; action validation then rejected the currency encoding and rolled back
state and queued messages. In these cases the replay id was not consumed.

The policy runner exits immediately when its baseline fails. Therefore these failures
do **not** establish surviving mutants: the targeted mutation loop had not been
reached, and the later original 61-mutation workflow step was skipped.

### Exact source-level cause

The relevant sequence is:

1. `Transaction::try_action_send_msg` calls
   `block::tlb::t_CurrencyCollection.validate_csr(info.value)` and returns an error
   when it fails.
2. `CurrencyCollection::validate_skip` delegates its extra map to
   `t_ExtraCurrencyCollection`.
3. In `crypto/block/block-parse.h`, that type's validator uses the dictionary with
   `t_VarUIntegerPos_32`, not the permissive plain `VarUInteger_32`.
4. `VarUIntegerPos::validate_skip` in `block-parse.cpp` requires `len > 0`,
   `len < 32`, a non-zero first amount byte, and sufficient bytes.
5. The later `remove_zero_extra_currencies` helper cannot rescue an input rejected
   at this earlier validation gate. Its count-before-filter ordering is real but
   is not by itself the complete message-admission rule.

The earlier report correctly noticed count-before-filter, but incorrectly concluded
that under-limit zero entries could be sent. The stronger delivery assertions exposed
this additional mismatch; they must not be weakened to accept an aborted transaction.

### Contract correction

In `require_valid_extra_currencies`, retain the live per-message limit, whole-batch
work bound, leading-byte check, exact leaf consumption and pre-verification ordering.
After consuming the leaf, require:

```func
throw_unless(error::invalid_message, bytes > 0);
```

Checking after `value.end_parse()` preserves cell-underflow rejection for truncated
or trailing-data leaves. A canonical length-zero leaf now produces the wallet's
explicit `invalid_message` rejection before ML-DSA verification, replay recording or
action queuing. This is a contract preflight fix as well as a test-fixture correction.
No changes to the native executor, signature algorithm or authorization checks are
needed to make the test conform to actual protocol behavior.

### Test correction without reducing coverage

- Zero-valued extra entries become negative tests. Assert rejection before
  verification, unchanged data, unused query id, and successful re-submission of a
  corrected, newly signed request without zero entries.
- Resource-scan vectors use **valid positive amounts** at 9/128/1,024/4,096 entries
  under an enlarged live per-message limit. Otherwise a new zero guard could reject
  the very first leaf and falsely appear to prove the traversal bound.
- Shared-dictionary tests fund actual assets. Two four-entry sends must transfer
  both native value and all named assets; three such sends exceed the eight-entry
  batch budget and must be rejected unused.
- Exact-quote worst-work tests use eight positive maximum-length amounts, including
  both packed and independently spread dictionaries. They still require actual
  messages, amounts, order, remaining balances and query-id recording.
- Add a dedicated mutation removing the positive-amount guard. It must be killed by
  a behavioral assertion, not by a build/setup error.

The corrected policy suite contains **15 test methods and 8 targeted mutations**.
Both v16 and v18 remain covered. A passing baseline is still mandatory before any
mutation; a kill still requires tests to run, an assertion failure and no errors;
original compiled code is restored and a full restored baseline is required. The
original wallet/quorum suites and 61-mutation runner remain enabled.

## Findings retained from earlier rounds

### F1 — Medium: reserved message flags

The wallet originally read the historical `ihr_fee` slot without validating its modern
`extra_flags` meaning. Reserved bits could pass compute and lead to skipped signed
payments under forced +2. The preflight now requires active mask 3 before verification.
Values 0..3 remain allowed. This was a signed-message reliability problem, not a
relayer's ability to forge or alter a signature.

### F2 — Low: unsupported fee-getter counts

`get_required_value` now rejects counts outside 1..254 before arithmetic. Valid quotes
are conservative attached-value requirements, not fixed fees that must all be spent.

### F3 / R3-1 — Medium: extra-currency preflight and configuration

`skip_dict()` did not validate extra leaves or message currency limits. Preflight now
uses the live ConfigParam 43 count, not a hardcoded 2. The getter and parser support
absence/#01 defaults and #02/#03 layouts, preserving explicit zero limits. Unknown
constructors fail closed. Every visited entry counts toward resource bounds; admitted
entries must additionally pass the positive-amount check described above.

### R3-2 — Medium: unbounded and unpriced extra work

The old non-zero-only count allowed arbitrarily many zero leaves to be walked before
verification. A whole-batch budget of `BATCH_MAX_EXTRA_ENTRIES = 8` now bounds aggregate
work, including repeated use of shared dictionaries. Clients must split/re-sign larger
extra-currency batches. The 254-action ceiling remains an action-count ceiling, not a
promise of 254 maximally complex asset messages.

The conservative compute quote remains:

```text
87,600 + 3,300 * action_count + 60,000 gas
```

The fixed reserve is included in attached-value admission and refunded when unused
under existing mode 64+2 semantics. The arithmetic full-batch bound is 985,800 gas.
Arithmetic alone is not proof of sufficiency: exact-quote tests, including dense replay
state and the complete eight-entry budget, are required on the final code revision.

### R3-3 — Medium: non-minimal amount encodings

The preflight checks a non-zero leading byte for non-empty encodings and consumes the
leaf exactly. Leading-zero positives, non-minimal zero encodings, truncation and
trailing bits/references are rejected. The unreachable five-bit `bytes >= 32` guard was
removed earlier. The positive-length guard completes agreement with the stricter
native ExtraCurrencyCollection validator.

### R3-4 — Medium: positive tests did not prove delivery

Earlier tests funded no assets and asserted only transaction success/replay-id
consumption, allowing forced +2 skips to look like successful transfers. `AssetWallet`
now adopts actual post-transaction state and decodes real outbound asset maps. Positive
tests deposit assets through native internal transactions and verify destinations,
native/asset amounts, order and remaining balances. These checks are retained, not
relaxed, in the CI correction.

## Verification and merge gate

Source/test copies used for this change were verified against original Git blobs
`5225cb45a4c5e37b7bd9ecde34951f973bfa8993` and
`79d974193552aecff44ee78545791a5ce2392c88`. Local checks include Python syntax/AST,
method inventory and unique matching of every mutation target. They are not local
TVM execution: this environment has no TOS compiler/emulator build and shell DNS
resolution failed.

Diagnostic run 37096711082 is a real native reproduction of the unchanged failing
baseline. It is not a passing result for the correction. **At the time this corrected
report is committed, the corrected code still requires its own latest-head dedicated
workflow to pass**: compilation, original suites, all 15 policy tests, all 8 targeted
mutations, restored baseline and original 61 mutations. The PR follow-up records the
exact final commit/run and its observed outcome; no pending or failed run counts as a
pass.

## Integration boundaries

The FunC/Tol quorum implementations, native ML-DSA implementation, signing contexts,
request field layout and stored wallet layout are unchanged by this CI correction.
Quorum callers still must persist validated configuration, bind the target/domain,
check expiry and consume nonces. Forced +2 is best-effort delivery, not atomic business
execution. Storage rent, account/state limits and balance/destination validity remain
applicable. Bytecode changes alter StateInit/address; regenerate deployment artifacts.
There is no state-layout migration and no authorization to merge or deploy.

## Primary source references

- [ExtraCurrencyCollection validator](https://github.com/tosnetwork/tos/blob/3d225ff43e06054a34be2488220ac80647951002/crypto/block/block-parse.h)
- [Positive and ordinary VarUInteger implementations](https://github.com/tosnetwork/tos/blob/3d225ff43e06054a34be2488220ac80647951002/crypto/block/block-parse.cpp)
- [Action-phase validation ordering](https://github.com/tosnetwork/tos/blob/3d225ff43e06054a34be2488220ac80647951002/crypto/block/transaction.cpp)
- [Count-before-filter helper](https://github.com/tosnetwork/tos/blob/3d225ff43e06054a34be2488220ac80647951002/crypto/block/block.cpp)
- [Original policy tests](https://github.com/tosnetwork/tos/blob/3d225ff43e06054a34be2488220ac80647951002/test/pq-contracts/test_pq_highload_policy.py)
