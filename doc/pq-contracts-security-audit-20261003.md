# PR #128 security audit — rounds 1–3 — 2026-10-03

## Status, provenance and scope

Repository: `tosnetwork/tos`; PR #128, **Add ML-DSA-44 quorum signatures and a relayer-funded post-quantum high-volume wallet**; branch `pq-quorum-and-highload`.

This is the consolidated current report. The complete earlier report remains in Git history:

- [Rounds 1–2, tos at 831ff96207b4](https://github.com/tosnetwork/tos/blob/831ff96207b447e1ff8508d74f6586cc64888a0c/doc/pq-contracts-security-audit-20261003.md)
- [Rounds 1–2, memo at 8f87d4f58de1](https://github.com/tosnetwork/memo/blob/8f87d4f58de15cdf8ced3c0d7fb13d94810d4e0c/pq-contracts-security-audit-20261003.md)

Both copies were verified to have blob `44bd13565252cad74ae7a3347205a712af430d7e` at the start of round 3. The current report is synchronized to `memo/main/pq-contracts-security-audit-20261003.md` as requested; the tos copy is retained, not deleted.

Round 1 reviewed `5195571a49b40153823669b234ea5597a8af76da`. Round 3 started from `831ff96207b447e1ff8508d74f6586cc64888a0c`, including the round-2 changes. Its focus is wallet/executor agreement, bounded pre-verification work, funding assumptions and whether tests prove asset delivery. The FunC/Tol quorum libraries, native ML-DSA implementation, signed request layout, signature contexts and persisted storage layout are unchanged in this round.

**Important correction:** the round-2 statement that the executor removes zeros *before counting currencies* was wrong. The C++ implementation counts encoded entries first. The earlier tests did not establish delivery. Sections R3-1 and R3-4 supersede those claims, including the earlier statement that four zero entries are usable under limit 2. This report does not treat previous review acceptance or a green old revision as proof about the new code.

**Release status:** source fixes and real-executor regressions are supplied. Latest-head native execution, gas measurements and mutation outcomes remain a merge gate until the corresponding workflow completes successfully. The PR review records the exact final revision and observed CI state. No merge or deployment is authorized by this report.

## Findings retained from rounds 1–2

### F1 — Medium — Reserved extra_flags can skip a signed payment

The wallet originally discarded the field before `fwd_fee` as legacy `ihr_fee`. It is `extra_flags` at the supported versions. The active executor mask is 3; an invalid bit can reach action-phase `check_skip_invalid(45)` and, with forced send mode +2, skip a payment while the query id is consumed. The round-1 patch validates mask 3 before verification, recording or queuing actions. Values 0..3 remain permitted. This is a signed-message reliability defect, not a relayer signature forgery.

### F2 — Low — Unsupported counts received fee quotes

`get_required_value` formerly accepted arbitrary integers although batches require 1..254 actions. It now refuses counts outside that range before fee arithmetic. Valid quotes remain conservative attached-value requirements, not promises that the whole quoted amount will be spent.

### F3 — Medium — ExtraCurrencyCollection was not preflighted

`skip_dict()` did not inspect extra-currency leaves or enforce message currency limits. Round 2 added a walk, but its non-zero-only counting, fixed limit, resource assumptions and positive tests were inadequate. Do not consider F3 closed based on the round-2 patch alone; the following corrections complete this round's implementation work and still require the native test gate.

## Third-round findings and fixes

### R3-1 — Medium — Count semantics and live configuration disagreed with the executor

**Evidence.** In `crypto/block/block.cpp`, `CurrencyCollection::remove_zero_extra_currencies` does, in order:

```cpp
++count;
if (count > max_currencies) {
  return -1;
}
// Only after the count check is the amount decoded and zero filtered.
```

Thus `max_msg_extra_currencies` bounds **encoded entries, including zeros**, not only non-zero balances. At limit 2, a dictionary containing four canonical zero amounts is over-limit. The old preflight admitted it and the action phase could skip its payment. The old hardcoded `MESSAGE_MAX_EXTRA_CURRENCIES = 2` also became too permissive when the live limit was lowered and too restrictive when raised.

**Fix.** Every visited leaf counts against the live per-message limit. `message_extra_currency_limit()` reads ConfigParam 43, supporting constructors #01/#02/#03, including the v3 optional field. Absent/#01 uses the executor default 2; an explicit limit 0 is retained as zero; unknown constructors fail closed. `get_extra_currency_limits()` exposes the live message-entry limit and the independent wallet batch-work limit.

Tests construct actual ConfigParam 43 cells and feed them to the real emulator, rather than mocking its decisions. They cover absence, #01, #02/#03 with limits 0/1/2/3, both zero and non-zero entries, and corrected re-submission using an unused query id. At limit 0 only an empty extra dictionary is admitted. At limit 2 up to two zero entries can be filtered and the native payment sent; four zero entries must fail preflight.

### R3-2 — Medium — Zero walks and aggregate work were not covered by the funding profile

The round-2 loop incremented its counter only for non-zero amounts. Arbitrarily many zero leaves could therefore be traversed before verification/funding admission. Even a correct per-message currency limit would not by itself bound aggregate extra work across 254 messages. The old action-count-only gas profile had been measured on messages without extra dictionaries.

**Fix.** `BATCH_MAX_EXTRA_ENTRIES = 8` bounds the total encoded extra-currency leaves visited across the entire signed batch. Zeros count. A shared dictionary counts again on each use. Each message receives the remaining budget, and the batch subtracts the returned work. The loop checks its budget before parsing the next leaf; only a bounded lookahead is needed. The 32-bit key width also bounds traversal depth. Empty maps bypass the dictionary/configuration walk.

This is an explicit **wallet resource policy**, separate from the chain's per-message limit. A batch exceeding eight encoded extra entries is rejected unused and must be split/re-signed. The 254-action ceiling remains; it is not a promise of 254 maximally complex messages.

The conservative compute quote is now:

```text
87,600 + 3,300 * action_count + 60,000 gas
```

The fixed extra-work reserve keeps the one-argument getter usable. Unspent attached value is refunded under the existing mode 64+2 semantics; the reserve is not a fixed fee. At 254 actions the arithmetic bound is 985,800 gas, below the fixture's 1,000,000 cap. **This arithmetic is not a measurement or proof of sufficiency.** Tests require real full-batch execution at exactly the getter quote, including dense replay state, cold/independent extra dictionaries, maximum 31-byte amounts and the entire eight-entry budget. One unit below the quote must reject the request unused. Older gas figures in the original design/PR description are historical, not measurements of this revision.

### R3-3 — Medium — Non-minimal extra amounts bypassed compute-time validation

Reading a five-bit length and that many bytes did not establish canonical `VarUInteger 32`. `VarUInteger::validate_skip` in `crypto/block/block-parse.cpp` requires a non-empty encoding to start with a non-zero byte. Examples previously admitted by the wallet include zero encoded with length 1 and value 1 encoded with length 2 and a leading zero. Native action validation can reject such a payment after the wallet's intended preflight point.

**Fix.** For non-zero length, require a non-zero leading byte, then consume exactly the declared bytes and the entire leaf. Zero is represented by length 0. Truncated values and trailing bits/references remain rejected. The old `bytes >= 32` guard was removed: a five-bit unsigned read cannot produce 32, so that condition provided no protection.

Tests cover non-minimal zero, leading-zero positive values, a 31-byte non-minimal value, truncated leaves and trailing bits/references. A separate mutation removes the leading-byte check and must fail a behavioral assertion.

### R3-4 — Medium — Positive tests could pass when no assets were sent

The round-2 "two currencies remain usable" test started from a wallet with no extra-currency balance. It asserted transaction success and replay-id consumption, but not the business outbound message. Under forced +2 an insufficient-extra-balance send can be skipped while those assertions still pass. The four-zero-entry test similarly did not prove that the native payment was emitted.

**Fix.** `AssetWallet` adopts the actual post-transaction state on success and failure and preserves extra-currency maps from actual outbound messages. Positive tests first credit assets through real internal deposits. They then assert destination, native value, currency ids/amounts, signed order and remaining wallet asset balances. The zero cases check the real native payment, not just a consumed id. Tampering with extra amounts without re-signing must fail verification and leave funds unchanged. Getter tests now explicitly use the same v16/v18 version as the wallet under test.

## Test inventory and execution boundary

`test/pq-contracts/test_pq_highload_policy.py` now contains **14 test methods**, running behavior at versions 16 and 18, and **7 targeted mutations**. It retains coverage of the round-1 flags/count guards and adds removal/substitution tests for the extra preflight, total-visit bound, aggregate batch budget, minimal amount encoding and live limit.

A mutation counts as killed only after a passing baseline, actual test execution, at least one assertion failure and no test errors. Sources are not overwritten: each mutant is compiled from a temporary sibling file. The original compiled wallet is restored and the complete baseline must pass again. The original FunC/Tol quorum suites, wallet suite and 61-mutation runner remain in the existing workflow.

Additional vectors exercise 9/128/1,024/4,096 zero entries under an enlarged live limit, so the wallet's independent work bound is tested rather than accidentally relying on the default chain limit of 2. Shared 4-entry dictionaries use a live per-message limit 4: two sends fit the batch budget; three do not. Exact-quote worst-work vectors enlarge the per-message limit to 8 where needed, while separate cases verify the default limit 2.

Local evidence for this round: Python syntax checking, AST inventory, all seven mutation targets matching exactly once, balanced source delimiters, and Git blob consistency of the prepared source/test files. These are **not** a FunC compilation, a TVM execution, an ML-DSA proof or a passing CI verdict. Shell cloning was attempted but DNS resolution for github.com failed, and no local TOS compiler/emulator build was available.

The earlier dedicated run [37091479871](https://github.com/tosnetwork/tos/actions/runs/37091479871) belongs to round-1 HEAD `eb64996e857f`; its success cannot validate round 2 or 3. Do not interpret earlier broad "all CI green" wording as a latest-head result. The required merge gate is a successful dedicated workflow for the final head, including compilation, generated deployment code, original suites, policy tests, exact-quote/gas checks and both mutation runners.

## Boundaries and rollout

- This is a source-level review with added regressions, not a comprehensive proof that every cell graph or every future configuration is safe.
- The quorum library still requires validated, persisted configuration. Expiry, operation domain, target binding and nonce consumption remain calling-contract responsibilities. No quorum-library API or signature suite is changed here.
- Forced +2 remains per-message best effort, not atomic payment execution. Native action/state limits, destination validity and sufficient balances still govern delivery. This bounded parser is not a complete independent TL-B validator.
- Relayers must use the current getter; attached-value requirements increased. A skipped refund may remain in the wallet. Storage rent still applies, and deletion/redeployment does not preserve replay history.
- The eight-entry aggregate budget is a new explicit admission restriction. Clients must count encoded entries, including zeros and repeated uses, and split larger extra-currency batches.
- Bytecode changes alter StateInit/address. Regenerate deployment artifacts. Stored data and signed request field layout are unchanged; there is no state-layout migration.
- No merge, deployment, main-branch code edit or wallet transaction was performed by this review. Repository writes are limited to the PR branch and the requested memo report.

## Primary source references

- [Round-3 input wallet](https://github.com/tosnetwork/tos/blob/831ff96207b447e1ff8508d74f6586cc64888a0c/crypto/smartcont/pq-highload-wallet-code.fc)
- [Round-3 input tests](https://github.com/tosnetwork/tos/blob/831ff96207b447e1ff8508d74f6586cc64888a0c/test/pq-contracts/test_pq_highload_policy.py)
- [CurrencyCollection count-before-filter implementation](https://github.com/tosnetwork/tos/blob/831ff96207b447e1ff8508d74f6586cc64888a0c/crypto/block/block.cpp)
- [Native VarUInteger canonical validation](https://github.com/tosnetwork/tos/blob/831ff96207b447e1ff8508d74f6586cc64888a0c/crypto/block/block-parse.cpp)
- [ConfigParam 43 wire layouts](https://github.com/tosnetwork/tos/blob/831ff96207b447e1ff8508d74f6586cc64888a0c/crypto/block/block.tlb)
- [Action-phase message handling](https://github.com/tosnetwork/tos/blob/831ff96207b447e1ff8508d74f6586cc64888a0c/crypto/block/transaction.cpp)
