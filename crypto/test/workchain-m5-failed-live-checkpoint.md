# Funded phase-0 Failed: Native publication checkpoint

Specification: memo `569ff21f`, SHA256 prefix `725e9e4dbd964e25`.
No independent accounting prediction was read. This is the narrow window-in,
strongly matched, sufficiently reserved branch, not M5 acceptance.

## Outstanding parameter freezes

The live fixture's `failed.issuance_billing_units=4` is an explicitly encoded
test value, NOT a frozen protocol constant or an absent-field fallback.
Its base=2 gives g=8 in this run; successful execution does not freeze either
test value. Under D70/section 12.1, system-issuance billing units still require
the freeze process, alongside Withdrawal state fee, max_bounce_cost, and
payout_settlement_blocks. No production default is established by this fixture.

## Three real integration refusals, then publication

The initial live route in `/tmp/uno-m3-live-2t35rtrk` produced a real wc0 bounce
with value 9996070 and full original body/LT. The continuation encountered:

1. `batch message destination is not the configured executor` in collator
   collection: custody was not an admitted collection role. Log
   `/tmp/uno-d77-live.log`; OFF still refused at phase 3.
2. `Failed selector owner differs from authenticated instance or roles`:
   the engine compared account registration incarnation to workchain instance.
   These are different identities. Only that comparison was removed; the
   selector is still checked against the acquired account incarnation and the
   domain remains independently bound. Log `/tmp/uno-d77-custody-live.log`.
3. Validator `InMsg ... refers to transaction that does not process this
   inbound message`: custody's settlement participant carries a batch binding,
   not a separate full inbox. Log `/tmp/uno-d77-published.log`.

After the changes below, the same authenticated predecessor and real bounce
were accepted with ON/OFF exit 0: `/tmp/uno-d77-published-linked.log`.
Old unsuccessful DB copies and observations were moved into named subfolders,
not deleted or counted as successful. The final accepted block is wc2 height 6,
root `172EE0BD8BD5476DDEEECFFC50DD80084B255D9053945B2BFF99E6457B8314E2`.
Final-import message:
`8674DE992D9C6779C4A4111BB1D2203492B3B80D826692A9ABBA851506FF9EFE`.

A fresh complete `uno-m3-live.py --m5-failed` run also exited 0, in
`/tmp/uno-m3-live-8x3sz5uk` (log `/tmp/uno-d77-full-live.log`). Its accepted
Failed root is `408E01F896367EE6DDB04740148BC0529FFB33652EF2DA25091160DE557CD01D`,
actual bounce hash `F48DB05B9AB6F79167A2483780B85697B2B104BA48F451A629312334947375F9`.
The strengthened assertions include coordinator +slot, custody transaction
compute fee, and the original observed bounce hash/destination/created_lt.

## Production boundary changes (separate from test assertions)

- `validator/impl/collator.cpp`, `collator-impl.h`: optional local custody role
  populated only inside the already D59-enabled account-binding branch. The
  collector additionally accepts bounced messages to that authenticated role,
  after existing Native route/key/processed-message checks. It does not decide
  Attempt matching or release obligations. Ordinary and block-transition
  branches leave it absent; the original fatal string is unchanged.
- `validator/impl/validate-query.cpp`, `validate-query.hpp`: optional local
  scope likewise requires resolved D59-enabled binding. Only when the old
  input predicate fails, the new predicate checks a custody settlement
  participant against the same candidate's unique coordinator entry: both
  input/effects hashes, actual entry roots, bounded inbox and exact Message
  hash. Destination must be custody, message bounced, ordinary in_msg absent.
  This does not skip full account-batch Native replay or artifact comparison.
  Scope absent reduces to the previous input predicate. All old rejection
  strings remain unchanged.
- `crypto/block/workchain-failed-funded.h`: after strong association, phase 0
  bypasses deadline arithmetic entirely. Phase 1 retains the checked height
  window. No Paid, late-return or shortfall success branch is added.

No ordinary Transaction phase, state encoding, Rust statement interface,
coordinator Deposit bounced rejection or D59 default is modified here.

### Direct validator OFF before/after

The accepted Failed archive above was fed directly to the real validator with
the engine registered but D59 OFF (`test-m3-live --validate-archive-off`).
Both builds exited 2 with `validate -7201`, message
`cannot execute configured workchain: multi-account admission and replay are not connected`,
and `config=1 / execute=0`; neither exported a candidate. The before build
restored only validate-query.cpp/.hpp to the committed predecessor while
keeping the same probe and candidate. Each used a fresh copy of the same DB.
`cmp` passed for all five stable output files: execution counters and validation
delivery/kind/message/result. Logs and timing are not byte-invariance claims.
Logs: `/tmp/uno-d77-validator-off-before.log` and `...-after.log`.
This is one concrete OFF candidate, not exhaustive equivalence of every input.
The collator OFF sequence separately observes zero transactions and no export.

The original validator refusals in `validator_account_binding_custom`,
`validator_account_binding_ready`, and the account-binding visitor in
`check_transactions` retain their strings and default behavior. The fourth,
collator account-binding refusal, is also unchanged. The two new openings are
the collator custody destination condition and validator participant attribution;
each has its own observed pre-opening refusal above.

## Actual values and observation boundaries

Prepare values: x=10000000, q=100, b=4000000, f=257. Failed observes:

| Quantity | Before | After / change |
|---|---:|---:|
| custody R_actual / R_book | 989999643 | 996995705 |
| test-decrypted N_hidden | 985999643 | 996995705 |
| P | 10000000 | 0 |
| W | 14000000 | 0 |
| deposit_sequence | 1 | 2 |
| system settlement receipt | absent | 10996062 |

Gross custody recovery is **y=9996070**, not x. Its same-batch fee debit is
3000008, giving net +6996062. P releases x; W releases x+b (not q).
Return loss is 3930; slot fee 3000000; compute g=8 from explicit test base 2
and billing units 4, NOT from proof-work 7. Thus reserve consumption is
3003938 and unused reserve is 996062. A single receipt returns principal
plus unused reserve, 10996062. These arithmetic quantities are derived from
actual recovery, the old W and explicit authenticated test policy, not new debts.
The Native bounce phase itself was decoded: collected fee 1309 plus forwarded
fee 2621 equals 3930. The observer rerun on the fresh accepted recipient block
exited 0 (`/tmp/uno-d77-actual-return-fee.log`); this is not merely naming x-y
as a fee. All three return-cost components are included.

Both equations after Failed:

```
R_actual = R_book = 996995705
R_actual + P = 996995705 + 0 = 0 + 996995705 + 0 = D + N_hidden + W
```

D=0 is the atomic operation-set property, not an independently stored counter.
The oracle reconstructs book from permanent accepted inputs and final-import
Message value. It decrypts available and all pending classes with test keys;
this is not public production auditing or node-side historical reconstruction.
The receipt is decoded from the accepted full account root, uses the Withdrawal
settlement origin with the previous record's Attempt ID, and carries sequence 2.
Available/revision/nonce are unchanged by this settlement, W is empty, and
custody emits no message. Collator and validator each consume **7 proof units**.
ON has three accepted Native account transactions; OFF identifies phase 3,
zero execution/transactions and no candidate export.

## Red evidence and remaining gaps

The old phase-0 helper rejects the height-100 fixture with exactly
`funded Failed requires an open height window`, then fails `early_return.is_ok()`.
The fixed helper passes `--filter FailedFunded` (1/1); phase-1 late rejection
remains covered at helper level. Logs `/tmp/uno-d77-phase-red.log` and
`/tmp/uno-d77-phase-green.log`. This proves the observed rejection, not a
silently reduced refund. The same high-height test also rejects naive zero-LT
window arithmetic. Phase-1 observation has no live producer in this checkpoint.

The full association CTest remains red at the separate, existing
`CodecFailureCategoriesSurviveProtection: write.is_error()` and does not reach
FailedFunded without filtering. It is not repaired or represented as D77 evidence.

Rust prepare guards passed 2/2. The sequence expiry guard still fails at the
Failed issuer; its replacement runner still reports all six successor tests
missing (`HANDOFF_NOT_READY`). No guard was retired or predicate relaxed.
The real publication is not completion of any mixed-source/sentinel/competing
or mutation contract: six sequence items remain unfulfilled, prepare contract
remains 0/9 here. Unknown-source counter is **absent/unmeasured**, never claimed
zero. Error classification remains incomplete. Removing the wrong incarnation
comparison moves candidate incarnation mismatch to the existing LocalUnavailable
account-binding check: the review correctly identifies this as a regression
of this change, not merely an older gap. It requires a provenance split and
a targeted negative control before acceptance; this checkpoint does not close it.

Claude Code reviewed both production openings read-only. The participant
predicate review found no blocker in that diff; individual conjunct mutations
remain untested and no broader coverage is claimed. Its phase-0 timeout concern
is resolved by the owner's explicit D77 rule (no invented phase-0 deadline).
The misplaced transaction-reference comment was restored to its own method.
The incarnation classification finding above remains open and prevents wiring
acceptance. The earlier collector review's inference that validator acceptance
followed was disproved by the separate real linkage refusal; it is not evidence.

Not claimed: shortfall, phase-1/late/Paid completion, split-wc0 route coverage,
full authenticated pending mutation evidence, production availability, external
cryptographic review, cumulative node ledger enforcement, or supply-chain audit.

## Follow-up: candidate incarnation classification

Owner clarification: memo `8cc604dc`, specification SHA256 prefix
`6cf757e0bda63b1e`; the original checkpoint above retains its original version.

The regression recorded above is addressed separately from the publication
checkpoint. The acquired owner's Native account key/workchain/custody checks
remain local-state checks. Only the candidate selector's incarnation comparison
now returns `-7200: Failed selector incarnation differs from authenticated owner`.
It does not infer provenance from an exception class or error string.

`test-m3-live --failed-incarnation-control` flips only the candidate incarnation,
leaving the real pre-Failed DB, account key, declarations and bounce unchanged.
The ordinary live script runs this control immediately before funded Failed.
Observation surface: real collator result/code/reason, transaction count,
proof-work counter and candidate export. It is not a direct malformed-candidate
validator replay or an injected local DB fault test.

Before the fix, `/tmp/uno-incarnation-red-live.log` observed `collate -7201` /
`authenticated Failed owner binding mismatch`; the exact `collate -7200`
assertion aborted. After the fix the same predecessor fixture
`/tmp/uno-m3-live-3nygkohf` passes with the specified -7200 reason, zero issuance
work, zero transactions and no export (`/tmp/uno-incarnation-green-control.log`).
Unchanged input then passes real ON/OFF publication
(`/tmp/uno-incarnation-positive-live.log`): R_actual=R_book=N_hidden=996995705,
sequence 1->2, actual recovery 9996070, receipt 10996062.

This closes that candidate-incarnation regression only. Unknown-source counting
and broader exception/provenance coverage remain incomplete; no contract item
or expiry guard is marked complete by this focused control. The unrelated full
association codec exception assertion is untouched.

Claude Code's focused classification review found no blocker and confirmed that
the accepted set is unchanged. Its "AFTER pending" note reflects the review
request time: the subsequent fresh full `--m5-failed` run exited 0, including
the new control and normal publication (`/tmp/uno-incarnation-final-live.log`,
fixture `/tmp/uno-m3-live-mxu2mivp`). The review also identified a separate
remaining surface: selecting an existing pre-Withdrawal account reaches the
schema decoder's blanket local error. That path requires its own source/route
classification and control; it is not covered by the incarnation fix.
The negative checks zero issuance work and no export, not a standalone
validator-replay-count assertion. No broader claim is made on that basis.
