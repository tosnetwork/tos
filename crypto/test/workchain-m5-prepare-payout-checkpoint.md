# Authenticated prepare: open record and real payout

Specification: memo `75066d66`, SHA256 prefix `26d355c0b3570a23`.
No independent accounting prediction was read.

## Executed checkpoint

`python3 test/uno-m3-live.py --build /tmp/uno-merge-6ea2fbf80-tL5Uih --m5-debit`
returned **0**. Fixture: `/tmp/uno-m3-live-phwresax`; log:
`/tmp/uno-prepare-payout-live.log`. Build target `test-m3-live` passed.
The sequence registers two accounts, makes a real Deposit, collects it, and
prepares a Withdrawal. Each step executes the existing ON/OFF pair. OFF identifies
phase 3, `collate -7201`, zero engine executions/transactions and no export;
ON produces a candidate accepted by the real validator.

Prepare inputs: `x=100`, actual Native-priced `q=100`, `b=23`, `f=257`.
The preceding debit-only checkpoint's `q=17` was a claim, not a paid fee.
Replacing it with the actual price explains the additional 83-unit debit.

- Authenticated available: `1000000000 -> 999999520`; revision `1 -> 2`;
  nonce successor checked. Proof-work consumption: `3636 / 3636`.
- Explicit schema-2 to schema-3 migration installs one phase-0 record in the
  account control envelope, bounded by the explicit test policy `K=4`.
- Actual custody transaction emits exactly one payout. Its message hash is
  `780FCA2D67B90AE5E8F8B9B677EE0BE403EFF678D293C3CD67F26DABAF92E247`;
  actual `created_lt=16000002` equals the stored record LT. The same message
  occurs exactly once in the **accepted state's outbound queue**.
- `R_actual=R_book=999999543`; decrypted liabilities `N_hidden=999999520`;
  enumerated phase-0 records give `P=100`, `W=123`.
  `R+P=N_hidden+W=999999643` passes. The existing nonzero backing controls
  and the unpaired confidential-fee control reject, then pass after restoration.
- Coordinator balance is `21003000250`, protected refundable deposits
  `20000000000`, unexpected holdings zero.

The observation is accepted account roots, custody transaction and outbound
queue, not merely proposed effects. The cumulative backing reconstruction and
test-key decryption remain **test-side** evidence, not a production historical
ledger or a publicly decryptable liability total. This oracle covers phase 0;
it explicitly rejects unsupported settlement phases rather than guessing P/W.

## Native boundary and observed blocker

The initial integration reached Native settlement but failed with
`batch native message send failed`: the registered engine priced q=100, whereas
the collator's existing settlement call supplied a zero forwarding allowance.
This was not a proof failure or a successful publication.

Production headers changed:

- `workchain-account-engine.h`: an optional **local execution-result**
  `payout_forward_fee`, reconstructed from the authorized Withdrawal input.
- `workchain-account-settlement.h`: the existing payout overlay consumes that
  allowance when present; absence preserves the existing caller allowance.

No collator/validator refusal text, D59 default, ordinary transaction function
or existing caller is redirected. The test registered engine alone opts in.
It independently prices the request using `Transaction::price_workchain_payout`,
compares q, and uses the same participant LT planner as Native materialization.
The existing overlay publishes the three accounts and payout atomically.
The earlier empty-inbox failure was a test-host framing bug: `Maybe` has a cell
even when absent. The host now decodes the inbox and checks the envelope count.

## Limits / remaining acceptance

Prepare handoff runner still exits **1**, all **0/9** named host contracts are
unregistered. This happy-path checkpoint does not replace their mutations,
especially full account/pending no-installation and oracle-control contracts.
Both existing statement guards remain; no guard was retired.

Unknown-source counter is **absent/unmeasured**, not zero. Error classification
is not closed; this is **not wiring acceptance**. Reserve b is still an explicit
fixture/input amount rather than a fully authenticated reserve policy. Missing
state-fee ConfigInvalid admission, shared billing-unit definition and broader
configuration admission remain separate work. No Failed/Paid/window transition,
second concurrent Withdrawal, migration round-trip lifecycle, split-wc0 bounce,
or mainchain-import acceptance is claimed here.

Read-only consensus-boundary review was requested; at this checkpoint its
response is pending. No review completion is claimed.
