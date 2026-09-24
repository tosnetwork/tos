# T3 multi-nominator first-stake timeout: bounded investigation

Status: **OPEN — the a4 report lacked second-stake feedback; the retained e48
raw transaction trace now contains an exact-query-ID Elector refusal.** The
e48 report's own pagination classification was inconclusive because of a
diagnostic bug, corrected below with an old-RED/new-GREEN unit test. This is
a same-host diagnostic, not launch or release acceptance. Do not extend the
180-second wait or mark the second live stake accepted on this evidence.

## a4d31b351 live2: first round proven, second round unresolved

The later exact-a4 diagnostic report is
`test/integration/.pq-nominator-pool-t3/20260924T003514Z/report.json`,
SHA-256 `fc93d48ab90ac019afa6ed1de91543469b767e92b7da809adc8b0b10ec24b16a`.
It has 26 passing checks, one not-exercised check, and `passed=false`. Its
campaign manifest digest is
`0b5a4284080a8cc0440f554dded4e70bd3e318f8be3b8d9078bae6272fba19ad`.
This is evidence from **a4d31b351**, not from the later 096a150c8 tree.

The **first** pool stake reached state 2 for election `1790210715`, the pool's
controller `dae8de3b…1c57d8` and ADNL `73606979…21ef71` were paired in live
ConfigParam 34, the stake was recovered, all eight identity-bound nominators
received positive ledger reward, and the queued withdrawal blocked staking
then drained. These are separate passing checks in the report. They do not
prove that the pool could stake **again** after the queue cleared.

The **second** order, labelled `pool-stake-after-drain`, was sent at
00:55:05 UTC for election `1790211315`. At 00:58:06 the unchanged 180-second
poll ended with pool state 0, `stake_amount_sent=10001000000000`, seven
nominators and one not-exercised check: “draining the queue lets the pool back
into an election”. The a4 report and terminal transcript contain neither the
second order's query ID nor its controller bounce/abort or Elector reply.
Pool state 1→0 is ambiguous: `pool.fc:345-376` handles a bounced controller
relay, while `pool.fc:510-518` handles Elector `new_stake_error`. Neither
branch is established by the retained result. The first-round amount fix
must not be assumed to diagnose the second round.

The minimum next observation is an exact-query-ID read of the pool's inbound
Elector opcode/reason and bounced controller relay, plus the matching
controller transaction's abort bit. The lifecycle script now records that
query ID and both account cursors **before** wallet send. On the unchanged
180-second failure path it pages `raw_getTransactions` (ten transactions per
call) back to those cursor IDs, records pages/transactions scanned, and
requires the exact pool order transaction to appear. If a cursor cannot be
reached or the order is absent, the classification is `INCONCLUSIVE`; null
reply/bounce fields mean **not found in the covered window or unavailable with
a recorded collection error**, not “no bounce” or “no refusal”. The later e48
run supplied raw feedback, described below. No wait extension or causal claim
follows from the a4 report alone. T3 remains OPEN.

### e48a31af1 follow-up: a reply recovered from the retained raw trace

The e48 exact-tree run ended `passed=false`; its report is
`test/integration/.pq-nominator-pool-t3/e48-feedback/20260924T011747Z/report.json`
(SHA-256 `c5c1a605b958316c82ff838ed9a36d2b8262e755aa1ce3c90571ba4744762c52`).
The terminal recorder is `test/integration/.pq-nominator-pool-t3/e48-feedback.typescript`
(SHA-256 `09a63284b9adafcf19b1a615ccf3726ef9fc9fb8d6203cc456d8267824675b8c`).
The first pool stake, live ConfigParam 34 selection, recovery, eight positive
rewards, queued refusal and drain passed again. The second order used query ID
`1790213858653322247` and again ended state 0 after 180 seconds.

The report's `INCONCLUSIVE` was **an instrument error, not an absence of chain
feedback**. The raw `raw_getTransactions` reply in the retained recorder has
the pool's exact pre-order baseline LT `2964000001` and hash
`2470dd98…24308251` **in the returned page**; its `previous_transaction_id`
is `2710000001`. The controller page likewise contains its exact baseline LT
`1045000005` and hash `ad9c93be…1076bc71`, then `previous` is zero.
`_transactions_since` had filtered out the baseline before checking that it
was present and moved to `previous`, incorrectly reporting a crossed cursor
and zero scanned transactions. Its new regression reconstructs this page
semantics: old logic RED on the crossed-cursor exception, corrected logic
GREEN; a page that crosses without the exact LT+hash still fails closed.

The retained **pool** page contains the second order transaction at LT
`2973000003` and an inbound message **from the Elector** at LT `2973000009`.
Its `msg_dataRaw.body`, copied from `e48-feedback.typescript`'s
`raw_transactions` reply, is the full 33-byte BOC
`B5EE9C72410101010012000020EE6F454C18D81E04FD033C07000000000F0F0726`.
The tracked `test_retained_e48_elector_reply_boc_names_the_second_order_and_reason`
decodes those exact bytes and checks that no bits or references remain.
Decoding yields opcode `0xee6f454c`
(`new_stake_error`), the exact query ID above, reason **0**, and no trailing
bits or refs. The retained **controller** page contains the matching pool
relay at LT `2973000005` and an outgoing `PQst` message to the Elector;
therefore this was not a missing controller relay. The pool page between the
order and reply contains no controller bounce. The recorder does not expose a
separate parsed controller `aborted` boolean, so do not invent one: the
outgoing Elector message and returned Elector opcode establish the route.

This is **raw-recorder evidence**, not a retroactive correction of the e48
`report.json`: that report remains `INCONCLUSIVE` with zero scanned pages
because its paginator failed before analysis. Reading the saved raw replies
shows the exact baseline in each page, the pool's two newer transactions and
the controller's one newer transaction. The corrected paginator will report
that coverage on a future run; no new run is claimed here.

Reason 0 is the Elector's “no active election / finished election / election
deadline reached” family (`elector-code.fc:236-242,303-311`). The accelerated
profile installs `election_params = 300 180 60 180`, so for the second
`elect_at=1790213868`, `elect_close=1790213808`. The Elector reply transaction
has chain `utime=1790213858`, **50 seconds after that close**. The script's
`active_election_id` get method returns a nonzero ID whenever the election
dictionary exists, including after its accepting window closes. The final
predicate `value > 0` therefore selected a stale election. This is the
specific script-level boundary to repair; it is not a controller-witness or
stake-amount refusal and does not justify extending the 180-second wait.
The selector now reads `participant_list_extended`'s actual `elect_close` and
`finished` fields, compares them to the lite-server chain time with a
30-second **harness send allowance**, and rechecks the same `elect_at`
immediately before making the final wallet order. This guard concerns the
script's fee-bearing order timing, not Simplex or PQ consensus parameters.
The parser test embeds the exact nested `result:` line from retained
`test/integration/.pq-election-first-round-retry/20260923T124354Z/artifacts/pq-first-three-participants.txt`
and also checks a wrapped-line variant. The source guard rejects restoring
the old `active_election_id` selection or dropping the pre-send recheck;
the short behavior test proves that the e48-style nonzero ID is rejected
after its close while an open window is returned. No new live
second-stake acceptance is claimed; T3 remains OPEN.

### 463f44bea exact-tree run: the stale order is prevented, re-entry remains untested

The serial run at
`test/integration/.pq-nominator-pool-t3/463f-window/20260924T015823Z/report.json`
has SHA-256 `9408613f6391226e1a29fd972f4472d007aefa9eaa2dd99fb0ea08de15d89f7f`.
Its unedited terminal recorder is
`test/integration/.pq-nominator-pool-t3/463f-window.typescript`, SHA-256
`6a6b269f1c3eb43c1a7fa56aff383c78d9f4ac603523c8c34ac858e973c3b828`.
The native build's `build/git.cc` identified full source commit
`463f44bea31e04da48abf5fa8b01c2b04426c8d3`; the validator-engine,
Rust order-builder and lifecycle script SHA-256 values recorded before the
run were respectively `7697fb1c1fb762c38a3b6c1204f3e4f920b067841dfcf139da7c2564b7985143`,
`ddc7e5e8ac36bc040163d232797be01509c40d495a62f1ff8da31ad21f545f64`, and
`fc717bb2b69782b329011b1fbc0be49f869792d5ce5f5073f903b950d5943553`.

The report is `passed=false`, exit 1, with **26/26 executed checks passing**.
It proves the first pool stake reached state 2 for election `1790215703`,
its controller/ADNL pair entered live ConfigParam 34, the stake was recovered,
eight identity-bound nominators received positive reward, and the blocked
withdrawal queue drained without validator messages on the exit path. The
specific unexercised check is “draining the queue lets the pool back into an
election”. The terminal failure is
`TimeoutError('an election with an open pool-stake acceptance window: gave up after 900s, last=0')`.
**No second order was sent**: there is no second query ID, no second Elector
reply and no second state-2 claim. This differs from e48, where a second order
was sent and the Elector explicitly returned reason 0.

A read-only live query during the wait found `elect_at=1790216303`,
`elect_close=1790216243`, chain time `1790216521`, and an empty participant
list. This shows the nonzero old `active_election_id` would have selected a
closed window again; the new selector correctly returned zero. The terminal
recorder contains two waves of four `support-validator-*-pool-stake` sends,
and no third wave. At chain time `1790216809`, a separate read-only
`getaccount` reported one supporting pool's balance as
`31.999833183 TOS`, below the script's approximately `10012 TOS` threshold
for another order. That one-off balance response was not saved as a separate
raw artifact, so it is supporting observation, not an artifact-backed
four-pool balance inventory.

The fixture reserves only two stake principals per supporting pool
(`SUPPORT_POOL_CAPITAL = 2 * POOL_STAKE_VALUE + 20 TOS`), and the upkeep loop
does not recover their matured first-round Elector credits. The source and
two observed support-stake waves make **support-capital exhaustion a specific,
testable explanation** for the empty later election; they do not establish
that all four credits were available for recovery at the required times.
The ordinary 100,000-TOS Genesis faucet has only 3,600 TOS uncommitted after
known fixture transfers, so simply granting each supporting pool a third
10,002-TOS principal would not fit the existing profile. The next bounded
unit is to prove whether those first-round credits can be recovered and
reused before the third window closes; do not extend the wait, alter Elector
or consensus parameters, or report a second accepted stake until a new live
run supplies it. T3 remains OPEN.

### Support-capital recovery gate (implementation pending live evidence)

The script now records each keeper poll's raw `getconfig 34`,
`participant_list_extended` (including `elect_at`/`elect_close`), Elector
`past_elections_list`, and all four supporting pools' raw `get_pool_data`,
account balance and `compute_returned_stake`. The per-poll paths and parsed
values enter the run report. `get_pool_data` on the single-nominator support
pool has compatibility state/counters, so those fields are **recorded, not
used as proof of maturity**.

The keeper retains the actual `unfreeze_at` and validator-set hash while a
*retired* election remains in Elector's past list. `check_unfreeze()` then
deletes that record when it creates owner credit. Consequently a positive
credit and a still-present, mature past record are not the intended joint
test. Reuse requires the prior live Config34 hash to match the observed
retired record, a different current Config34 set, chain time past that
record's actual `unfreeze_at`, its subsequent absence from the live past
list, and sufficient credit on that **pool owner**. Only then does the pool's
operator send `RECOVER_STAKE` through the pool. The script pages the pool's
history to a pre-send LT+hash baseline and requires the matching Elector
`0xf96f7324` reply and consumed credit plus increased pool balance. A
fee-bearing recovery with an error or missing reply is not sent again on the
next keeper tick. These checks are local tests and source guards until a new
fixed-tree live run produces the corresponding chain artifacts. The 463f
run remains failed; its unsent second order is not an Elector rejection.

## Contract-level falsification and bounded fixture correction

The original section below deliberately preserves the hypothesis and its
pre-test uncertainty. `a_multi_nominator_first_stake_exposes_the_exact_refusal`
now exercises the compiled multi-nominator pool, PQ controller and Elector
with the production `nominator::new_stake_with_witness` builder. The pool is
provisioned with the same 5,100 TOS validator contribution but no nominator
entries; this isolates transfer economics and does **not** recreate the full
eight-nominator live state. With the lifecycle script's old 10,001 TOS order:

| Observable | Sandbox result |
| --- | ---: |
| Pool → controller | 10,001 TOS |
| Controller → Elector | 10,000.26741 TOS |
| Controller aborted / bounce to pool / Elector aborted | false / false / false |
| Elector reply | `STAKE_RETURNED` (`0xee6f454c`), reason **5** |
| Pool state / controller membership | 0 / absent |

The controller forwarding path consumed 0.73259 TOS. The Elector then reserves
1 TOS before its 10,000 TOS minimum check, so the old order has only
9,999.26741 TOS left for the minimum. This is a measured contract-path
mechanism, **not** a recovered reply from the earlier live report. The
paired `a_multi_nominator_first_stake_with_forwarding_allowance_is_accepted`
test requests 10,002 TOS. It measures pool → controller 10,002 TOS,
controller → Elector 10,001.26741 TOS, no abort or bounce, Elector
`STAKE_ACCEPTED` (`0xf374484c`) with reason 0, pool state 2, and the
controller in the Elector participant book. Both tests complete as a short
contract sandbox without booting a network.

The lifecycle fixture now budgets a separate 1 TOS controller forwarding
allowance as well as the existing 1 TOS Elector confirmation allowance. Its
route guard pins both the formula and the builder argument; its budget test
pins the resulting amount. This changes no production consensus or contract
parameter and does not close T3. Closure still needs a fixed-tree live run
showing `STAKE_ACCEPTED` and pool state 2, with its own preserved report.

## Exact retained report and observed boundary

- Report: `test/integration/.pq-nominator-pool-t3/20260923T194602Z/report.json`
- SHA-256: `cd0d167de01c24545fc2038426859062d66105618bc24849ba3475b5ad07fb58`
- Run ID: `n6-49a-multipool-diagnostic`; `passed=false`; 17 later checks were
  not exercised. The report does not itself pin a `source_commit`, so the run
  ID must not be substituted for exact-tree provenance.
- At 19:53:04 UTC the script observed election ID `1790193363`; at 19:53:06
  it recorded sending the primary `pool-stake` order with a 2 TOS wallet
  message to pool `-1:b49791ce18adec5aedff8d9e7024395b660a29c51b543e87b6ccd77037e8db8a`.
  After 180 seconds waiting for `POOL_STATE_STAKED`, the last `get_pool_data`
  result was `state=0` (idle), `stake_amount_sent=10000000000000` nanotos
  (10,000 TOS), `stake_at=1790193363`, eight nominators and zero validator-set
  changes. The report records neither a controller bounce nor an Elector reply
  opcode/reason.

The nonzero `stake_at` and `stake_amount_sent` show that the primary pool
processed an order past its local validation and saved its stake attempt:
`pool.fc` sets those fields, then state 1, before relaying to the controller
(`crypto/smartcont/nominator-pool/pool.fc:632-669`). A failure in the Python
authorization request or production body builder *before* wallet send, failure
to reach the election-open stage, or an early pool validation throw before `save_data`
does not explain this final pool data. This does **not** prove that the Elector
received the relay.

The final idle state has two distinct contract paths. A bounced `relay_stake`
from the configured controller resets state 1 to 0 (`pool.fc:345-376`);
alternatively, an Elector `new_stake_error` addressed to the pool resets state
1 to 0 (`pool.fc:510-518`). Both leave `stake_amount_sent` and `stake_at`
populated. The run's state-only poll (`scripts/nominator-pool-lifecycle-e2e.py:3744-3750`)
cannot distinguish them. A successful `new_stake_ok` would set state 2, which
was not observed at the timeout. The other support-pool sends show that the
network continued to process the election, but sending alone is not proof
that every support stake was accepted.

## Specific hypothesis, not a diagnosis

The fixture asks the primary pool to stake only `NETWORK_MIN_STAKE + 1 TOS`
(`scripts/nominator-pool-lifecycle-e2e.py:110-115`), while its economics Genesis
sets ConfigParam 17's minimum to 10,000 TOS
(`test/tostester/src/tostester/zerostate.py:554-563`). The multi-nominator pool
forwards exactly the requested amount to its controller using send mode 1
(`pool.fc:669`), unlike the single-nominator support pool's mode 64, which also
carries remaining inbound value (`single-nominator-code.fc:163`). The
controller forwards remaining inbound value using mode 64
(`validator-controller-v1.fc:219-226`), and the Elector subtracts 1 TOS for
its confirmation before checking the minimum (`elector-code.fc:298-299,383-384`).
If any forwarding fee is deducted from the primary 10,001 TOS along this
path, the effective amount falls below 10,000 TOS and the Elector returns
`new_stake_error` reason **5**. `stake_amount_sent=10,000 TOS` is the pool's
bookkeeping (`pool.fc:647`), not a measurement of what reached the Elector.

This predicts a precise reply, but the retained report does not record it.
An earlier controller bounce, a different Elector refusal, or another
unobserved transaction result would refute the amount explanation. The live
ConfigParam 47 read-back in the report establishes that the admitted code hash
was present; it does not independently prove the primary controller's witness,
key binding or stake acceptance.

## Minimum falsifying check before a fix

Use a short contract sandbox, not a ten-minute network. Reuse the real
controller/Elector setup in `tosctl/src/node-control/contracts/tests/elector_sandbox.rs`
and substitute a compiled multi-nominator pool with the same production
`new_stake_with_witness` body and 10,001 TOS order as the script. The current
`nominator_pool_sandbox.rs` uses a treasury account as its controller, so its
pool-only relay assertion cannot provide an Elector verdict. Capture the
pool-to-controller and controller-to-Elector transferred amounts, the
controller transaction's abort/bounce status, the Elector transaction's
abort status and exact reply opcode/reason, and the pool's final state.

If and only if the baseline produces an Elector `new_stake_error` reason 5,
add an explicit forwarding-fee allowance to the fixture's requested stake and
funding budget, then require the same short test to yield `new_stake_ok`, pool
state 2 and the controller in `participant_list_extended`. Restoring the
original too-tight amount must make that test red on reason 5. If the baseline
shows a controller bounce or another refusal, investigate that exact branch
instead; neither a longer wait nor a speculative amount increase is evidence.

T3 and the product first-stake witness correctness question remain OPEN. The
separate Merkle actor reproduction is not touched by this investigation.

## 2026-09-24 support-capital reuse run (diagnostic, still failing)

The exact `07a9e25d8` tree ran with the production pool-order builder and
fixed-head native binaries. Its retained report is
`test/integration/.pq-nominator-pool-t3/957-support-reuse/20260924T030116Z/report.json`
(SHA-256 `df537aa870c0b9a67bff9d26d18a00110b3e4a601d6da4ae507eec105bebd3d6`).
The report says `passed=false`: all 26 checks reached passed, but the final
"draining the queue lets the pool back into an election" check was not
exercised. The main pool's second order was **not sent**. The script waited
its existing 900-second limit for an election with an accepting window and
ended with `last=0`. This is not an Elector refusal of a second order.
Before launch, `build/git.cc` identified `07a9e25d8`; SHA-256 was
`5b9922c73a90ddd5eba7c91137ec699bdffa199d2959d9867dd27df5590f58ce`
for `build/validator-engine/validator-engine` and
`0f8ec7280d913127012f811da0cdc37f6bc8be87e2ffdddce9ac6083f5842ca1`
for the production Rust `pq_pool_stake_order` bridge. The bridge's Cargo
target was already up to date because its Rust sources had not changed since
the preceding build; its binary predates this head and is identified by hash,
not claimed as newly compiled from this commit. The bounded run exited
1 without a watchdog stop; peak run-directory size was 9,884,368,896 bytes,
below its 12 GiB cap. Its report and raw artifacts remain in place.

The run did establish four independent support-pool capital recoveries from
the *first* election. ConfigParam 34 had moved from set `1790219476` to
`1790219776` with different hashes; the former set's chain-reported reset
`unfreeze_at=1790219956` passed, its `past_elections_list` record disappeared,
and each pool owner then had `compute_returned_stake=10014780045073` nanotos.
Each pool sent its own `RECOVER_STAKE` and received exact query-id Elector
reply `0xf96f7324`, detail zero. Transaction pagination covered the pre-order
baseline (two transactions, one page each), the owner credit was consumed,
and each pool balance rose from about 32 TOS to about 10,047.78 TOS. The raw
ConfigParam 34, past-elections, participant-list, account, credit and pool-data
outputs are retained under the same run's `artifacts/` directory. These are
evidence of first-set maturity and capital reuse, not evidence of a complete
multi-nominator lifecycle.

At the third election, `elect_at=1790220076` and `elect_close=1790220016`.
The keeper's 20-second poll first observed recoverable credit at chain time
about `1790219974`. Recoveries then ran serially. Support pools 1–3 sent a
third-round stake; after pool 4's successful recovery the chain time was
`1790219989`, leaving 27 seconds before close, below the harness's 30-second
send allowance. Pool 4 did not send. The later participant-list output still
named this closed election and live ConfigParam 34 remained set `1790219776`.
This is a directly observed *window scheduling boundary*, not yet proof that
the missing fourth order alone prevented a new set. The next falsifying step
is a bounded keeper-poll scheduling test, followed by an exact-tree live run.
The next tree polls every five rather than twenty seconds when an
unrecovered support stake has a chain-observed retired-set `unfreeze_at`
within sixty seconds. The unit test checks both sides of the threshold,
continuation after unfreeze while credit is pending, and return to the normal
poll after all pools recover; the source guard pins the call-site wiring. This
does not weaken the accepting-window check or change an Elector/consensus
parameter. It is **not yet live-verified**. T3 and the product first-stake
witness question remain OPEN.
