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
Decoding the latter's full 33-byte message BOC yields opcode `0xee6f454c`
(`new_stake_error`), the exact query ID above, reason **0**, and no trailing
bits or refs. The retained **controller** page contains the matching pool
relay at LT `2973000005` and an outgoing `PQst` message to the Elector;
therefore this was not a missing controller relay. The pool page between the
order and reply contains no controller bounce. The recorder does not expose a
separate parsed controller `aborted` boolean, so do not invent one: the
outgoing Elector message and returned Elector opcode establish the route.

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
