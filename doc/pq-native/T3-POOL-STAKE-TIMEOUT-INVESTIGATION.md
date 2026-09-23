# T3 multi-nominator first-stake timeout: bounded investigation

Status: **OPEN — the rejection path and root cause are not yet observed.** This
is a same-host diagnostic run, not launch or release acceptance. Do not extend
the 180-second wait or mark the stake accepted on this evidence.

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
