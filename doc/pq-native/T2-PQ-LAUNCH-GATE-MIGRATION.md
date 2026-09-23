# T2 launch-gate migration map

The pushed `--mode pq-election` rehearsal has proved one complete PQ election
on a running local chain. It is **not** a replacement for the script's default
`--mode launch-gate`: the latter still calls
`validator-elect-req.fif`/`validator-elect-signed.fif` and asserts multiple
elections, recovery, restarts and quorum behaviour. Changing the default to
the narrower mode would silently discard those assertions. The
`classical-stake-surface` inventory must continue to count this caller.

The shared PQ route is node `createPqStakeAuthorization` ->
`nominator::new_stake_with_witness` -> validator wallet -> single-nominator
pool -> admitted controller -> elector. A valid stake is identified by the
elector's `STAKE_ACCEPTED` reply and its participant record; an election is
identified separately by activated ConfigParam 34 with the four controller
IDs. Neither a sent message nor `STAKE_ACCEPTED` alone proves election.

## Classical stake caller inventory at `8fdc1c044`

This is an exact-file inventory, not the shorthand globs in the open
correctness entry. The first ten rows are the retained Fift/caller surface
that prevents deleting the base election tools today. The remaining paths are
recorded to keep already-converted tosctl callers and intentional legacy
fixtures from being confused with an unconverted launch path.

| File | Current use / disposition |
| --- | --- |
| `crypto/smartcont/validator-elect-req.fif` | Base classical preimage producer; retain until all callers move in T3. |
| `crypto/smartcont/validator-elect-signed.fif` | Base classical signed-body producer; same T3 constraint. |
| `crypto/fift/lib/Validator.fif` | Defines `validator-elect-req>B`; removing it alone breaks the pool tools and Fift tests below. |
| `crypto/smartcont/single-nominator-pool/validator-elect-signed.fif` | Stale operator tool for a PQ-ready pool; convert to node authorization and pool order. In launch set. |
| `crypto/smartcont/liquid-staking/controller-elect-signed.fif` | Classical tool for a contract-level unconverted product; liquid staking is not launch-supported. Do not represent this as a working PQ pool. |
| `crypto/test/test-smartcont.cpp` | Loads both base Fift tools and the single-pool script; update in the same T3 change that retires tools. |
| `crypto/test/fift/validator-proposal-test.fif` | Calls `validator-elect-req>B`; migrate or explicitly preserve as a self-contained legacy vector before removing the library word. |
| `crypto/test/fift/validator-proposal-legacy-parity.fif` | Same dependency, with an explicit classical parity vector. |
| `scripts/nominator-pool-lifecycle-e2e.py` | Still invokes the two base Fift tools for its election route; convert through the admitted controller/pool. |
| `scripts/validator-election-stage-a.py` | The new `pq-election` mode is clear, but its default `launch-gate` still invokes both base tools. **Do not remove this caller from T3's count.** |
| `tosctl/src/node-control/elections/src/runner.rs` | Converted: node authorization and pool order; no-pool route refuses. |
| `tosctl/src/node-control/commands/src/commands/nodectl/vote_cmd.rs` | Converted to a local refusal for its direct wallet-to-elector bid; no classical signature is sent. |
| `tosctl/src/node-control/commands/src/commands/nodectl/config_wallet_cmd.rs` | Converted: node authorization and pool order. |
| `tosctl/src/node-control/contracts/tests/elector_sandbox.rs` | Keeps an intentional classical `ELECT_REQUEST` fixture alongside its PQ pool/controller chain test; not an operator entry point. |
| `crypto/func/auto-tests/legacy_tests/elector/elector-code.fc` | Historical classical elector fixture, not the production PQ elector. |

The first ten rows are the retirement dependency graph, not permission to
delete them. A textual occurrence of `0x654C5074` in an intentional legacy
test or audit document is not a live stake producer. Conversely, the absence
of that literal does not clear a Fift caller that imports the library word.

## Existing assertion to PQ-path map

| Existing launch-gate assertion | PQ path and assertion to retain | State |
| --- | --- | --- |
| Under-minimum, wrong-election and invalid-signature requests leave participant state unchanged | Drive a well-formed PQ request through the pool/controller when admission must be reached. Pin the elector's specific refusal: source currently gives reason 5 for a first stake below `min_stake`, 3 for wrong `stake_at`, and 1 for a bad ML-DSA signature after other checks. The last case must alter a valid node authorization's signature without changing its length. Confirm those reasons live rather than treating returned funds as sufficient. | Not migrated |
| Three accepted candidates are below the four-validator election minimum | Submit three production-builder pool orders; require exactly their three controller IDs, and compare the elector's actual effective total with the four-validator threshold. The old literal 30,000 TOS does not apply to the current 11,000-TOS order. | Not migrated |
| Restart the fourth node during the open election; its stake is accepted | Restart its PQ-custody node, re-check controller-address/key binding, obtain a fresh node authorization, send through its pool, and assert elector `STAKE_ACCEPTED`. | Not migrated |
| A duplicate validator key is refused without changing the first stake | After controller 1 registers, send a deliberate test-only elector-layout request from the negative wallet carrying that held PQ key. Source checks key ownership before controller admission and should return reason 4; assert that exact reply and unchanged `participates_in(controller_1)`. This is not a client staking path. | Not migrated |
| First ConfigParam 34 activation elects the expected four and the network runs 3-of-4 | Require `utime_since == election_id`, `total=main=4`, and the exact four controller IDs (plus ADNL IDs); then retain the existing 3-of-4 height-advance test. | First activation/IDs proven in `pq-election`; 3-of-4 not yet migrated |
| Early stake recovery pays nothing | Send recovery from validator wallet **to the pool**, not directly to elector. The pool forwards the request, and the elector credits the pool that owns the stake. Check the pool's returned-stake value and balance; wallet balance is no longer the payout authority. | Not migrated |
| Second election accepts four, survives restarts, and activates a second set | Reauthorize for the second `election_id`, fund each pool for another order, require four `STAKE_ACCEPTED` replies and exact controller IDs in the second live ConfigParam 34. Preserve the pre/post-activation node restarts. | Not migrated |
| Rollover election opens, accepts four, and activates the third set | Use the same node-authorized pool route for all four, retaining the `past_elections` readbacks and exact third ConfigParam 34 activation. Fund pools for the third stake without conflating a top-up with an election reward. | Not migrated |
| First and second held stakes recover with bonus; duplicate recovery does not pay | Query `compute_returned_stake` for each **pool address**, order recovery through each pool after unfreeze, then require that pool's credit is removed and its balance increases by the recorded amount. Require the credit to exceed the original effective stake, and repeat recovery to prove no second credit. The wallet-based legacy assertions would inspect the wrong owner. | Not migrated |
| 2-of-4 validators safely halt and resume when restored | Keep the existing height-sample and restart assertions after PQ rollover; no stake encoding change is needed for this consensus property. | Not migrated |

The refusal numbers above are source-derived expectations from
`elector-code.fc::process_pq_stake`, not yet live results. In particular, an
invalid request must be constructed so it reaches the intended branch; a
wallet with no birth witness normally returns reason 8 instead. The proven
reason-8 wallet negative in `pq-election` remains a separate admission
control, not a substitute for the legacy three negatives.

## Serial implementation units

1. Extract the already-proven PQ authorization, Rust production order and
   exact elector-reply check for reuse by the old multi-round driver. Keep
   `pq-election` as the one-round diagnostic control. Add a source inventory
   that names every classical Fift caller in this script; do not remove one
   from the count before it actually disappears.
2. Migrate the first-round negatives, three-then-four candidate sequence,
   duplicate-key control, restart, exact activation, 3-of-4 liveness and
   early-recovery refusal. Pin each negative to the intended elector reason.
   Run this unit on the real PQ chain before proceeding.
3. Migrate the second and rollover elections and pool-owned recovery. Budget
   three distinct pool stakes; account for the owner/pool balance separately
   from validator-wallet fees. Require two bonus recoveries, duplicate
   recovery refusal, all ConfigParam 34 transitions and the 2-of-4 safe halt.
4. Only after every old assertion has a live PQ counterpart, make the full
   route the default and remove this script's classical
   `validator-elect-req.fif`/`validator-elect-signed.fif` calls and local
   Ed25519 stake signing. Re-run the default invocation on the committed
   tree. The two Fift files themselves remain until **all** retained callers
   and `test-smartcont.cpp` migrate together under T3.

No step changes election criteria, weakens a negative check, or treats the
co-located diagnostic run as release-scale measurement.
