# T2 launch-gate migration map

The no-argument `--mode launch-gate` runs the complete PQ Stage-A route,
including three elections, pool-owned recovery, restarts and quorum behavior.
The narrower `pq-election` remains a one-round diagnostic. The original
default-route conversion did **not** retire the script-wide classical caller:
`--mode experiment` still used both validator-election Fift tools, signed
locally, and attributed stake recovery to validator wallets at `60a299125`.
That distinct route was converted at `471e0a027`; both modes now obtain node
authorization and use the same production pool stake builder. This does not
retire the base Fift tools, which have other retained callers.

The shared PQ route is node `createPqStakeAuthorization` ->
`nominator::new_stake_with_witness` -> validator wallet -> single-nominator
pool -> admitted controller -> elector. A valid stake is identified by the
elector's `STAKE_ACCEPTED` reply and its participant record; an election is
identified separately by activated ConfigParam 34 with the four controller
IDs. Neither a sent message nor `STAKE_ACCEPTED` alone proves election.

## Classical stake caller inventory at `8fdc1c044`

This is an exact-file inventory, not the shorthand globs in the open
correctness entry. The first nine rows are the retained Fift/caller surface
that prevents deleting the base election tools today; the tenth is a now-cleared
caller retained here as migration history. The remaining paths are
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
| `scripts/validator-election-stage-a.py` | Cleared at `471e0a027`: default, PQ diagnostic and explicit `experiment` all use node authorization and the production pool body. The experiment credits/reclaims pool-owned stake and joins selected controller/ADNL identities, not classical keys or validator wallets. Remove this script from the live Fift-caller count, but retain this row to explain the prior dependency. |
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
| Under-minimum, wrong-election and invalid-signature requests leave participant state unchanged | Drive a well-formed PQ request through the pool/controller when admission must be reached. Pin the elector's specific refusal: source currently gives reason 5 for a first stake below `min_stake`, 3 for wrong `stake_at`, and 1 for a bad ML-DSA signature after other checks. The last case must alter a valid node authorization's signature without changing its length. Confirm those reasons live rather than treating returned funds as sufficient. | Proven live: reasons 5/3/1, unchanged participation, `af79222b9` report below. |
| Three accepted candidates are below the four-validator election minimum | Submit three production-builder pool orders; require exactly their three controller IDs, and compare the elector's actual effective total with the four-validator threshold. The old literal 30,000 TOS does not apply to the current 11,000-TOS order. | Proven live: 33,002,996,815,200 below 40,000,000,000,000. |
| Restart the fourth node during the open election; its stake is accepted | Restart its PQ-custody node, re-check controller-address/key binding, obtain a fresh node authorization, send through its pool, and assert elector `STAKE_ACCEPTED`. | Proven live after one closed connection and three bounded `not started` authorization retries. |
| A duplicate validator key is refused without changing the first stake | After controller 1 registers, send a deliberate test-only elector-layout request from the negative wallet carrying that held PQ key. Source checks key ownership before controller admission and should return reason 4; assert that exact reply and unchanged `participates_in(controller_1)`. This is not a client staking path. | Proven live: reason 4, unchanged participation. |
| First ConfigParam 34 activation elects the expected four and the network runs 3-of-4 | Require `utime_since == election_id`, `total=main=4`, and the exact four controller IDs (plus ADNL IDs); then retain the existing 3-of-4 height-advance test. | Proven live: exact controller/ADNL pairs, four main validators, and seqno 1485→1515 with one stopped. |
| Early stake recovery pays nothing | Send recovery from validator wallet **to the pool**, not directly to elector. The pool forwards the request, and the elector credits the pool that owns the stake. Check the pool's returned-stake value and balance; wallet balance is no longer the payout authority. | Proven live: pool credit remained zero; no-credit elector reply. |
| Second election accepts four, survives restarts, and activates a second set | Reauthorize for the second `election_id`, fund each pool for another order, require four `STAKE_ACCEPTED` replies and exact controller IDs in the second live ConfigParam 34. Preserve the pre/post-activation node restarts. | Proven in opt-in full PQ Stage A at `36ac27039`; default entry not yet switched. |
| Rollover election opens, accepts four, and activates the third set | Use the same node-authorized pool route for all four, retaining the `past_elections` readbacks and exact third ConfigParam 34 activation. Fund pools for the third stake without conflating a top-up with an election reward. | Proven in opt-in full PQ Stage A at `36ac27039`; fresh pool top-ups recorded separately. |
| First and second held stakes recover with bonus; duplicate recovery does not pay | Query `compute_returned_stake` for each **pool address**, order recovery through each pool after unfreeze, then require that pool's credit is removed and its balance increases by the recorded amount. Require the credit to exceed the original effective stake, and repeat recovery to prove no second credit. The wallet-based legacy assertions would inspect the wrong owner. | Proven: four credits per round, mature-success/no-credit opcodes, credit deletion and pool balance increase. |
| 2-of-4 validators safely halt and resume when restored | Keep the existing height-sample and restart assertions after PQ rollover; no stake encoding change is needed for this consensus property. | Proven: eight height samples at 3437, then 3440 after restart. |

The first-round results above come from the exact-tree diagnostic report
`test/integration/.pq-election-authority-retry/20260923T125649Z/report.json`
at `af79222b9` (SHA-256
`9b6c369d4ffe2e4a6685e45b46c348a4f525a617530c36507460209517eacfb7`).
A wallet without a birth witness separately returned reason 8. It is an
admission control, not a substitute for the three pool-route negatives.
The second/rollover and recovery rows use the exact-tree opt-in full-mode
report `test/integration/.pq-full-launch-gate-budgeted/20260923T133630Z/report.json`
at `36ac27039` (SHA-256
`a8ac3f21dd616bbf1eb7feeef6cd27b6cecfaeed7c8365e8d12ce42f0d7aebbd`).
The previous full-mode report at `52689aa0f` stopped at a test-faucet
funding boundary before a second-round stake, not at the elector; it remains
retained rather than silently replaced.

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
   **Implemented and passed** in explicit `pq-launch-gate` Stage A on
   `36ac27039`; this is not yet the default command.
4. Only after every old assertion has a live PQ counterpart, make the full
   route the default and re-run that default invocation on the committed
   tree. **Done for the default route** at `60a299125`, but the explicit
   `experiment` route still called the two classical election Fift tools and
   signed locally at that checkpoint. The original script-wide dependency was
   discharged separately at `471e0a027`, not by changing the default. The two
   Fift files themselves remain until **all** other retained callers and
   `test-smartcont.cpp` migrate together under T3.

The no-argument default run from exact source commit `60a299125` completed
with report `test/integration/.pq-default-launch-gate-final/20260923T141145Z/report.json`
(SHA-256 `a5f8491276fa2718e1898fdd2d8bbd533edba3cfb56c114fc920bf142eb871cf`).
The source commit at report time is identical. The report has zero failures:
12 production-builder pool/controller stakes received `STAKE_ACCEPTED`, while
the first-round admission controls pinned reasons 8/5/3/1 and duplicate-key
reason 4. Separately, live ConfigParam 34 activated at election IDs
1790173307, 1790173607 and 1790173907, each with `total=main=4` and the
same exact four controller/ADNL associations. Four first-round and four
second-round pool credits matured and were recovered with success opcode
`0xf96f7324`; a duplicate recovery returned `0xfffffffe`. The two-of-four
halt kept eight samples at height 3435 and resumed to 3436. These are
co-located diagnostic results, not release-scale evidence. Overall T2 stays
open at that checkpoint while the experiment-mode classical stake path remained
reachable.

On exact source commit `471e0a027`, the explicit `--mode experiment` live
diagnostic ran 600 seconds plus a 600-second settlement tail and exited 0.
Its report is
`test/integration/.pq-experiment-v4-live/20260923T145843Z/report.json`
(SHA-256 `d04b4a111d004e5466838f25f85e568bf0dd2c84c5649de5f39402188b2199df`);
the v4 allocation evidence is in the same directory
(SHA-256 `c8c63932f760dfee3c801be34e8b2fff2eba242f449db7808e9fcbf549a10ac7`).
The report records the same source commit at start and finish, an empty tracked
patch, 12 binary snapshots and 48 generated-contract snapshots. Two elections
each accepted four node-authorized, production-builder wallet→pool→controller→
elector stakes. Both activated live ConfigParam 34 with `total=main=4`.
The original ConfigParam 34 artifacts, not just the v4 summary's ADNL list,
independently reproduce the four expected controller/ADNL pairs: first-election
SHA-256 `1d88566aa0784259c94379e32fbe0c2aab2a90d1a3692a840add8d0dc8eb4eae`,
rollover SHA-256 `2b0878db5beffd71f6623cd5a9a193bd5d8cc87a18167c7e007b5f0db30a38d7`.
Four matured first-election pool credits were recovered; each was
11,015,493,742,708 nanoTOS against 11,000,998,938,400 nanoTOS of elector-observed
accepted principal. The four successor stakes remain explicitly marked as
not-yet-mature settlement rollover, not misattributed to the first election.
`outstanding_allocations=0` counts matured and primary obligations, not a claim
that those successor stakes have already recovered. The matured-retained and
mixed-credit attribution branches are covered by fake-client tests, not by
this live run. A subsequent 600+900-second exact-tree run at `8dd38d088`
ended red (report SHA-256
`2a29b4f79be100410497be277890af6bcd6af163714d1f8a0b6a59dc3495e1ad`)
after classifying four still-active successor stakes as matured merely because
the *initial estimate* had passed. The live ConfigParam 34 had not changed
from that successor set. Elector `check_unfreeze` cannot credit an active set,
and `update_active_vset_id` resets the old set's unfreeze time on retirement.
The corrected v4 classifier reads current ConfigParam 34 and its cell hash
against Elector `past_elections_list` and distinguishes active-retained,
retired-frozen and matured-unrecovered. The red run is preserved as the reason
for the correction, not described as a pool-recovery failure; the corrected-tree
600+900-second rerun at `98459da62` passed (report SHA-256
`e705ba47099b62c4daefa8b72292622cc6c7603174185e8fcbd01d0978a3c882`,
v4 evidence SHA-256
`564ad033f8f4946c98c2298dc4edbfad3e445a1c5f0b3c0b4f88921457adddc0`).
It recorded eight accepted production PQ pool stakes, two activated
four-controller ConfigParam 34 sets and four recovered first-round pool
credits. At terminal sampled masterchain creation time `1790180906`, the second set `1790180280`
was still current ConfigParam 34 and matched Elector's past-election set
hash; its recorded `unfreeze_at=1790180760` had passed, but an active set
cannot unfreeze. Its four stakes were `active-retained`, not outstanding,
and the experiment recorded no second-round recovery. That recovery is shown
by the separate three-election default launch-gate report, not by either
experiment-mode run. The 600+600 observation completes the
script-wide T2 classical-stake conversion on a co-located diagnostic topology;
it is **not** release-scale evidence and does not retire other T3 Fift callers.

No step changes election criteria, weakens a negative check, or treats the
co-located diagnostic run as release-scale measurement.
