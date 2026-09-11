# D61 payout fee edge retirement

Specification baseline: `900aaf87853c29a5`. Work in progress; no M5 live claim.

D68 follow-up verified against `817dbacecc6171b4`: insufficient return reserve
is a normal partial-compensation branch, never an operating-budget subsidy or
an unreachable assertion. This outward-fee helper does not implement that
return settlement branch. The existing wrong-destination bounce helper only
prices against its own inbound value and is not a Withdrawal reserve ledger.
Rich-bounce routing tests will establish body/metadata preservation and message
size, not an empirical bound on future governance fee changes.

## Consumer inventory before implementation changes

- `workchain-payout-accounting.h`: constructs the coordinator-to-custody
  `fee_funding` edge and balances its payout-stage rows against it.
- `transaction.cpp`, `Transaction::build_workchain_payout_pair`: applies the
  helper's custody/operator balances, adds the locally collected forwarding
  fee and serializes the two Native participants.
- `transaction.h`: exposes that pair builder and its accounting result.
- `workchain-payout-overlay.h`, `build_workchain_payout_overlay`: reserves an
  extra transfer-count allowance, inserts the edge into the decoded value-flow
  graph and publishes the edge in `WorkchainPayoutOverlay`.
- `workchain-payout-overlay.h`, `replay_workchain_payout_overlay`: rebuilds the
  overlay before comparing candidate artifacts; inherits the same funding rule.
- `workchain-account-settlement.h`: dispatches payout effects to the overlay
  and consumes its authenticated state/import/export artifacts. It does not
  independently create a funding edge; its integration tests must still pass.
- `test-workchain-block.cpp`: helper, Native pair, disposal/payout composition,
  entry/allocation composition, overlay and replay expectations consume the
  accounting result or the edge directly.
- `test-workchain-construction-isolation.cpp`: builds and stores payout
  overlays; consumes their shape indirectly, not the edge directly.

Inventory command: `rg -n 'fee_funding|account_workchain_payout\(|build_workchain_payout_pair'
crypto/block crypto/test test validator --glob '*.{h,cpp}'`.

## Required change

Custody pays principal plus the full outward forwarding fee, while coordinator
funds are unchanged by this payout stage. Native local fees plus exported
principal and remaining forwarding value still balance independently. Remove
the old funding edge and its synthetic count allowance, rather than retaining
a zero-valued coordinator funding capability. Other authenticated allocation
edges are unaffected. Operation fees remain separately accounted by D32.

This does not implement Withdrawal authorization, reserve persistence, bounce
settlement, or Paid. Those require their own authenticated state transitions.
In particular, no charge may be deferred to Paid: payout principal is recorded
when exported, actual bounce receipts reverse the net payout amount, and Paid
does not move Native funds. No independent accounting prediction was read.

## Red observations before completion

After changing expectations but before the helper implementation, the rebuilt
`test-workchain-block --filter PayoutPrincipalAndFees` exited 1 at the custody
270 assertion. `--filter NativePayoutPair` separately exited 1 at custody 763.
These are funding-role observations before overlay validation, not malformed
request failures. Logs: `/tmp/uno-d61-helper-red.log` and
`/tmp/uno-d61-pair-red.log`.

With only the helper corrected and the old overlay edge retained,
`--filter AccountEngineExecution` exited 1 at `settled.is_ok()`. This intermediate
failure alone does NOT establish its exact error layer: the original assertion
did not print the returned error. A diagnostic was added; no precise rejection
layer is claimed from that original log (`/tmp/uno-d61-overlay-red.log`).

The diagnostic red was subsequently obtained in
`/tmp/uno-d61-overlay-control-lHf0oE`: only a shadow overlay header reinserted
the old coordinator-to-custody edge for the fixture's 100 forwarding fee. Its
transfer allowance was expanded so the count gate could not mask accounting.
The current test translation unit was compiled against that header and linked
against the normal libraries. `control --filter AccountEngineExecution` exited
1 and explicitly logged `per-account native value-flow mismatch` before the
named success assertion failed. This is the isolated accounting layer's neutral
error, not a claim of an end-to-end CandidateInvalid classification. The main
source and binary were never mutated for this control.

## Restored execution

The rebuilt `test-workchain-block` ran all 133 tests successfully (log
`/tmp/uno-d61-native-full-fresh.log`). Do not confuse this with the earlier run
of an obsolete object: a test edit during compilation required a forced
translation-unit rebuild before this result was recorded.

The default CTest closure-expiry, crypto-ABI-boundary and key-epoch-inventory
guards passed 3/3 with unchanged criteria (`/tmp/uno-d61-guards.log`). These are
focused results, not a full default CTest or M5 live acceptance claim.

After resolving review findings, both targets were rebuilt. The complete Native
target again passed 133/133 (`/tmp/uno-d61-reviewed-native.log`); the three guards
plus `test-workchain-m5-accounting-assertions` passed 4/4 under CTest
(`/tmp/uno-d61-reviewed-ctest.log`). The final reviewed run supersedes the
pre-review run above; it does not expand the scope of the acceptance claim.

Observed isolated Native pair: old balances 1000/1000, principal 137, outward
fee 100, new custody/operator balances 763/1000, exported value including
uncollected forwarding value 212, locally collected fee 25. The overlay tests
decode the same balances from actual produced account records and replay the
claimed roots. The operation has no coordinator fee-funding edge.

The forwarding predicate shared with B is used on helper balances, Native pair
balances and balances decoded from the overlay's actual ShardAccounts result.
The old-rule test in B's separate accounting target was migrated after notifying
B to avoid duplicate edits: real helper output now must pass the unchanged
predicate; synthetic old-policy output must still fail with the original named
reason. No independent prediction artifact was modified.

## Production consensus file disclosure

`transaction.cpp`: comments at `Transaction::build_workchain_payout_pair` now
identify D61 funding and limit the prior-state envelope claim to principal;
the called accounting helper changes
its balance results. No ordinary transaction phase, pricing algorithm, source
address rule or workchain activation refusal is changed. The payout-specific
helper and overlay are the behavioral changes. A consensus-boundary review was
completed under AGENTS. The review found no forwarding-arithmetic defect but
identified the separate test's retired expectation, the combined-debit boundary,
an overbroad principal-envelope comment and the zero-fee test's zero operator
balance. All four were addressed: unchanged predicate/new observation, 729
rejected with the named arithmetic reason versus 730 accepted, narrowed comment,
and a nonzero operator balance preserved in the zero-fee test. The review
transcript remains outside the repository in memo/reviews. This is a focused
code review, not D34 external cryptographic review or a consensus-safety claim.
