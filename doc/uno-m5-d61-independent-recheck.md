# Independent D61 fee-chain recheck

B rechecked A's committed tree 293fc152ac32e9a464a3e426534a69b881ddcf78,
including correction 8b615855d328fc8544515ac7f4e3f567be7b7ae8, on 2026-09-11.
This is an after-the-fact recheck, not a new pre-observation prediction. The
independent criterion already existed in fa7dd4a18. B directly ran the commands
below; results here are not observations relayed by the coordinator.

## Execution and why this is not an empty green

In `/home/tomi/tos`:

```
cmake --build build --target test-workchain-m5-accounting-assertions test-workchain-block -j2
build/crypto/test-workchain-m5-accounting-assertions --filter D61PayoutChargesCustodyNotOperatingBudget
ctest --test-dir build --output-on-failure -R '^test-workchain-m5-accounting-assertions$'
build/test-workchain-block --filter PayoutPrincipalAndFees
build/test-workchain-block --filter NativePayoutPair
build/test-workchain-block --filter NativePayoutPricing
build/test-workchain-block --filter AccountEngineExecution
build/test-workchain-block --filter NativeDisposalEntry
```

Both targets rebuilt successfully. The direct D61 selector reported one test
passed; CTest reported 1/1 passed. Each of the five Native selectors reported
one test passed, exit 0. Build emitted initializer warnings; no build/test failure.
The initially guessed `build/crypto/test-workchain-block` path did not exist;
the rebuilt target is `build/test-workchain-block`. That path lookup was not a
business-check failure.

The D61 test actually calls the helper with custody 1000, coordinator 100,
principal 700 and outgoing fee 30. It checks custody 270, coordinator 100 and
then applies B's payout_forwarding predicate. In an isolated shadow-header build,
B replaced ONLY the helper header with its pre-8b615855d version and rebuilt the
same test translation unit. It exited 1 at the explicit
`observed.custody_after == C(270)` assertion (line 22), before the later predicate.
Thus this red is a real wrong-debit observation, not a malformed-input error or
proof that a later assertion ran. The normal binary subsequently passed.
No shared source was mutated. Isolation artifacts/logs: `/tmp/b-d61-independent`.

The fee-bearing Native path still exists:

* `transaction.cpp:4647-4689`: Native prices the actual request, then passes
  priced payment, total fee and collected fee to account_workchain_payout;
  applies custody_after/operator_after to the actual two transactions.
* `workchain-payout-accounting.h:37-52`: checked principal+total fee leaves
  custody; coordinator is retained; exported principal+remaining fee and local
  fee remain explicit. The synthetic coordinator funding transfer is gone.
* `transaction.cpp:4690-4710`: local fee is retained in transaction total_fees,
  the actual priced message is pushed to out_msgs, and participants serialize.
* `test-workchain-block.cpp:8029-8038,8091-8120`: the executed Native pair test
  checks custody 1000->763 and coordinator 1000->1000 for principal 137 and
  total fee 100; rereads serialized accounts and total_fees (25 on custody,
  zero on coordinator). The remaining forwarded value is exported, not erased.
* `test-workchain-block.cpp:8198-8247`: the executed overlay path requires a
  nonnull message, correct source and created_lt, published outbound message
  identity, decoded account balances and B's forwarding predicate. Replay and
  claimed-root comparisons execute in the same NativePayoutPair test.

These independent state/output observations make removal of the entire payout
edge an insufficient way to pass. They do not prove confidential authorization,
reserve persistence or a complete live Withdrawal lifecycle.

## Consumer set comparison (not counts alone)

B searched the committed whole tracked C++/header tree for:

```
fee_funding|account_workchain_payout\(|build_workchain_payout_pair|PreparedWorkchainPayoutPair|build_workchain_payout_overlay\(|replay_workchain_payout_overlay\(
```

The initial helper/overlay search was expanded to include the Native pair and
its declaration. The retired fee_funding member was also searched in the parent
of 8b615855d to identify consumers no longer spelling that member. These are
lexical direct-reference sets, not proof against aliases or indirect runtime
coupling. B then compared with A's committed retirement document.

| File (under crypto/) | Role | In A's textual inventory? |
| --- | --- | --- |
| block/workchain-payout-accounting.h | Direct funding construction, replaced by custody debit | yes |
| block/transaction.cpp | Applies helper result, retains fee and actual payout message | yes |
| block/transaction.h | Pair result and builder declaration | yes |
| block/workchain-payout-overlay.h | Build and replay; decoded flow verification and publication | yes |
| block/workchain-account-settlement.h | Payout dispatch and artifact consumption | yes |
| test/test-workchain-block.cpp | Helper, pair, pricing, overlay/replay and combined settlement consumers | yes |
| test/test-workchain-construction-isolation.cpp | Indirect overlay construction/isolation consumer | yes |
| test/test-workchain-m5-accounting-assertions.cpp | Direct helper consumer and B criterion | **no** |

B found eight unique files; A's eight bullets represent seven unique files
because overlay build/replay are separate bullets. The exact set difference is
`crypto/test/test-workchain-m5-accounting-assertions.cpp`; A-only difference is
empty. Crucially, 8b615855d DID modify this file and the test now passed here:
this is an inventory omission, not a discovered unfixed consumer. No remaining
fee_funding direct reference was found in the current tracked C++/header set.
A's report is left unchanged because it is A-owned evidence.

## Boundaries

The construction-isolation consumer was statically checked, not rebuilt/run in
this focused selection. Declaration files have no standalone execution. The
other listed roles are reached by the selected helper/Native pair/engine tests;
this does not enumerate every branch of each file. No full CTest, M5 live run,
network queue delivery or private harness result is claimed.

A's worktree had uncommitted Failed-related work while this ran. HEAD remained
293fc152a; the inspected payout implementation, settlement and test files had
no diff from that commit before/after execution. The uncommitted association
fixture and untracked Failed header were not part of these selected target
inputs. No source edits or baseline refresh were made to A's tree. Existing
build products were rebuilt rather than trusting timestamps alone.

Conclusion: the observed D61 helper and Native payout funding paths are green
for the intended reason. There is one textual consumer-inventory omission,
already implemented and tested, plus the explicit execution/lexical limits
above. This is not a claim that every future payout caller is D61-compliant.
