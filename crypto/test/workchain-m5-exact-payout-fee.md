# D75: exact outward fee at Native publication boundary

Specification: memo `b9b99b4f`, SHA256 prefix `d4885ae7bc210b68`.
No independent accounting prediction was read.

## Binding, not an allowance

There is one operation value: `debit.data.amounts.outward_fee`.
`execute_m5_test_debit` places it in the verified ABI request; the registered
engine independently prices the fixed payout request against authenticated
configuration, compares the price to that same field, and copies it into
`effects.payout_forward_fee`. Settlement and the payout overlay forward it as
`exact_outward_fee` to `Transaction::build_workchain_payout_pair`.

The new final check does **not** compare two quotes. After serializing the
private Native pair it computes:

    paid_fee = custody_before_payout - serialized_custody_after - actual_message_value
    paid_fee == exact_outward_fee

`custody_before_payout` is a value copy taken **after** imports, allocations and
D32 fee debits. The right endpoint is decoded from the generated Native Account
cell; the message value is decoded from the actual outbound Message. Checked
currency subtraction is used throughout. Mismatch returns **-7200** with
`Native payout fee differs from authenticated exact q`, before the pair can be
returned to the overlay for publication. No residual-value/refund flow exists.
The message value excludes its remaining forwarding-fee field: paid_fee thus
includes both the Native locally collected share and the share carried onward,
not merely the current block's collected fees.

For exact-q callers the Native pricing scratch uses old custody balance as a
computational ceiling, not a spending authorization. This avoids a too-small q
failing an earlier send-budget check instead of reaching equality. Actual
debit remains bounded by custody, and the serialized result must spend exactly
q. Legacy callers without the optional exact value retain the original
`fee_budget` behavior, including zero. Exactness is opt-in from the registered
engine; it is not claimed for arbitrary legacy payout callers.

## Red before green

The real Native-pair fixture uses distinct principal **137**, actual fee **100**,
old custody/coordinator balances **1000/1000**. Successful construction yields
**763/1000**. It does not use a detached arithmetic oracle.

Before installing the equality check, the explicit exact-q parameter was
present but unused, with a generous legacy ceiling of 500:

- `NativePayoutExactFeeLower`, declared q=99: exit **1** at `result.is_error()`.
- `NativePayoutExactFeeHigher`, declared q=101: exit **1** at `result.is_error()`.

Both had constructed successfully: neither red came from malformed input,
compilation, or insufficient Native funds. Logs:
`/tmp/uno-d75-lower-red.log`, `/tmp/uno-d75-higher-red.log`.

After implementation, both cases require **the exact -7200 message above**.
Each is also run with the registered caller's **zero legacy ceiling**, still
requiring that equality rejection rather than an earlier send failure. Exact
q=100 passes with ceilings 500 and zero; absent exact-q preserves the legacy
case. The unchanged `NativePayoutPair` and `NativePayoutPricing` tests also pass.

Final command: `test-workchain-block --filter NativePayout`, **5/5**, exit **0**.
Log: `/tmp/uno-d75-final-tests.log`. These mismatch tests exercise the Native
pair boundary; they do **not** claim signed-candidate mutation or the full
prepare handoff contracts. They do not use entry_input; the live run below
provides the evidence for the D32/import-isolation entry path.

## Follow-up: rejection must not publish

`NativePayoutExactFeeNonpublication` runs the same real Native builder with
x=137, actual q=100, declared q=101 and legacy ceiling zero. Its observation
boundary is both caller-owned Native Accounts (full serialized Account BOCs),
their committed transactions' decoded `out_msgs` dictionaries and counts, and
the returned pair. It requires unchanged BOCs, no committed transaction or
message residue, and no returned pair, then checks the specified -7200 error.
It does not infer nonpublication from that error code alone.

Before accepting this oracle, two temporary production mutations were run
separately inside the existing exact-fee mismatch branch, **retaining the same
-7200 return**:

- `const_cast<Account&>(custody).push_transaction(pair[0]->root, pair[0]->start_lt);`
  actually exposed the serialized transaction through the caller's Account.
  Exit **1** at `out_msgs.is_empty()`, not at the return-code check.
  Log: `/tmp/uno-d75-nonpublication-red.log`.
- `CHECK(pair[0]->commit(const_cast<Account&>(custody)).not_null());`
  actually committed the private transaction before returning the rejection.
  Exit **1** at the custody BOC byte comparison.
  Log: `/tmp/uno-d75-nonpublication-state-red.log`.

The const casts deliberately violate the builder's existing read-only Account
interface; ordinary direct writes are already blocked by that interface. The
red observations above are runtime failures from executing the bad writes,
not the preliminary compile rejection of a write through a const reference.
Neither mutation is retained; `transaction.cpp` is unchanged by this follow-up.
After restoration, `test-workchain-block --filter NativePayout` passes **6/6**
(exit **0**), including the new nonpublication test. Log:
`/tmp/uno-d75-nonpublication-green.log`.

Scope: real Native pair construction and its caller-visible Account/transaction
outputs. Private, unreturned transaction `out_msgs` may exist before rejection;
the test does not assert they were never constructed. It is **not** a live
collator queue/nonpublication mutation, does not exercise entry_input here,
and does not complete a prepare handoff item. The earlier live evidence below
has not been rerun for this test-only follow-up. Unknown-source counter remains
absent/unmeasured and the prepare contract remains 0/9.

## Actual accepted prepare

`python3 test/uno-m3-live.py --build /tmp/uno-merge-6ea2fbf80-tL5Uih --m5-debit`
returned **0**. Final fixture `/tmp/uno-m3-live-grcv32yz`, log
`/tmp/uno-d75-final-live.log`; both build targets passed.

- **x=137, q=100, b=23**, f=257; available `1000000000 -> 999999483`.
- `R_actual=R_book=999999506`; `N_hidden=999999483`, P=137, W=160.
- Both sides of `R+P=N_hidden+W` equal **999999643**. Nonzero backing and
  unpaired-fee controls reject, then pass after restoration.
- Real accepted payout hash
  `0DDCBAE82CC46610672CE6084CA2D31BB1DC985A7D9F5DDB104F818E1869A247`;
  stored/actual/queued LT **16000002**. Rich flags=3 checked. Record principal
  is checked against the operation and actual message, independently of the
  principal that cancels between P and W in the conservation equation.
- Collator/validator proof work **3636/3636**. Existing OFF phase-3 refusal,
  zero execution/transactions and no export checks remain active.

This is test-key decryption and test-side cumulative accounting, not a public
liability audit or node-side historical ledger reconstruction.

## Production boundary and review

`transaction.cpp` changes only **build_workchain_payout_pair** (plus an include):
private pricing ceiling selection and serialized-result equality are necessary
to reject both mismatch directions at the correct layer. Its production caller
is `workchain-payout-overlay.h`; settlement passes the independently reconstructed
exact value. Ordinary compute/action/bounce/storage functions are untouched.
The ordinary wc=0 transaction path does not call this explicit batch pair.
Absence of exact-q preserves the old ceiling expression; D59 defaults and all
four original refusal strings are unchanged. Native legacy tests and live OFF
are behavioral corroboration, not a claim of whole-repository regression.

Read-only Claude boundary review: **no blockers**. It confirmed serialized
debit measurement, import/D32 isolation, borrowed pricing-pointer handling,
checked arithmetic and default behavior. Its read-only test uncertainty is
resolved by the runs above. The new generated-cell `-7201` fallback is **not**
claimed as an exercised classification; no triggering case was demonstrated.
The generic test-only `replay_workchain_payout_overlay` still has no exact-q
parameter and no production caller; production validation uses registered
engine execution plus settlement, not that helper.

Prepare contract remains **0/9**, unknown-source counter **absent/unmeasured**.
Reserve policy, configuration admission and other error classification gaps
remain open. No guard was retired and no complete M5 wiring acceptance is claimed.
