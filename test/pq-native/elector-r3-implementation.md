# R3: explicit relay debt and bounded operating funds

This implementation follows sections 15–16 of the design decision at memo
commit `9153173c`, plus the operator's explicit authorization on 2026-10-02 for
the minimal bounce-and-retry extension. It supersedes the R3 candidate described
in `elector-review-followup.md`. Earlier result indexes remain historical.

## Ownership and authorization

Controller READY stores an explicit debt `D`, credited only by the pinned
elector's matching result or the matching native stake bounce. An unsuccessful
nonbounce message may physically credit this account without changing storage;
that balance is never a business receipt or an operating deposit. Payment is
exactly `D + K`, where `K` is a separately identified current callback budget.
The mandatory payment action and READY-to-PAID transition are atomic. PAID
retries contain only a new caller's `K` and the historical receipt, never `D`.

Each transaction reserves its unrelated assets using its current balance and
inbound value, not a balance snapshot saved by an earlier transaction. For a
READY payment, the floor is `balance - inbound - D`. Both pool types reserve
`balance - K` before callback processing. The multi pool charges any actual
refusal/bounce shortfall to the validator's recorded capital, rather than
nominators. The single pool has one principal owner and no separate nominator
ledger; a real transport loss reduces that owner's returned cash.

Root-signed controller action kind `4` explicitly deposits operating money and
sets an independent remaining allowance, per-request cap, storage floor and
expiry. The payload binds the actual sending wallet. Network, controller,
epoch, nonce, signature and root authorization expiry retain their existing
checks. The initial operating funds and allowance are both zero. Depositing
without permission, granting permission without funds, ordinary transfers,
unclassified credits and pool principal cannot sponsor a request.

Before accepting a new relay, the controller checks all of the following:

- the consensus signature is valid, names the pool, and has not expired;
- the new query is exactly the next one and no earlier request is pending;
- the current-price automatic grant fits the remaining funds, allowance and cap;
- sponsorship has not expired and physical pre-message assets cover the
  operating ledger plus the explicitly configured storage floor.

The entire finite grant is debited from funds and allowance when the request is
accepted. Its unused cash is refunded to the recorded operating payer; it is not
silently credited back as permission. Changing permission to zero prevents new
grants without erasing an existing grant or creditor. Rewards never replenish
funds automatically. Root sends reserve operating funds and the storage floor
and remain prohibited while a relay debt is pending. Root action kind `5`
withdraws an explicit amount of unreserved operating funds to its bound sending
wallet after cleanup. It decreases the operating ledger, preserves the storage
floor, and cannot withdraw unclassified assets as operating funds. The ledger
therefore does not turn voluntary deposits into a permanent lock.

## Fee ownership across asynchronous messages

Pool inlet change returns to the actual operator wallet in that transaction.
Controller forwarding change follows that same payer. A public retry's change
belongs to its actual caller, including callback and ACK change. It never
becomes pool principal or a reward. The automatic attempt uses the explicitly
recorded sponsor. Its authenticated self-message also carries the sponsor so
that a late wakeup can refund its own fees after cleanup or a later query.
Delayed pool ACKs, elector delivery ACKs and return retries likewise refund
their own inbound fee value without modifying a later obligation.

The retained grant is an explicit operating reservation, not unused inlet fees.
There is one optional automatic wakeup per recorded result. Suppressing its
action cannot erase READY. Every subsequent recovery attempt requires its own
caller funding; there is no free resend loop.

## Failure before the controller can record a result

Elector success/refusal transfers are now bounceable. Elector retains one
return record per admitted immutable controller: query, full commitment,
IN_FLIGHT / RETURNED / ACKNOWLEDGED, outstanding business amount, result and any
returned retry-fee credit with its payer. The native bounced prefix binds the
opcode, query and 160 commitment bits, and its source must be that controller.

IN_FLIGHT is never authority to pay twice. Only an actually received native
bounce can change it to RETURNED. The recorded amount becomes the smaller of
the previously outstanding amount and actual returned cash. Any remaining
retry-fee cash retains the previous payer. A new paid retry uses the same query
and commitment, pays only the returned amount plus the new delivery budget,
and refunds the previous payer's returned fee credit. Controller acknowledgment
retains a replay tombstone. A higher query from that immutable controller can
also retire the previous IN_FLIGHT record: the controller cannot issue it
until its previous pool obligation is completed. RETURNED cannot be overwritten.

The book grows with distinct historical controllers, not rounds or retry
count; it is not globally constant, TTL-pruned or automatically deleted.
Unadmitted requests cannot allocate return history. Outstanding returns block
elector cutover. A nonempty history requires the target's read-only capability
method `1668` to return `0x52525633`, in addition to the existing recovery
capability. Code probes must preserve data and actions, and installation hooks
must preserve both histories. Compatible same-code installation is tested by
its actual success reply, not merely unchanged code bytes.

## Wire and deployment compatibility

The shared high-bit query, single controller slot and original route remain.
There is no second query counter, per-round record list, reward topup or bond.
The matching contract set changes these payloads:

| Message | Added or changed fields |
| --- | --- |
| Pool relay `0x50517232` | payer reference included in the 160-bit commitment |
| Elector result `0x50516f32` / `0x50516532` | 160-bit bounce commitment after query; delivery budget and payer reference after full hash |
| Controller result `0x50516232` | historical actual business return `D`, current callback budget `K`, payer reference |
| Pool ACK `0x50516132` | payer reference |
| Return retry `0x50517433` | same query, full hash, caller address |
| Delivery ACK `0x50516133` | same query, full hash, payer reference |
| Fee change `0x50517833` | query |

The controller is immutable: the repair creates a different code hash and
birth address. Deployment requires fresh matching controllers and pools and
explicit code admission. Keep their original birth StateInit for witnesses;
data read after funding or key changes is not birth data. The frozen multi-pool
BOC, Rust embedded code, address vector, node recognition table and native
recognition test are regenerated together, as are both single-pool copies.
No live account is upgraded, no funds are migrated and no network is activated
by this branch change.

## Operator procedure

Use an operator-owned wallet. Explicitly choose all monetary values in
nano-TOS and both expiry times; this implementation supplies no default deposit,
allowance, cap or storage floor. First encode the payload:

```sh
cargo run --manifest-path tosctl/src/Cargo.toml -p contracts --locked \
  --example controller_operating_payload -- \
  "$PAYER" "$DEPOSIT" "$ALLOWANCE" "$PER_REQUEST_LIMIT" "$STORAGE_FLOOR" "$SPONSORSHIP_EXPIRES"
```

In the offline root domain, sign the returned payload BOC:

```sh
tos-pq-controller fund-operations "$ROOT_SEED_FILE" "$GLOBAL_ID" \
  "$CONTROLLER_HEX" "$EPOCH" "$NONCE" "$AUTHORIZATION_VALID_UNTIL" "$PAYLOAD_BOC_B64"
```

Send that body from the bound wallet with the explicit deposit plus sufficient
current transaction fees. Root authorization TTL remains at most 3,600 seconds.
Read `controller_state` for epoch/nonce and `operating_state` for
`(funds, allowance, cap, floor, sponsorship_expiry, payer)` before staking.
An empty transfer does not perform this step. Existing live rehearsal scripts
also need this explicit setup before their first pool order; they must not infer
authorization from the deployment balance. A zero-deposit, zero-allowance signed
action disables new sponsorship while preserving existing obligations.

To withdraw unused operating funds after cleanup, encode `withdraw "$PAYER"
"$AMOUNT"` with the same payload example and sign the resulting BOC with
`tos-pq-controller withdraw-operations` using the same explicit authorization
fields. The bound wallet submits it with current transaction fees. It cannot
withdraw a pending grant or pool debt, and a replay cannot withdraw twice.

Public recovery remains controller opcode `0x50516632` plus the original uint64
query, funded by its caller. In WAIT it asks the pinned elector to repair a
RETURNED transfer. In READY it pays the recorded debt. In PAID it repairs the
pool's bookkeeping/ACK using only new fees. Read the actual state and current
fee configuration; do not create a new query to repair an old debt.

## Validation and support boundary

`elector-r3-accounting-mutations.py` requires a passing baseline, successful
native compilation, the named failing assertion, and a passing restored source
for each defect. CI retains these logs for 30 days. `elector-r3-results.json`
binds the checked source hashes and the local validation result index. Reproduce:

```sh
cmake --build build --target func fift create-state gen_fif tos-pq-controller tos-pq-vote
export TOS_ROOT="$PWD"
cargo test --manifest-path tosctl/src/Cargo.toml -p contracts -p elections --locked --no-fail-fast
python3 test/pq-native/elector-r3-accounting-mutations.py --out r3-mutations
scripts/check-nominator-pool-code-lock.sh
scripts/check-single-nominator-code-lock.sh
```

The gas envelopes are 200,000 for controller verification, 50,000 per control
hop and 200,000 for the pool callback, with current-price forwarding allowances
for 4,096 bits / 8 cells. The automatic grant is four control allowances plus
one callback allowance; caller inlet fees are separate. The indexed native
trace measures the compiled source and its fixture fee configuration. Test
deposits and fee values are fixtures, not recommended production funding.

Recovery assumes active executable compatible accounts, a functioning native
bounce path, sufficient operating reserve/current caller fees, and delivered
messages. Real controller pre-accounting OOG, native bounce, actual returned
cash, mandatory action rollback, recipient abort, duplicate results and delayed
controls are exercised. Freezing/deletion, an unexecutable or unaffordable bounce,
arbitrary rent/fee growth and permanent message non-delivery are outside the
automatic recovery guarantee. These cases cannot be resolved by treating an
unknown balance as a debt. The native evidence establishes the bounded profile;
it does not promise unconditional recovery under every future chain configuration.
