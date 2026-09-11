# BUCKET-SWEEP: mandatory real-host D62/D63 handoff

Requested after B `f75612eaf`. Normative basis: D62/D63/D69/D70/D71,
coordinator-supplied memo `86e775a9`, SHA256 prefix `1f756b55faf2820c`.
The live memo file has advanced; this contract does not silently substitute its
moving contents for that reference. No new protocol decision is made here.

This replaces no frozen prediction. The synthetic scope limitation in
`uno-m5-accounting-criteria.md` now has an executable successor obligation:
`python3 crypto/test/workchain-bucket-sweep-handoff.py --build <build>`.
Missing, disabled, duplicate, skipped or unobserved host tests exit 1 and name
the obligation. All eight are mandatory. Registration/markers alone do not
prove authentic observation: independently review the adapters before acceptance.

## Common fixture, execution and observation boundary

Use authenticated coordinator bucket state, actual Native inbound/outbound
messages, registered account/control/pending state, explicit authenticated fee
and capacity configuration, and authorized sweep events. Execute production
bucket dispatch and Native publication, then validator replay. Do not assign
lineage IDs in a synthetic trace: derive association from authenticated message
and bucket artifacts. Test repeated events across committed batches.

Observe committed coordinator and custody account BOCs/balances, complete bucket
contents and protected holdings, account lifecycle/control, both pending maps
and counts, sequence, actual emitted messages/fees and independently decrypted
receipt values. Inspect the final batch cut, never a mix of old and new roots.
Individual predicates on manually supplied observations are not these tests.

Each suffix below names `test-workchain-bucket-sweep-<suffix>`. Each real test
prints `BUCKET-SWEEP_OBSERVED:` followed by its full CTest name only after its
positive execution, named negative controls and restoration complete.

| Suffix | Fixture / execution | Mandatory observation and exact red |
| --- | --- | --- |
| `return-once` | Ordinary return of one entry, authenticated return failure, then a second sweep touching its successor | At most one ordinary return over that lineage; successor retains return_failed. Mutate flag propagation or permit a second send: `BUCKET_RETURN_ONCE` fails on actual second message, not an unrelated admission error. Observe actual fees and K_sweep consumption; unrelated entries must not supply a fresh retry identity. |
| `terminal` | Touch return_failed entries of both kinds; attempt both ordinary return and type-2 Deposit admission, then separately authorized governance cleanup | Neither ordinary branch runs or signs a receipt; terminal flag survives until authorized cleanup. Clear/bypass flag: `BUCKET_TERMINAL_NO_RETRY` fails on published send/credit. Unauthorized governance cleanup must fail at authorization (`BUCKET_GOVERNANCE_AUTH`) with no publication; authorized cleanup and alert must be observed. |
| `close` | Valid close-ready owner with one attributed bucket entry (including return_failed); otherwise identical owner without it | Attributed entry blocks voluntary close. Remove only bucket-ownership close predicate: `BUCKET_CLOSE_OBLIGATION` fails when lifecycle closes. Owner proof must be valid first; corrupt-proof control independently proves the proof checker rejects. No assertion that closure prevents future late returns. |
| `transfer` | Eligible type-2 entry value y, enough slot/fees, actual same-shard coordinator-to-custody move | Installed credit and actual custody increment both equal y-s-g. Delete physical transfer but retain book/receipt credit: `BUCKET_CUSTODY_TRANSFER` fails on actual custody balance/message, not just conservation. Also perturb book or receipt credit independently at `BUCKET_CREDIT_COMPONENT`. |
| `fee-routing` | Same successful sweep; vary authenticated base and issuance units separately, and slot fee separately | Slot s stays at coordinator, g=base*units enters actual fees_collected. Redirect g to operator or hold g constant: `BUCKET_COMPUTE_DESTINATION` / `BUCKET_COMPUTE_AMOUNT` fails. No defaults for un-frozen units. Observe sufficient and no-issuance threshold y<=s+g: no receipt, no sequence increment, no issuance compute fee; the specified residue disposition is independently observed. |
| `sequence` | Two distinct bucket entries with identical fixed attribution fields swept consecutively, also mixed with another system origin in one batch | Real receipts have different IDs and ciphertexts using the shared staged checked sequence; keep both duplicate-ID checks. Mutate reuse of the old counter or consume on a failed/non-issuance path: `BUCKET_SEQUENCE_STAGED` / `BUCKET_SEQUENCE_NO_ISSUE` fails on committed counts/receipts. This complements, does not retire, the six-item sequence handoff. |
| `atomicity` | Successful transfer plus injected failure between proposed debit/credit/holdings/fee updates | Success observes all components below at one committed cut. Failure publishes none, including fees/sequence/account/bucket changes. Mutate early publication while retaining error return: `BUCKET_ATOMIC_PUBLICATION` fails on committed artifacts; correct error code alone is insufficient. |
| `oracle-control` | For every preceding isolated mutation, run with its oracle enabled, disabled, restored | Enabled must produce that named red; disable only that oracle with mutation retained: driver fails `BUCKET_ORACLE_MISSING:<name>` when its expected red disappears. Earlier errors cannot satisfy the driver. All "X passes before Y" premises need independent corrupt-X rejection controls. |

For isolated successful type-2 issuance let U be bucket holdings, Q refundable
registration deposits, C coordinator Native balance, R custody balance, s slot
fee, g compute fee and t=y-s-g>0. All arithmetic is checked. Independently read:

- R_actual and R_book increase t; N_book increases t (receipt decrypted separately).
- U decreases y; Q unchanged; C decreases y-s; actual fees_collected increases g.
- D/P/W unchanged; D60 slack C-Q-U increases **s**, not s+g.

No operating subsidy is permitted; normal slot income is not an illicit change.
Checking C unchanged would be a false oracle. Conservation is an additional
cross-check, not a substitute for independent source/destination assertions.
Schema/codec round trips alone cannot prove lineage, closure dispatch, governance
authorization or physical publication. No guard retires merely because it reds.

## Current status

NOT READY: no real host execution is claimed by this delivery. The runner is an
acceptance readiness gate, not a placeholder green default CTest. Future named
host tests belong in the default suite. The original synthetic tests remain useful
unit evidence, but cannot discharge any of these real-host obligations.

Delivery checks: runner protocol selftests 11/11; real B CTest inventory exits 1
with eight missing names. Isolated removal of D62 `return-once` and D63 `transfer`
each makes the independent mandatory-membership control fail. Logs are in
`measurements/uno-m5-bucket-sweep-handoff/`. No real sweep was run.
