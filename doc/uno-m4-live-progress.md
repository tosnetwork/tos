# M4 live sequence: partial acceptance

The nine-step successful sequence passed on 2026-09-11 using the real local
collator and validator actors under test-constructed authenticated parameters.
This is not closure of the full M4 acceptance checklist. The rejection and
protected-budget follow-up below records the newly connected paths separately
from the original nine-step observation.

Commands:

```
cargo build --manifest-path uno/prover/Cargo.toml --example m3-scenario --release --locked --offline --target-dir build-m3-host/m3-vector-wallet-target
cmake --build build-m3-host --target test-m3-live -j3
python3 test/uno-m3-live.py --build build-m3-host --m4
```

The last command exited 0. Authenticated static base=2, slot_fee=3000000,
send_tip=5, collect_tip=7; each Deposit principal was 1000000000. These are
explicit test parameters, not an assertion of production readiness or dynamic
D28 pricing. Billing units are SEND=1 and COLLECT=3, independently of proof work.

| Step | Observed available | Paired engine proof units |
| --- | --- | --- |
| Register A | A=0 | 433 / 433 |
| Register B | B=0 | 433 / 433 |
| Deposit #1 to A | A=0, one system receipt | 7 / 7 |
| Deposit #2 to A | A=0, two system receipts | 7 / 7 |
| A COLLECT #1 | A=999999987 | 2639 / 2639 |
| A COLLECT #2 | A=1999999974 | 2639 / 2639 |
| A SEND to B | A=0, principal=1996999967 | 2649 / 2649 |
| B COLLECT | B=1996999954 | 2639 / 2639 |
| Close A | A=0, closed; B unchanged | 441 / 441 |

Every step was paired with the same-path disabled run: identified phase=3,
zero execution, zero transactions, no candidate export. All nine enabled
blocks were accepted. The assertion helper reads serialized block inputs;
the retained system receipt is compared by its complete record hash and is
subsequently consumed by COLLECT #2. Test wallet expectations are never node
replay inputs.

Final block:
`(2,8000000000000000,9):014B01B4BE77C815A7BF1A29C010E76809F1213135BE2C60EF9A4ECAD264EBDA:92050F68C75D54BA235986A88F1EE6789AC8453CF33E3B2F22312059D779A9BC`.
Its collation took 20.741 ms and validation 9.407 ms; these are single samples,
not throughput measurements. Actual masterchain imports contain 13 for each
COLLECT and 7 for SEND. SEND moves S=3000000 to the coordinator; its F=3000007.
Final custody and liability totals both equal 1996999954.

A read-only inspection of the accepted final state reports registered_accounts=2,
A system/user slots=0/0, B system/user slots=0/0, and coordinator Native
balance=11008999900. D/P/W are zero by the implemented atomic operation set;
they are not three separately stored counters being read from the state.
Reading each actual Block.value_flow gives fees_collected of
21567, 21567, 4341, 4341, 13, 13, 7, 13, 33: total 51895 across the nine wc=2
blocks, excluding source wc=0 and masterchain blocks. These include Native
components and must not be inferred from the D32 tariff alone.

The block-loop checks include nonzero R mismatch, nonzero cross-block D, and
an unpaired confidential fee debit, followed by restored successful checks.
Test keys decrypt available and pending, directly measuring N_hidden for this
sequence. Production has no such aggregate decryption capability:
N_book=N_hidden is conditional on cryptographic and state-machine correctness,
not independently publicly numerically auditable. These observations establish
only this finite sequence in this implementation.

The earlier failure after integrating system receipts was a test search bound:
a receipt's pre-fee amount exceeded the post-fee available used as the bound.
Increasing that finite test-wallet bound does not relax the balance equality
or any node validation rule. Neither earlier failed run counts as acceptance.

The effective minimum Native message value is V_min+slot_fee, not V_min.
Exact equality means an in-flight fee change causes rejection and bounce,
with repeated bounce cost an operational tradeoff. M3's 100:1 fixture cannot
admit a Deposit because its V_max is below V_min; this M4 fixture uses the
specification's 1:1 balance/value bound.

Retirement condition for M3 test funding: remove that test operation and its
allowlisted call sites only after the complete M4 checklist passes, the M3
regression scenario runs using real Deposit instead, and the funding removal
is itself tested with default-off guards unchanged. This successful sequence
alone does not satisfy that condition.

No claim is made of consensus security, cryptographic correctness, production
usability, capacity or hardware sufficiency, multi-node execution, M5 support,
or audited supply-chain dependencies. Closure materializes a one-way historical
deposit refund message; delivery is not guaranteed and recipient credit is not
asserted. D45 remains in effect; production activation is unchanged.

## Specification synchronization (rejection work in progress)

The rejection path now targets specification SHA-256 prefix
`f436123d9476e00e`, memo commit `f491cad9`. Earlier frozen predictions retain
their original specification identity; this note does not rewrite them.

Section 11.3 requires sender-only attribution for the M4 bucket, never the
original message body or a confidential account ID. An unparseable body cannot
authorize type-2 attribution. Bucket value belongs to the coordinator's
dedicated, non-spendable bucket, not custody or unlocked operating funds.
Rejection assertions read custody before and after: R_actual is unchanged
because these incoming Deposits address the coordinator and never enter
custody, not because bucket bookkeeping can exclude coins from custody's
Native balance. Direct-to-custody handling is outside this tested path; its
physical destination is now specified, but is not claimed implemented here.

This synchronization is not additional live acceptance evidence. In
particular, the dedicated bucket's exclusion from other operating expenditure
must be checked before claiming that its non-spendability is enforced.

### Enforcement boundary clarification (applies to M3 and M4 reports)

Per-batch Native value-flow conservation is enforced by the node (I13).
Cumulative ledger reconstruction currently runs only in the test assertion
helper; the node has no genesis-rebuilt ledger context. Thus references in M3
and M4 reports to successful Section 3.2 per-block assertions mean test-side
cross-checks, not a demonstrated node rejection by that cumulative check.
This absence alone does not demonstrate a candidate bypass of the existing
per-batch checks; any such bypass would require its own construction.

The current budget work targets node enforcement of Native balance covering
both independently recorded protected holdings, plus classification fixed by
the authenticated event. It does not introduce a historical budget context.
Classification catches funds never marked protected; backing catches spending
that leaves protected claims underfunded. Neither substitutes for the other.
The earlier statement "bucket non-diversion is not yet claimed fully enforced"
described the pre-fix state, not an assumed guarantee supplied by the schema.

### Rejection and protected-budget follow-up

The registered test engine now binds each locally executed result to its old
coordinator snapshot. Shared node settlement checks old-state backing, new
backing and event-derived protected credits/debits before publishing its result.
Registration value is refundable; non-bounced rejected value is bucket value;
Deposit slot fees and D32 S do not increase either protected category. Both
actors independently reconstruct these events. No spendable field, historical
ledger context, deployment switch or new schema was introduced.

`build-m3-host/test-workchain-block` passed 133 tests. Before the fix, the new
closure control exited 1 at `protected_failure.is_error()`: the old code really
accepted a fee invading the unexpected bucket. After the fix the same path
returns -7200, `refund fees invade unexpected bucket holdings`, publishes no
message and leaves the account unchanged. Increasing operating funds restores
success. The fixture has Native balance 1000, refundable claims 300, unexpected
holdings 650, historical refund 100 and forwarding fee 100; only 50 was free.

The production predicates also reject missing bucket credits (-7200), bucket
credits mislabeled as operating income (-7200, despite sufficient total
backing), and balances below protected claims. Removing the backing predicate
in an isolated copy makes the `below.is_error()` control fail; removing the
classification predicate makes `missing.is_error()` fail. Unmodified controls
exit 0. These are predicate-level controls, not claims of four separately
submitted malformed live candidates.

Commands, both exit 0 after node integration:

```
python3 test/uno-m3-live.py --build build-m3-host --m4 --m4-rejections
python3 test/uno-m3-live.py --build build-m3-host --m4
```

Three rejection ON/OFF pairs cover below-minimum principal, an overpaid slot
fee, and protocol-non-bounceable input. Actual wc0 receiving transactions match
the exact outbound hashes and contain Native credit phases of 1002999899 and
1002999901, respectively. This is receipt evidence, not just export evidence.
The third case records 1002999999 in the sender-only bucket, with no outbound.
Final coordinator balance 22008999999 covers refundable claims 20000000000
and bucket holdings 1002999999. Custody remains 2000000000 throughout rejection
because the rejected value entered the coordinator, not custody. All three
rejections consume 0/0 proof units: admission rejects before cryptographic work.
The independent nine-step rerun still ends A=0, B=1996999954, with the same
nine paired proof counts. Every disabled run identifies the registry refusal,
zero executions/transactions and no candidate export.

Consensus-file change, reported separately: `transaction.cpp` changes only
`prepare_workchain_entry_impl` (exact independently rejected input selection)
and `prepare_workchain_refund_message` (both protected amounts checked before
publication). The former is reached through `prepare_workchain_entry` and
`prepare_workchain_disposal_entry`; their callers are allocation-overlay entry
construction, `prepare_workchain_import_participant` and
`prepare_workchain_payout_pair`. Refund construction is called only by the
allocation overlay's closure continuation and requires wc=2. The disposal
context is a workchain-method parameter/local object, not ordinary Account or
Transaction state. These generic helpers are workchain-specific, not all
hardcoded wc=2; ordinary wc0 execution does not call them. No ordinary Native
phase behavior was changed. No before/after byte-comparison result is claimed.

At this follow-up checkpoint seven of eight targeted guards pass. The closure
inventory correctly reports changed source identities and awaits its owner's
baseline update; no scanner criterion has been relaxed. No full M4 completion
or universal coverage of other engines' budget expenditure is claimed.
