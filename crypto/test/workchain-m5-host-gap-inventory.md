# M5 host pre-implementation gap inventory

Date: 2026-09-11. Source baseline: `e64a2d153` on `agent/uno-m5-host`.
Specification: memo commit `99959a9d`, SHA-256
`dd979cd244831d3f0bd150a4ba83edc190954c2bf3bafc45f77ef63cb318c6a2`.
Section and decision names below refer to that revision, not old line numbers.

Status: **implementation stopped for a Withdrawal statement decision**. No
production code, relation, ABI, state schema, refusal or D59 default is changed
by this inventory. An absent implementation is distinguished from an undefined
construction, and a source inspection from a live measurement.

## 1. Cryptographic boundary: ordinary SEND/COLLECT is insufficient

The required public debit is principal `x`, the D61 outward forwarding charge,
the D35 return reserve, and any separately authorized operation fee. These
amounts must remain distinguishable even if checked addition produces one
debit. The proof must link that debit to the authenticated old balance and the
submitted new ciphertext, with a nonnegative bounded remaining balance.

`uno/crypto/src/relation.rs:29` admits only SEND (10 points, eight equations,
six shared witnesses) and nonempty COLLECT. Unknown kinds and COLLECT with zero
receipts are rejected. `crypto/block/workchain-confidential-input.h:46` has only
SEND/COLLECT transfer variants; registration and closure are separate replay
variants. There is no Withdrawal statement constructor.

| Required binding | Present SEND/COLLECT mechanism | Withdrawal gap |
|---|---|---|
| Engine/relation/wire/proof versions, network, genesis, workchain instance | Transfer protocol and kernel protocol domain | Need an explicitly identified Withdrawal operation; do not label it an ordinary SEND |
| Asset, custody, policy, profiles, fee-table cut | Transfer rules/profiles and 427-byte canonical context | Reuse authenticated sources, but define the new semantic record and its commitment |
| Source address/incarnation, P, epoch, lifecycle | Host loads source, compares claims, builds old statement | Reusable checks, not yet a Withdrawal admission path |
| Old available, nonce/revision; new available | SEND points P_A, C_A, D_A, C'_A, D'_A; shared equations and range commitments | These components already prove authorized bounded balance change |
| Public principal x | SEND has secret witness v and public C_t/D_tA/D_tB; no public scalar x | No existing equation or authenticated opening identifies v with payout x |
| Native destination | SEND requires registered confidential P_B, address/epoch, lifecycle and a pending slot | A Native recipient is not that participant; no Native destination field in SEND data |
| Withdrawal/Attempt identity and returned-account attribution | Transfer operationID derives kind 1/2 and nonce; semantic hash covers those typed data | No Withdrawal/Attempt codec or preimage; do not reuse DepositID or a proof hash |
| Outward fee, refundable return reserve, expiry/lock policy | One authorized_fee scalar, checked against SEND/COLLECT tariff | No separate reserve/outward-fee fields; reinterpreting f would bypass its current meaning |
| Settlement effect | SEND installs recipient pending; COLLECT consumes authenticated receipts | Neither creates a W record or authorizes a custody export |

The kernel equations in `relation.rs:90-104` constrain
`a = a' + v + f` and `C_t = vG + rH`, with the corresponding handles. Adding
an arbitrary public x to Fiat-Shamir context would bind the prover to that
string, **not add the equation v=x**. A prover can honestly prove the existing
relation with another v while including x in a context. Likewise, the
COLLECT relation adds positive authenticated receipts; using zero or invented
receipts for Withdrawal is not reuse of its current admitted relation.

### Decision needed, not an assertion that a new relation is unavoidable

There is a mathematical candidate for retaining the eight SEND equations:
fix its transfer commitment and both handles to an independently reconstructed
encryption of public x with known nonzero randomness. The shared handle
equations then constrain the same r, and the commitment equation constrains v
to x (subject to the existing cryptographic assumptions and integer bounds).
This is **not implemented or authorized as a Withdrawal construction**:

- The auxiliary recipient P_B and its meaning must be specified; it must not
  require a fictitious confidential Native recipient or create a fake pending.
- The public randomness derivation, its domain/identity, and its zero rule need
  a defined construction. D33 currently specifies Deposit system encryption,
  not a Withdrawal opening. It must not simply be relabeled by this host.
- The Withdrawal context must include x, Native destination, return identity,
  both fee amounts and lock policy before challenge derivation. Ordinary SEND
  context/data do not contain these fields.
- Reserve plus outward charge must not silently become D32 operating fees.
  The kernel's scalar f and the host's tariff/effects contract are different
  responsibilities; any specialization must define their mapping explicitly.
- Public transfer randomness must never replace the fresh private randomness
  of the new available ciphertext (section 8).

Thus **current entry points cannot cover Withdrawal unchanged**. This inventory
does not prove that a third algebraic relation is necessary. Approval of a
fully specified SEND specialization could avoid new equations; a dedicated
Withdrawal relation would expand the D34 cryptographic scope. Both require a
decision before implementation. No third relation or independent proof entry
has been added, and no zero-new-cryptographic-surface claim is made.

Anchors: specification sections 6.1, 6.2, 7.1, 7.3, 8, 11.2, D24/D35/D61;
`workchain-confidential-execution.h:72-140` (authenticated checks/point order),
`workchain-confidential-input.h:143-157,440-476` (kind/identity/context),
`relation.rs:90-146` (equations and challenge absorption).

## 2. Outward fee: pricing primitive exists, admission object does not

`Transaction::price_workchain_payout` (`transaction.cpp:4536`) already prices a
complete relaxed Native message through the existing Native message staging
path. It requires rich flags 3, bounce enabled, IHR disabled, zero caller fwd_fee,
a standard destination, sufficient principal and a supplied fee allowance.
It returns the actual message, value, total forwarding fee, collected fee and
end LT. This is not a Withdrawal authorizer.

For a completely fixed request and authenticated action configuration, Native
pricing is deterministic. `try_action_send_msg` measures StateInit, body and
applicable extra-currency references before `compute_fwd_ihr_fees`
(`transaction.cpp:3514-3557`). `created_lt` is a fixed-width field assigned from
the schedule (`:3443`); its later value is not itself a variable body length.
This does **not** prove that an M5 request is already fixed at admission.

Missing integration inputs are the exact canonical payout body/StateInit
policy, Native destination and currency restrictions, the bound authenticated
pricing configuration, and a deterministic participant schedule. The present
helper also takes a caller fee_budget: D61 cannot be implemented by assuming
this is the return reserve or a coordinator subsidy. Its allowance must be
derived or bounded without inventing a local fee default, and the admitted
price must be checked against the final serialized payout independently.

The existing `NativePayoutPricing` test was also executed in the 133-test run
below. Its workchain-2 source / workchain-0 destination, referenced 256-bit body
case produces total_fee=460 and collected_fee=230 with lump=200, bit_price=65536,
cell_price=262144, first_frac=32768. Its other case verifies created_lt=21 for
start_lt=20, fee-config changes and excess virtual allowance. This is a measured
Native pricing primitive, not a measured Withdrawal admission pipeline.

Conclusion: **conditionally computable, not yet computed by a Withdrawal
admission path**. No demonstrated size/fee circularity was found, but no
admission-to-final-payout byte/price equality measurement has been performed.
Required future controls include changed body/flags/destination/fee-table cut,
encoding boundary sizes, and no charge of an outward shortfall to coordinator.

## 3. Rich bounce: measured local capability, routing remains unverified

Rebuilt and ran the existing Native test executable on the inspected tree:

```sh
cmake --build /tmp/uno-merge-6ea2fbf80-tL5Uih --target test-workchain-block -j 4
/tmp/uno-merge-6ea2fbf80-tL5Uih/test-workchain-block
```

Result: exit 0, **133 tests passed**. Logs:
`/tmp/uno-m5-gap-native-build.log` and `/tmp/uno-m5-gap-native-tests.log`.
These are existing tests, not new M5 acceptance tests.

`NativeBounceBody` (`test-workchain-block.cpp:2384`) exercises flags 0/1/2/3,
the pure encoder, and the ordinary transaction bounce caller. It checks the
rich tag 0xfffffffe, full original-body hash/ref retention, original value,
created_lt=77 and created_at=99. Its ordinary caller uses global_version=16,
an input from -1 to workchain 2, and zero forwarding prices. This **is not**
the requested wc=2 -> wc=0 routing experiment. `NativeBounceStorageCaller`
also exercises priced/nofunds cases, without establishing that route.

Source evidence: input flags select the format in `transaction.cpp:1088-1089`;
`prepare_bounce_phase:4055` preserves original metadata through the extracted
encoder. `Collator::enqueue_transit_message:4207` reuses the Message cell in a
new envelope, and validator checks imported message identity (`:4192`). These
support a routing hypothesis, **not a measured intermediate-shard result**.

**Open acceptance gap:** no fresh wc=2 -> wc=0 rich-bounce run, and no split-wc0
intermediate-shard run, was performed in this stopped investigation. Those must
observe actual exported/imported Message hashes, flags, full original_body and
original_info.created_lt, with legacy/insufficient-funds controls. Do not count
the 133 local tests as satisfying this item. global_version<12 must reject the
payout profile rather than reinterpret flags as legacy IHR fees.

## 4. Authenticated W/Attempt storage is absent

`WorkchainConfidentialAccount` (`workchain-confidential-state.h:57-81`) has
available, nonce/revision, pending and lifecycle, with an explicit comment that
settlement refs require a future tag migration. `WorkchainCoordinatorState`
(`workchain-coordinator-state.h:10-30`) has system fields, refundable registration
deposits, Deposit sequence and the unexpected bucket root. `block.tlb:1-54`
contains their current layouts. None provides an authenticated open Withdrawal
record for principal, return reserve, payout created_lt, phase or queue-removal
height. A payout request in effects (`block.tlb:143`) is not such a record.

Required design/interface, **not a selected encoding**: bounded open records
must link account/instance and Withdrawal/Attempt identity to x, return reserve,
actual assigned payout created_lt, outstanding state and settlement timing.
The schedule-to-record installation must be atomic and independently replayed.
The authenticated old queue needs an observed-enqueue prerequisite; absence
alone is not proof that the recorded payout left the queue. Process the complete
authenticated inbox before closing remaining expired records.

On terminal Paid/Failed, remove the open record: no permanent per-payout table.
Late bounce uses its returned body, never a terminal history lookup. These
mutually exclusive terminals need a state machine, not an 'un-Paid' proof.
Missing state acquisition is LocalUnavailable; a candidate's invented matching
record, double termination or invalid state transition is CandidateInvalid.

## 5. D61 amounts are not separated in current persisted state

`account_workchain_payout` (`workchain-payout-accounting.h:35-48`) currently
subtracts payment from custody and total forwarding fees from operator funds,
then creates `WorkchainInternalTransfer{coordinator, custody, total_fee}`.
This is precisely the **superseded** D61 funding direction. Its successful
`PayoutPrincipalAndFees` test validates the old helper, not D61 compliance.
No code was changed to make that test green for the new rule.

The outgoing charge is spent; return reserve remains refundable and is part of
W while physically retained at custody. Current account/coordinator layouts
store neither as Withdrawal fields. They cannot be recovered by interpreting
a single total fee or by reusing refundable registration deposits. The future
record/effects interface must keep actual outward fee, original reserve,
consumed return costs and refundable remainder distinguishable, with checked
arithmetic. Exact field placement is for the encoding/host contract decision.
`max_bounce_cost` and `payout_settlement_blocks` remain conditional freezes:
no local numeric defaults are authorized by this inventory.

## 6. Adjacent known blockers, not implemented here

- D62: the M4 bucket (`workchain-unexpected-bucket.h:9-33`) represents only
  sender attribution, no account_id, return_failed or return-attempt state.
  M5 needs the approved type/one-attempt semantics and authenticated matching;
  the present overflow aggregation also needs explicit compatibility with
  per-entry return failure. Do not infer that adding a Bool implements a retry
  limit. The account-attributed bucket closure condition is not present today.
- D63: type-II sweep must move net value coordinator -> custody in the same
  batch; slot fee stays outside custody. Existing transfer machinery is not
  evidence that the four atomic sweep effects have been connected.
- M3 test-funding retirement remains incomplete. `e64a2d153` migrated the live
  runner and passed eleven ON/OFF pairs; the pure scenario/epoch path still
  calls the old helper. No funding operation or whitelist was deleted.
- Existing no-obligation/epoch/loading/bucket/D60 guards must not be relaxed to
  admit an unfinished M5 operation. The current operation-set premise will
  expire when actual Withdrawal obligations become representable.

## Handoff and limits

First decision: define the Withdrawal cryptographic statement (including the
public-amount link) and decide whether it is an approved specialization of an
existing relation or a new D34-scoped relation. Until then no Withdrawal host
call, new ABI call, payout fee-direction change or state migration is connected.
Items 2-6 are an inspected backlog, not claims of completed M5 functionality.

No claim of cryptographic correctness, consensus safety, production readiness,
multi-node/cross-shard M5 acceptance, delivery guarantees, capacity/hardware
adequacy, full regression success, supply-chain audit or completed test-funding
retirement is made. Cumulative section 3.2 history reconstruction remains
test-side; node batch conservation is not a cumulative authenticated ledger.
