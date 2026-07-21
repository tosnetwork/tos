# Service Actor Concurrent Escrow Upgrade

## Status

This document defines the pre-testnet upgrade of the existing Service Actor
contract. TOS has not entered public testnet, so this change replaces the
current implementation directly. It does not introduce versioned contract
variants, compatibility modes, legacy deployment flags, or parallel state
parsers. The Service Actor product and protocol version remain unchanged.

The contract bytecode, persistent-state layout, code hash, and deterministic
contract addresses will change. Existing local development deployments are
disposable and must be redeployed. No on-chain migration is provided.

## Objective

The current single pending-response slot serializes calls and requires global
policy and attestor freezes while a request is pending. The upgraded contract
must support concurrent paid requests without weakening payment custody,
attestation binding, policy commitments, or refund guarantees.

The design is governed by three invariants:

1. Every payment maps to exactly one request.
2. Every accepted request reaches a final disposition -- responded, refunded,
   or swept to the owner after an unclaimed refund's window lapses -- within a
   bounded time, never left pending indefinitely.
3. Funds backing unfinished, refundable, or not-yet-swept requests are never
   owner revenue.

## Request Identity

The contract maintains `next_request_id:uint64`. Each accepted call receives
the current value, after which the counter is incremented. Counter overflow is
rejected. Contract-assigned identifiers are deterministic and collision-free,
without caller nonces or caller-maintained replay state.

The request identifier is observable from the transaction result, contract
state, and indexer. Clients must not treat a predicted identifier as final
before the call succeeds.

Because the identifier is contract-assigned, a caller cannot know it before
`call` lands, unlike a caller-chosen nonce. `tosctl agent service call` must
surface the assigned `request_id` directly in its output (not only leave it
to a separate `get_request`/indexer lookup) so integrators can correlate a
submitted call with its lifecycle without an extra round trip.

## Service Policy

The active policy contains:

- `policy_version:uint32`
- `price_per_call:Coins`
- `storage_fee:Coins`
- `cleanup_bounty:Coins`
- `response_sla:uint32`
- `refund_claim_window:uint32`
- `metadata_hash:bits256`
- `proof_scheme_hash:bits256`
- `has_attestor:uint1`
- `current_attestor_pubkey:bits256` (meaningful only when `has_attestor = 1`)
- `active:Bool`

An attestor is optional. `has_attestor` is an explicit bit rather than an
implicit all-zero `attestor_pubkey`, matching the `has_attestor`/`attestor_pubkey`
pair already used by Task Escrow, Dispute, and the current Service Actor
implementation -- a `Maybe` constructor would be equally correct but would be
the only place in this contract family using that convention instead.

The owner declares one response SLA and one refund-claim window. A caller
either accepts the active policy or does not submit a call; callers cannot
choose either duration. The chain enforces minimum and maximum constants for
both. For each request:

```text
response_deadline = now() + response_sla
refund_claim_deadline = response_deadline + refund_claim_window
terms_hash = hash(policy_version || price_per_call || storage_fee ||
                  cleanup_bounty || response_sla || refund_claim_window ||
                  metadata_hash || proof_scheme_hash || has_attestor ||
                  current_attestor_pubkey)
```

The terms and attestor key are snapshotted when the request is accepted. Policy
and key changes affect only later requests and do not require a global freeze
while requests are pending. When `has_attestor = 0`, the canonical
`current_attestor_pubkey` value is zero; this prevents semantically equivalent
no-attestor policies from producing different `terms_hash` values.

The following protocol constants are not owner-configurable policy fields:

- `MINIMUM_OPERATING_RESERVE:Coins`, the balance that must remain after every
  value-moving operation
- `MINIMUM_STORAGE_FEE:Coins`, the minimum fixed fee for one live entry
- `MINIMUM_CLEANUP_BOUNTY:Coins`, a strictly positive lower bound for sweeper
  compensation
- `MAXIMUM_CLEANUP_BOUNTY:Coins`, an upper bound preventing abusive policies

They are network parameters shared by FunC, Rust builders, CLI validation, and
tests. Changing them requires the normal protocol configuration process; a
Service Actor owner cannot lower or bypass them.

## Persistent State

Pending requests are stored in a dictionary keyed by request identifier:

```text
pending_requests:(HashmapE 64 ^PendingRequest)

pending_request$_
  caller:MsgAddressInt
  price:Coins
  storage_fee:Coins
  cleanup_bounty:Coins
  response_deadline:uint64
  refund_claim_deadline:uint64
  policy_version:uint32
  commitments:^PendingCommitments
= PendingRequest;

pending_commitments$_
  request_hash:bits256
  terms_hash:bits256
  has_attestor:uint1
  attestor_pubkey:bits256
= PendingCommitments;
```

The split is intentional because a TVM cell is limited to 1023 bits. The root
request cell is approximately 427 fixed bits (`MsgAddressInt` + three `uint`
fields) plus three variable-length `Coins` fields (`price`, `storage_fee`, and
`cleanup_bounty`, each up to 124 bits), comfortably under the limit even at their maximum
encoded size. The commitment cell is 769 bits. Presence in `pending_requests`
is the pending status, so no status field is stored. Creation time is
available from chain history and is not duplicated in contract state.

Expired-but-unclaimed requests are stored in a second dictionary, also keyed
by request identifier:

```text
refunds:(HashmapE 64 ^Refund)

refund$_
  caller:MsgAddressInt
  price:Coins
  storage_fee:Coins
  cleanup_bounty:Coins
  refund_claim_deadline:uint64
= Refund;
```

`storage_fee` moves with the entry. It is a fixed, non-refundable service fee
collected at `call` time to fund storage, cleanup, and execution. It remains
locked while the entry is live and becomes owner revenue only when the entry
is deleted. It is carried into the `Refund` record by `expire`; only `price`,
not `storage_fee`, is refundable. Completed (`responded`/`refunded`/swept)
history belongs in the chain indexer rather than permanent contract storage;
this contract never stores a terminal-state record for a resolved request.

## Request Lifecycle

```text
Pending --respond--------------------------------> Responded
Pending --expire--> Refundable --claim_refund-----> Refunded
Pending/Refundable --refund_claim_deadline reached--> Swept
```

- `call` rejects an inactive service, invalid payment, invalid policy, capacity
  excess, or malformed body. It allocates an ID and stores the request snapshot.
- `respond` verifies that the request exists, `now() < response_deadline`, and has a
  valid request-bound attestation when an attestor is configured. It removes
  the pending entry and recognizes the request price as owner revenue.
- `expire` is permissionless when `response_deadline <= now() <
  refund_claim_deadline`. It removes the pending entry and creates a
  caller-owned refund credit. Both deadlines were fixed when `call` was
  accepted; calling `expire` later never extends either one.
- `claim_refund` is initiated by the caller while `now() <
  refund_claim_deadline` and sends `price` to a caller-chosen destination.
- `sweep_expired_request` is permissionless when `now() >=
  refund_claim_deadline`. It accepts a `request_id` found in either
  `pending_requests` or `refunds`, deletes that entry, and moves the unclaimed
  price and the locked storage fee, less `cleanup_bounty`, into
  `withdrawable_revenue`. Supporting both dictionaries prevents a missing or
  late `expire` call from blocking cleanup. This is the same
  finality-by-inaction pattern already used by Task Escrow's no-verifier
  `timeout()`: a bounded window to act is given, and unclaimed value defaults
  to the other party rather than staying stuck indefinitely.
- Repeated responses, expirations, refund claims, and sweeps are rejected
  because the corresponding live entry no longer exists.

### Why refund delivery is not "atomic," and what this contract does about it

A cross-account send and the destination's processing of it are two separate
transactions, possibly in different blocks; nothing in this contract's own
transaction can observe whether the destination's processing eventually
succeeds. Two distinct failure modes need different handling:

1. **Sender-side failure** (this contract cannot afford to send `amount` plus
   forward fees) is fully observable inside `claim_refund`'s own transaction.
   This is checked before any state is mutated, so it is genuinely atomic: on
   failure the refund entry is untouched and can be retried.
2. **Destination-side failure** (the destination throws, rejects the value, or
   never existed) is only ever signaled, if at all, by a later message
   carrying the protocol `bounced` flag. This flag is not a reliable
   authentication signal: any contract executing `send_raw_message` fully
   controls its own outgoing message header, including the `bounced` bit, so
   a live (non-throwing) destination contract can construct a message that is
   indistinguishable on chain from a genuine protocol-generated bounce. There
   is no cell-level or protocol-level property this contract can check to
   prove such a message wasn't self-crafted by the destination rather than
   synthesized by a real delivery failure.

   Consequently this upgrade does **not** implement automatic bounce-triggered
   refund restoration. A design that credits `refundable_liability` again
   whenever a message with the `bounced` flag arrives from a caller-chosen,
   otherwise-unconstrained destination is exploitable: that destination can
   receive its refund successfully and then immediately craft a matching
   "bounce" to reopen the same entry, repeating this to extract more than it
   is owed. Restricting the destination to the caller's own address at
   `call` time narrows *who* can exploit this but does not close it, since the
   caller and a malicious destination can be the same party.

   `claim_refund` therefore sends `price` once, at the caller's chosen destination and
   risk. If delivery genuinely fails, any value the protocol does bounce back
   arrives as ordinary balance on this contract -- it is not lost -- but it is
   not automatically re-attributed to that specific request. Recovering it
   requires the manual/governance process out of scope for this document (see
   Non-Goals), not an on-chain state transition triggered by an incoming
   `bounced` message. A caller who wants a delivery guarantee should claim to
   a destination they know can receive value unconditionally (an ordinary
   wallet address, not an arbitrary contract).

Pull-based refunds keep expiration permissionless without allowing an
untrusted cleaner to choose the refund destination. The bounded cleanup bounty
is mandatory because time alone cannot execute a TVM contract.

## Financial Accounting

The contract tracks these disjoint balances:

- `pending_liability`: prices held for unanswered requests.
- `refundable_liability`: expired prices waiting to be claimed.
- `withdrawable_revenue`: prices and unlocked storage fees earned or
  reclaimed by the owner.
- `locked_storage_fees`: fixed, non-refundable storage fees that cannot become
  owner-withdrawable revenue while their entries remain live.

At every committed state transition:

```text
contract_balance >= pending_liability
                  + refundable_liability
                  + MINIMUM_OPERATING_RESERVE
```

`withdrawable_revenue` is a nominal earned-revenue counter, not an additional
liability. Storage and execution fees naturally consume owner revenue. The
amount available to withdraw at any instant is therefore:

```text
withdrawable_now = min(withdrawable_revenue,
                       contract_balance - pending_liability
                                        - refundable_liability
                                        - MINIMUM_OPERATING_RESERVE)
```

`storage_fee` is collected once and travels with its entry through
`pending_requests` into `refunds` if the request expires. It is not a debt owed
back to the caller. While the entry is live, the corresponding amount is
tracked in `locked_storage_fees` and cannot be withdrawn. When the entry is
deleted, the nominal fee is unlocked into `withdrawable_revenue`. Actual TVM
storage fees reduce the contract's real balance independently of these nominal
counters, so every withdrawal remains capped by `get_balance()` and the
liabilities plus `MINIMUM_OPERATING_RESERVE` invariant:

```text
call:                    pending_liability    += price
                         locked_storage_fees  += storage_fee
                         (msg_value must cover price + storage_fee + gas)

respond:                 pending_liability    -= price
                         locked_storage_fees  -= storage_fee
                         withdrawable_revenue += price + storage_fee

expire:                  pending_liability    -= price
                         refundable_liability += price
                         (locked_storage_fees unchanged: the entry still exists,
                          now inside `refunds` instead of `pending_requests`)

claim_refund:            refundable_liability -= price
                         locked_storage_fees  -= storage_fee
                         withdrawable_revenue += storage_fee
                         (only price is sent to the chosen destination)

sweep refundable entry:  refundable_liability -= price
                         locked_storage_fees  -= storage_fee
                         withdrawable_revenue += price + storage_fee
                                                 - cleanup_bounty
                         (cleanup_bounty is sent to the sweeper)

sweep pending request:   pending_liability    -= price
                         locked_storage_fees  -= storage_fee
                         withdrawable_revenue += price + storage_fee
                                                 - cleanup_bounty
                         (valid only at or after refund_claim_deadline)

withdraw:                withdrawable_revenue -= amount
```

`cleanup_bounty` is policy-snapshotted, chain-bounded, and included within
`storage_fee`, not an additional liability. The chain enforces all of:

```text
MINIMUM_CLEANUP_BOUNTY <= cleanup_bounty <= MAXIMUM_CLEANUP_BOUNTY
storage_fee >= MINIMUM_STORAGE_FEE + cleanup_bounty
MINIMUM_CLEANUP_BOUNTY > 0
```

A successful sweep pays the bounty to `msg_sender`; the remainder of the fee
and the unclaimed price become owner revenue. The sweep
uses action-failure semantics that abort the transaction if the contract
cannot create the bounty send. As with refund delivery, later destination-side
failure does not reopen the deleted entry; sweepers should call from an address
that can receive value reliably.

Only `withdrawable_revenue` can be withdrawn by the owner. A payment above the
request price is returned to the caller at `call` time and never classified
as revenue.

`withdraw_revenue` must reject against the contract's actual `get_balance()`,
not only against the internal `withdrawable_revenue` counter: passive TVM
storage-fee accrual reduces the real balance over time independently of any
message, so a withdrawal that the counter alone would allow could still leave
`get_balance()` below what `pending_liability + refundable_liability +
MINIMUM_OPERATING_RESERVE` requires. Every value-moving operation must check the
invariant against the real balance, matching the existing `get_balance()`
pre-payout discipline already used elsewhere in this contract family.

The caller's response and refund rights have a fixed maximum window of
`response_sla + refund_claim_window`. Time alone does not execute a TVM
contract, however, so this is a bounded rights window rather than a guarantee
that storage is physically deleted by that time. A permissionless sweep can
delete either pending or refundable entries after the fixed deadline. The
initial `storage_fee` must include a bounded cleanup bounty paid to the sweep
caller, so cleanup does not depend on owner or caller cooperation. The owner
must also operate a sweeper as part of normal service operations.

## Attestation Domain

An attestor response signature commits to all security-relevant request data:

```text
service_address || request_id || caller_address || request_hash ||
response_hash || terms_hash || price || response_deadline ||
refund_claim_deadline
```

`refund_claim_deadline` can be derived from `response_deadline` and the
snapshotted claim window inside `terms_hash`, just as `price` is also committed
both directly and through `terms_hash`. Both are intentionally repeated so the
signed domain is self-contained for verifiers and does not rely on reconstructing
security-critical values from a nested commitment.

The implementation must define one canonical cell serialization for this
domain and use it identically in FunC, Rust helpers, `tosctl`, tests, and
documentation. A signature for one request, caller, policy, amount, or deadline
must not authorize any other request.

The attestor public key is snapshotted per request. Rotation immediately
protects new calls but cannot unilaterally rewrite existing commitments. This
creates an explicit concurrency tradeoff: compromise of an old key exposes all
still-pending requests that captured that key until they respond or expire.

Initial mitigations are short bounded SLAs, global and per-caller pending
limits, immediate pausing of new calls, hardware-backed or short-lived keys,
and monitoring of pending requests and rotations.

Pending-request key migration is outside this upgrade. A future migration must
require caller consent plus owner and new-attestor authorization; owner-only
migration would defeat the snapshot guarantee.

## Storage and Denial-of-Service Controls

The policy and contract configuration enforce:

- `max_live_global`, counting pending and refundable entries
- `max_live_per_caller`, counting pending and refundable entries
- minimum and maximum `response_sla`
- minimum and maximum `refund_claim_window`
- a non-refundable storage fee priced against the fixed rights window
  (`response_sla + refund_claim_window`), sufficient for both request and
  refund entries and including a bounded cleanup bounty
- bounded dictionary and message parsing

Live-entry counters are updated atomically with request insertion and final
deletion. Moving an entry from pending to refundable does not release capacity;
otherwise callers could repeatedly expire requests and fill the refund
dictionary while remaining below a pending-only limit.
Storage fees are locked separately from withdrawable service revenue while an
entry is live, then unlocked when it is deleted. Limits must be enforced on
chain even when `tosctl` performs the same validation client-side.

## Contract Interface

The upgraded message surface is expected to include:

```text
call(query_id, request_hash)
respond(query_id, request_id, response_hash, attestation_signature)
expire(query_id, request_id)
claim_refund(query_id, request_id, destination)
sweep_expired_request(query_id, request_id)
update_policy(...)
rotate_attestor_key(...)
revoke_attestor(...)
withdraw_revenue(...)
```

`call` has no caller-selected timeout. Owner operations affect the active
policy for future requests only. Pausing blocks new calls but does not prevent
responses, expirations, refund claims, or sweeps for existing requests.

As with the current Service Actor implementation, `recv_internal` ignores any
incoming message with the `bounced` flag set (`flags & 1`) rather than acting
on it. This is a deliberate consequence of the decision in Request Lifecycle
not to trust the `bounced` flag as a restoration trigger -- there is no
special bounce-handling branch to add.

Required getters include:

- `get_service_data`
- `get_request(request_id)`
- `get_refund(request_id)`
- `get_pending_count`
- `get_live_count`
- `get_caller_live_count(caller)`

The CLI, HTTP query API, SDK helpers, and indexer must expose request IDs and
the complete lifecycle without depending on the removed single-slot fields.

## Direct Upgrade Plan

Because no public testnet state must be preserved, implementation proceeds as
an in-place replacement:

1. Replace the state schema in `service-actor-code.fc` with request and refund
   dictionaries, counters, policy snapshots, and explicit liabilities.
2. Replace single-slot call/respond logic with the lifecycle in this document.
3. Implement canonical request-bound attestation serialization.
4. Add capacity, SLA, storage, overflow, and accounting checks.
5. Update Rust contract builders and parsers, `tosctl`, the query API, and the
   chain indexer to the new schema and messages.
6. Regenerate the embedded Service Actor BOC from the updated FunC source and
   verify source/embedded-code synchronization.
7. Reset and redeploy local development contracts and indexes.
8. Keep the existing Service Actor name and version identifier. Do not add a
   legacy deploy path or maintain the replaced implementation.

## Acceptance Criteria

The upgrade is complete only when automated tests demonstrate:

- monotonic, unique request IDs and explicit overflow rejection
- multiple concurrent calls from one and several callers
- responding to one request cannot alter another request
- signatures cannot be replayed across requests or changed terms
- policy and attestor rotation affect new requests but not snapshots
- boundary behavior is exact: `respond` requires `now() < response_deadline`,
  `expire` requires `response_deadline <= now() < refund_claim_deadline`,
  `claim_refund` requires `now() < refund_claim_deadline`, and sweep requires
  `now() >= refund_claim_deadline`
- `claim_refund` is rejected atomically, with the refund entry untouched, when
  the contract cannot itself afford `price` plus forward
  fees -- this is the one failure mode this design claims to handle atomically
- a `claim_refund` sent toward an address that does not exist or whose
  processing throws still leaves the contract's own accounting internally
  consistent (`get_balance()` at or above the remaining tracked liabilities);
  the test must not assert the refund entry is restored, only that no
  liability is double-counted or lost
- an incoming message with the `bounced` flag set never mutates any pending,
  refund, or liability state, regardless of its sender or body -- a
  crafted-to-look-like-a-bounce message must be indistinguishable in effect
  from any other unhandled message
- `refund_claim_deadline` is enforced: `claim_refund` fails once it has
  passed, `sweep_expired_request` fails before it, and both are rejected once
  the entry no longer exists
- duplicate respond, expire, claim, and sweep operations are rejected
- owner withdrawals are rejected once they would take the contract's actual
  `get_balance()` below pending and refundable liabilities plus the minimum
  operating reserve,
  not only checked against the internal revenue counter
- overpayments are returned and accounting invariants hold after every path,
  including the `sweep_expired_request` path
- global/per-caller live-entry limits, storage fees, and cleanup bounties resist
  state-filling attacks; sweep works directly against pending and refund entries
- generated bytecode matches the embedded Rust constant
- sandbox and local-chain end-to-end tests cover CLI, query API, and indexer
- storage fees and SLA/refund-claim windows are validated against
  measured masterchain gas/storage/forward fees on the real sandbox fee
  config, not only reasoned about abstractly -- the previous overpayment-refund
  feature shipped with insufficient fixture funding that only surfaced under
  real masterchain pricing, not in review

## Non-Goals

This upgrade does not include batch responses, threshold attestors, automatic
bounce-triggered refund restoration, unilateral pending-key migration,
sharded request dictionaries, or permanent on-chain history. Recovering value
sent to a destination that cannot receive it requires a separate, explicitly
out-of-scope manual or governance process; the contract does not attempt to
detect or reverse that case on chain, for the reasons given in Request
Lifecycle. These can be considered after the direct replacement is stable
under local-chain load and security testing.

## Testnet Readiness Gate

The Service Actor contract must not be deployed to public testnet until all
acceptance criteria pass, the generated code artifact is reproducible, and an
independent review confirms the lifecycle, signature domain, and financial
accounting invariants. Once public testnet begins, future incompatible state or
message changes require an explicit migration and compatibility policy.
