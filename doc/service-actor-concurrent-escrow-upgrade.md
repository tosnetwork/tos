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
terms_hash = hash(policy_version || price_per_call || response_sla ||
                  refund_claim_window || metadata_hash || proof_scheme_hash)
```

The terms and attestor key are snapshotted when the request is accepted. Policy
and key changes affect only later requests and do not require a global freeze
while requests are pending.

## Persistent State

Pending requests are stored in a dictionary keyed by request identifier:

```text
pending_requests:(HashmapE 64 ^PendingRequest)

pending_request$_
  caller:MsgAddressInt
  price:Coins
  storage_deposit:Coins
  response_deadline:uint64
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
request cell is approximately 363 fixed bits (`MsgAddressInt` + two `uint`
fields) plus two variable-length `Coins` fields (`price`, `storage_deposit`,
each up to 124 bits), comfortably under the limit even at their maximum
encoded size. The commitment cell is 769 bits. Presence in `pending_requests`
is the pending status, so no status field is stored. Creation time is
available from chain history and is not duplicated in contract state.

Expired-but-unclaimed requests are stored in a second dictionary, also keyed
by request identifier:

```text
refunds:(HashmapE 64 ^Refund)

refund$_
  caller:MsgAddressInt
  amount:Coins
  storage_deposit:Coins
  refund_claim_deadline:uint64
= Refund;
```

`storage_deposit` moves with the entry: it is collected at `call` time as part
of `msg_value`, carried into the `Refund` record by `expire` (the refund entry
needs storage until it is claimed or swept, exactly like the pending entry
did), and returned to whichever party's action finally deletes the entry --
see Financial Accounting. Completed (`responded`/`refunded`/swept) history
belongs in the chain indexer rather than permanent contract storage; this
contract never stores a terminal-state record for a resolved request.

## Request Lifecycle

```text
Pending --respond--------------------------------> Responded
Pending --expire--> Refundable --claim_refund-----> Refunded
                                --refund_claim_deadline passed--> Swept
```

- `call` rejects an inactive service, invalid payment, invalid policy, capacity
  excess, or malformed body. It allocates an ID and stores the request snapshot.
- `respond` verifies that the request exists, is before its deadline, and has a
  valid request-bound attestation when an attestor is configured. It removes
  the pending entry and recognizes the request price as owner revenue.
- `expire` is permissionless after the deadline. It removes the pending entry
  and creates a caller-owned refund credit with
  `refund_claim_deadline = now() + refund_claim_window` (the window snapshotted
  from the policy in force when the request was accepted).
- `claim_refund` is initiated by the caller before `refund_claim_deadline` and
  sends the credit to a caller-chosen destination.
- `sweep_unclaimed_refund` is permissionless after `refund_claim_deadline`. It
  moves an unclaimed refund into `withdrawable_revenue` -- the same
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

   `claim_refund` therefore sends once, at the caller's chosen destination and
   risk. If delivery genuinely fails, any value the protocol does bounce back
   arrives as ordinary balance on this contract -- it is not lost -- but it is
   not automatically re-attributed to that specific request. Recovering it
   requires the manual/governance process out of scope for this document (see
   Non-Goals), not an on-chain state transition triggered by an incoming
   `bounced` message. A caller who wants a delivery guarantee should claim to
   a destination they know can receive value unconditionally (an ordinary
   wallet address, not an arbitrary contract).

Pull-based refunds keep expiration permissionless without allowing an
untrusted cleaner to choose the refund destination. A bounded cleanup bounty
may be added later if operational testing shows that expiration or sweeping
needs one.

## Financial Accounting

The contract tracks these disjoint balances:

- `pending_liability`: prices held for unanswered requests.
- `refundable_liability`: expired prices waiting to be claimed.
- `withdrawable_revenue`: prices (and swept storage deposits) earned or
  reclaimed by the owner.
- `storage_reserve`: the sum of every live entry's `storage_deposit`.

At every committed state transition:

```text
contract_balance >= pending_liability
                  + refundable_liability
                  + withdrawable_revenue
                  + storage_reserve
```

`storage_deposit` is collected once, at `call` time, and travels with its
entry through `pending_requests` into `refunds` if the request expires. It is
never re-derived or re-estimated later; it settles exactly once, in the same
transition that deletes the entry it was backing:

```text
call:                    pending_liability    += price
                         storage_reserve      += storage_deposit
                         (msg_value must cover price + storage_deposit + gas)

respond:                 pending_liability    -= price
                         withdrawable_revenue += price
                         storage_reserve      -= storage_deposit
                         (storage_deposit is returned to the caller: the
                          storage obligation it covered has ended)

expire:                  pending_liability    -= price
                         refundable_liability += price
                         (storage_reserve unchanged: the entry still exists,
                          now inside `refunds` instead of `pending_requests`)

claim_refund:            refundable_liability -= price
                         storage_reserve      -= storage_deposit
                         (price + storage_deposit both sent to the caller's
                          chosen destination in one message)

sweep_unclaimed_refund:  refundable_liability -= price
                         storage_reserve      -= storage_deposit
                         withdrawable_revenue += price + storage_deposit
                         (no outbound message -- see below)

withdraw:                withdrawable_revenue -= amount
```

`sweep_unclaimed_refund` deliberately does not attempt to return the deposit
to the non-claiming caller: doing so would be another push-based send with
the exact cross-transaction delivery problem described in Request Lifecycle,
reintroduced for a case the design is specifically trying to close out
cleanly. Once `refund_claim_deadline` has passed without a claim, both the
price and the now-unneeded storage deposit fold into `withdrawable_revenue`
as a pure accounting move with no outbound action.

Only `withdrawable_revenue` can be withdrawn by the owner. A payment above the
request price is returned to the caller at `call` time and never classified
as revenue.

`withdraw_revenue` must reject against the contract's actual `get_balance()`,
not only against the internal `withdrawable_revenue` counter: passive TVM
storage-fee accrual reduces the real balance over time independently of any
message, so a withdrawal that the counter alone would allow could still leave
`get_balance()` below what `pending_liability + refundable_liability +
storage_reserve` requires. Every value-moving operation must check the
invariant against the real balance, matching the existing `get_balance()`
pre-payout discipline already used elsewhere in this contract family.

`pending_liability` has a bounded lifetime per entry (`response_sla`, then
`expire` moves it to `refundable_liability`), and `refundable_liability` is
now also bounded (`refund_claim_window`, then `sweep_unclaimed_refund` closes
it out). No entry can accumulate storage-rent exposure indefinitely: every
entry's maximum lifetime is `response_sla + refund_claim_window`, and
`storage_deposit` must be sized against that fixed, finite duration rather
than an open-ended one.

## Attestation Domain

An attestor response signature commits to all security-relevant request data:

```text
service_address || request_id || caller_address || request_hash ||
response_hash || terms_hash || price || response_deadline
```

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

- `max_pending_global`
- `max_pending_per_caller`
- minimum and maximum `response_sla`
- minimum and maximum `refund_claim_window`
- a storage deposit sized against the fixed worst-case entry lifetime
  (`response_sla + refund_claim_window`), sufficient for both request and
  refund entries
- bounded dictionary and message parsing

Per-caller counters are updated atomically with request insertion and removal.
Storage deposits are accounted separately from service revenue and any unused
remainder is returned when state is cleaned up. Limits must be enforced on
chain even when `tosctl` performs the same validation client-side.

## Contract Interface

The upgraded message surface is expected to include:

```text
call(query_id, request_hash)
respond(query_id, request_id, response_hash, attestation_signature)
expire(query_id, request_id)
claim_refund(query_id, request_id, destination)
sweep_unclaimed_refund(query_id, request_id)
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
- `get_caller_pending_count(caller)`

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
- early expiration is rejected and post-deadline expiration succeeds
- `claim_refund` is rejected atomically, with the refund entry untouched, when
  the contract cannot itself afford `price + storage_deposit` plus forward
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
  passed, `sweep_unclaimed_refund` fails before it, and both are rejected once
  the entry no longer exists
- duplicate respond, expire, claim, and sweep operations are rejected
- owner withdrawals are rejected once they would take the contract's actual
  `get_balance()` below the sum of pending, refundable, and reserve balances,
  not only checked against the internal revenue counter
- overpayments are returned and accounting invariants hold after every path,
  including the `sweep_unclaimed_refund` path
- global/per-caller limits and storage deposits resist state-filling attacks
- generated bytecode matches the embedded Rust constant
- sandbox and local-chain end-to-end tests cover CLI, query API, and indexer
- storage deposits and SLA/refund-claim windows are validated against
  measured masterchain gas/storage/forward fees on the real sandbox fee
  config, not only reasoned about abstractly -- the V1 overpayment-refund
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
