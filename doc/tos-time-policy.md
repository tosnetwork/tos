# TOS Time and Scheduled Message Policy RFC

## 0. Status and scope

**Status.** Draft v0.2, 2026-05-01. Companion RFC for Slice 6 Stage 0
after the first design-review fix pass.

This document defines the resource model and semantics for native
scheduled messages. It intentionally starts below Tol syntax because the
danger is not spelling `sendAfter`; the danger is an unpriced validator
timer queue.

For AI actor workflows, scheduled messages are the foundation for task deadlines, cancellation windows, retry backoff, service-call expiry, and dispute periods.

## 1. First principles

A scheduled message is persistent consensus state. It is not a callback
in a local runtime. It consumes storage until due, then consumes block
space and forwarding fees when delivered or expired.

Therefore every scheduled message must be:

- bounded by count and storage;
- funded for delivery, expiry, and cancellation;
- cancellable only by a well-defined authority;
- delivered no earlier than its due point, with no exact-time guarantee;
- observable enough for audit without exposing precise validator queue
  internals.

Task actors and service actors should use scheduled messages only for consensus-visible deadlines. Off-chain timers may improve UX, but they are not authoritative for escrow, timeout, or settlement.

## 2. Time base

Slice 6 scheduled delivery uses **masterchain seqno** as its consensus
time base. The scheduler compares `not_before_mc_seqno` and
`deliver_by_mc_seqno` against the masterchain seqno visible to the
delivery engine.

Timestamp-based scheduling is rejected for the Stage 0 baseline because
validators have bounded discretion over block timestamps. That
discretion is enough to create MEV around escrow expiry, option
exercise, order cancellation, and vesting cliffs. Masterchain seqno gives
less wall-clock precision, but it makes the ordering rule objective:
delivery is valid only after the named masterchain block has appeared.

Contract-local caller-provided `msg.now` is never a trusted scheduling
source. Tol and stdlib helpers use `blockchain.currentMcSeqno()` (TVM
`PREVMCBLOCKS`) or the protocol-provided scheduling context for
masterchain-seqno validity windows. `blockchain.now()` remains valid for
ordinary Unix-time business logic, but it must not feed any `*McSeqno`
field.

## 3. Scheduled action shape

Minimum fields:

```tlb
scheduled_action_v1#d602
target: MsgAddressInt
body: ^Cell
value: CurrencyCollection
send_mode: uint16
not_before_mc_seqno: uint32
expire_after_blocks: uint32
cancel_authority: MsgAddressInt
dead_letter: (Maybe MsgAddressInt)
= ScheduledActionV1;
```

`deliver_by_mc_seqno` is not a wire field; it is computed as
`not_before_mc_seqno + expire_after_blocks`. Overflow is invalid at
scheduling time. Stage 2 adds the scaffold type and predicate fixtures;
validator queue integration remains version-gated.

## 4. Funding and rent

The scheduling transaction escrows:

- storage rent for the scheduled entry until `deliver_by_mc_seqno`;
- delivery forwarding fee;
- cancellation refund fee;
- dead-letter/bounce forwarding fee when requested.

If the sender does not fund the entry, scheduling fails synchronously.
If later config changes make the escrow insufficient, delivery proceeds
only up to the escrowed budget and diagnostics are dropped before
delivery itself is dropped. If escrow cannot cover storage until
`deliver_by_mc_seqno`, the entry is force-expired on the next scheduler
sweep and routed through the delivery-SLA failure path with whatever
escrow remains.

## 5. Cancellation

Cancellation is valid only while the scheduled entry is still pending.
Cancellation races resolve by deterministic ordering:

1. if delivery transaction is already selected into a block before the
   cancellation, delivery wins;
2. otherwise cancellation wins and refunds any refundable escrow to the
   declared refund target.

Only `cancel_authority` may cancel. The original sender is the default
cancel authority, but a contract may explicitly delegate cancellation in
the scheduled action.

If `cancel_authority` is deleted, frozen, or missing, no other actor
inherits cancellation rights automatically. The `dead_letter` address may
cancel only if it was explicitly set as `cancel_authority`. A stuck entry
with a missing cancel authority is resolved by normal delivery,
force-expiry on escrow depletion, or expiry at `deliver_by_mc_seqno`.

## 6. Frozen, deleted, or missing accounts

At due time:

- missing or uninitialized target follows ordinary internal-message
  semantics;
- frozen target produces delivery failure if delivery cannot execute;
- deleted target routes to bounce or dead-letter if funded;
- missing sender does not cancel delivery automatically. A funded
  scheduled message is already protocol state.
- missing cancel authority does not block expiry and does not transfer
  cancellation authority to the dead-letter address unless the scheduled
  action explicitly made that address the cancel authority.

## 7. Limits

Config must define:

- max scheduled entries per account;
- max scheduled entries per workchain shard;
- max body bits/refs per scheduled message;
- max total scheduled storage per account;
- max future horizon;
- max delivery attempts per block or shard;
- storage price multiplier, if scheduled state is priced differently
  from account state.

The default limits should be conservative until system-contract dogfood
shows real load.

## 8. Tol and stdlib surface

Stage 3 may expose:

```tol
sendAfterBlocks(target, body, delayBlocks, value, mode)
sendAtMcSeqno(target, body, notBeforeMcSeqno, expireAfterBlocks, value, mode)
cancelScheduled(handle)
```

The handle is an opaque scheduled-message id, not a secret. A handle
authorizes nothing by itself; cancellation still checks
`cancel_authority`.

The scheduled handle for the initial delivery attempt is the
`delivery_id` defined in `doc/tos-delivery-sla-policy.md` section 3 with
`attempt_kind = 1` and `attempt_seq = 0`. It is stable for a finalized
scheduling transaction. If a block containing the scheduling transaction
is reorganized out, both the scheduled entry and any contract state that
stored its handle are rolled back. If an off-chain client retained the
orphaned handle, `cancelScheduled(orphaned_handle)` behaves the same as
`cancelScheduled(unknown_handle)`: it fails without side effects.
`cancelScheduled(already_delivered_handle)` and
`cancelScheduled(expired_handle)` also fail without side effects.

## 9. Non-goals

- No exact wall-clock execution.
- No protocol selective receive.
- No free wakeups for contracts with zero balance.
- No automatic retry loop beyond the configured delivery-SLA window.
- No reliance on caller-provided `msg.now`.

## 10. Stage 2/3 exit criteria

- Emulator fixtures prove delivery no earlier than `not_before`.
- Emulator fixtures prove delivery no earlier than `not_before_mc_seqno`.
- Cancellation race ordering is deterministic.
- Expired scheduled messages produce bounded delivery failure records.
- Tol examples use `blockchain.currentMcSeqno()` / protocol scheduling
  context for masterchain-seqno fields, and use `blockchain.now()` only for
  ordinary Unix-time business logic.
- Handle derivation, orphaned-handle cancellation, already-delivered
  cancellation, and expired-handle cancellation are covered by tests.
