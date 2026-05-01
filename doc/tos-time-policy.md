# TOS Time and Scheduled Message Policy RFC

## 0. Status and scope

**Status.** Draft v0.1, 2026-05-01. Companion RFC for Slice 6 Stage 0.

This document defines the resource model and semantics for native
scheduled messages. It intentionally starts below Tol syntax because the
danger is not spelling `sendAfter`; the danger is an unpriced validator
timer queue.

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

## 2. Time base

Stage 0 leaves the exact time base open for review, but narrows it to
two safe options:

1. masterchain block time with a configured fairness window;
2. masterchain seqno with a configured block-count window.

Contract-local caller-provided `msg.now` is never a trusted scheduling
source. Tol and stdlib helpers must use `blockchain.now()` or the
protocol-provided scheduling context.

## 3. Scheduled action shape

Minimum fields:

```
target: address
body: Cell
value: coins
send_mode: uint8
not_before: uint64
expire_after: uint64
cancel_authority: address
dead_letter: address?
```

The implementation may pack these differently, but the semantics must
be visible in tests and manifests.

## 4. Funding and rent

The scheduling transaction escrows:

- storage rent for the scheduled entry until `expire_after`;
- delivery forwarding fee;
- cancellation refund fee;
- dead-letter/bounce forwarding fee when requested.

If the sender does not fund the entry, scheduling fails synchronously.
If later config changes make the escrow insufficient, delivery proceeds
only up to the escrowed budget and diagnostics are dropped before
delivery itself is dropped.

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

## 6. Frozen, deleted, or missing accounts

At due time:

- missing or uninitialized target follows ordinary internal-message
  semantics;
- frozen target produces delivery failure if delivery cannot execute;
- deleted target routes to bounce or dead-letter if funded;
- missing sender does not cancel delivery automatically. A funded
  scheduled message is already protocol state.

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
sendAfter(target, body, delaySeconds, value, mode)
sendAt(target, body, notBefore, expireAfter, value, mode)
cancelScheduled(handle)
```

The handle is an opaque scheduled-message id, not a secret. A handle
authorizes nothing by itself; cancellation still checks
`cancel_authority`.

## 9. Non-goals

- No exact wall-clock execution.
- No protocol selective receive.
- No free wakeups for contracts with zero balance.
- No automatic retry loop beyond the configured delivery-SLA window.
- No reliance on caller-provided `msg.now`.

## 10. Stage 2/3 exit criteria

- Emulator fixtures prove delivery no earlier than `not_before`.
- Cancellation race ordering is deterministic.
- Expired scheduled messages produce bounded delivery failure records.
- Tol examples use `blockchain.now()` and scheduled helpers rather than
  accepting `now` as a wire field.

