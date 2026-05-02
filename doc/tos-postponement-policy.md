# TOS Bounded Postponement Policy

Actor-layer Slice 4 resource model for selective receive without an
unbounded mailbox.

## 0. Status, scope, and references

**Status.** Draft v1, 2026-04-30. This is the Slice 4 Stage 0
resource-model input. It is not a protocol activation document.

This document defines the first implementable form of
`actor.md` section 5.9: bounded postponement. It is intentionally
stricter than Erlang selective receive because TOS validators must
execute deterministically and price all work.

References:

- `doc/actor.md` section 5.9, selective receive and postponement.
- `doc/actor.md` section 5.7, delivery failure handling.
- `doc/actor.md` section 6.5, behaviour patterns for Tol contracts.
- `doc/tos-message-policy.md` section 5.3, `ErrorClass`.
- `doc/tos-language-syntax-policy.md`, Slice 2 contract/state syntax.
- `doc/tol.tex`, current Tol language and stdlib surface.

## 1. First principles

1. **The protocol mailbox is not a contract-owned data structure.**
   A contract cannot reorder or scan future inbound messages. It only
   sees the single message currently being executed.
2. **Postponement is a state transition.** In the first Slice 4
   implementation, postponing a message means committing a bounded
   snapshot of that message into the contract's own `c4` storage.
3. **No unpriced replay.** The chain will not automatically wake a
   contract or re-deliver a postponed message. A later transaction must
   explicitly drain or expire postponed work.
4. **Rent follows storage ownership.** Because the postponed item lives
   in the receiver's storage, the receiver pays rent. The sender does
   not get an implicit escrowed mailbox slot.
5. **Value is not magically escrowed.** The inbound value has already
   become part of account balance during execution. If a contract needs
   per-message refund semantics, it must store a refund plan and remain
   solvent enough to honor it.
6. **The queue must be locally bounded.** Count, body size, total
   storage footprint, cell-tree depth, age, and per-transaction drain
   work are all part of the contract ABI. There is no global default
   that is safe for all contracts.
7. **Expiry is observed, not scheduled.** Without the Slice 6 time
   primitive, expiry is checked on enqueue, drain, or explicit cleanup.
   No timeout message is synthesized by the protocol.

## 2. Non-goals

Slice 4 postponement does not add:

- a new TL-B constructor;
- a new TVM opcode;
- a new bounce-body format;
- `extra_flags` mask widening;
- a protocol mailbox scanner;
- protocol-scheduled wakeups;
- cross-shard delivery SLA semantics from `actor.md` section 5.7;
- protocol-level supervision or scheduled messages.

External-message postponement is out of scope for the first
implementation. External bodies such as wallet-v5 signed requests do
not have the same sender/bounce/refund semantics as internal messages.

## 3. Queue model

A postponed queue is ordinary contract storage. The stdlib shape is
expected to be:

```tol
struct PostponedItem {
    nonce: uint64
    sender: address
    opcode: uint32
    queryId: uint64?
    body: cell
    valueCoins: coins
    originalForwardFee: coins
    createdAt: uint32
    expiresAt: uint32
    bodyBits: uint16
    bodyRefs: uint8
    bodyDepth: uint16
}

struct PostponedQueue {
    nextNonce: uint64
    count: uint16
    totalBodyBits: uint32
    totalBodyRefs: uint16
    lastMeasuredCellDepth: uint16
    items: map<uint64, PostponedItem>
    queryIndex: map<uint256, uint64>
}
```

The exact field names may change during implementation, but the
semantics above are load-bearing:

- `nonce` gives deterministic FIFO order without scanning hashes.
- `queryIndex` prevents replay for query-bearing messages by
  `(sender, opcode, query_id)`.
- Messages whose schema declares `query_id: optional` use the
  `(sender, opcode, query_id)` replay key only when a `query_id` is
  actually present. If it is absent, the message follows the non-query
  rule below.
- Non-query messages are not postponable by default. A stdlib helper
  may accept an explicit author-supplied idempotency key, but the
  compiler must not silently invent one. Behaviour manifests spell this
  as `missing_query_id: author_key`; otherwise the correct value is
  `missing_query_id: reject`.
- `bodyBits`, `bodyRefs`, and `bodyDepth` are measured before insertion
  and charged against queue limits.
- `valueCoins` is a record of the inbound value, not a locked coin
  object. Contracts that expose refunds must implement a solvency rule.

## 4. Required budget parameters

Every queue must declare or construct with these limits:

| Parameter | Meaning | Minimum compiler/stdlib check |
|---|---|---|
| `maxItems` | Maximum live postponed entries | enqueue fails at or above limit |
| `maxBodyBits` | Maximum bits per postponed body | body snapshot larger than limit is rejected |
| `maxBodyRefs` | Maximum refs per postponed body | body snapshot larger than limit is rejected |
| `maxTotalBodyBits` | Aggregate body-bit ceiling | insertion cannot exceed ceiling |
| `maxTotalBodyRefs` | Aggregate body-ref ceiling | insertion cannot exceed ceiling |
| `maxAgeSeconds` | Maximum age before expiry | `expiresAt = now + maxAgeSeconds` |
| `maxDrainItems` | Per-transaction drain bound | drain helper stops after this many items |
| `maxCellDepth` | Maximum serialized queue subtree depth | helper rejects mutations that would exceed the configured depth; the value must stay below TVM's hard cell-depth limit |

The implementation may add a gas-reserve argument to drain helpers, but
the first release must not claim a hard gas proof unless the compiler
can prove it. A conservative `maxDrainItems` bound is required even
when a gas-reserve helper exists.

When postponement is enabled, `maxItems`, `maxAgeSeconds`,
`maxDrainItems`, and `maxCellDepth` must all be greater than zero.
`maxAgeSeconds = 0` is legal only for a disabled queue and means "do not
enqueue"; it must not be used to create immediately expired live items.

## 5. Enqueue semantics

An internal receiver may enqueue the current message only after:

1. the 32-bit opcode has been decoded;
2. the receiver has established that the message is deferrable rather
   than malformed;
3. the body snapshot fits per-entry limits;
4. the queue totals will remain within bounds;
5. a query-bearing duplicate key or explicit author idempotency key does
   not already exist;
6. `expiresAt` is finite and greater than `blockchain.now()`.

Malformed messages are not postponable. They follow the contract's
normal unknown-opcode or protocol-error policy.

If enqueue fails because the queue is full, the contract may send an
`OP_ERROR` reply with `ErrorClass.Transient` and a Slice 4
postponement error code. `ErrorClass.BackPressure` remains reserved
until the delivery-SLA work in `actor.md` section 5.7 defines its
cross-shard meaning.

## 6. Drain and expiry semantics

Drain is explicit. A contract drains during a later normal receive path,
usually immediately after `become` enters a state that can handle the
postponed class.

The stdlib drain helper must:

- process entries in increasing `nonce` order;
- skip or evict expired entries before replay;
- stop at `maxDrainItems`;
- preserve storage consistency if the user callback throws;
- never recursively call the contract entrypoint.

The replay callback receives a `PostponedItem` value. It is ordinary
Tol code, not a second TVM transaction. Authors must treat it as a
local continuation over a saved message snapshot.

Callback failure semantics are fixed:

- On callback success, the helper deletes the item and decrements all
  queue accounting in the same transaction.
- On an expected application-level rejection, the callback must return
  an explicit failure status or the contract must call an explicit
  drop/expire helper before retrying. It must not use `throw` as normal
  flow control.
- If the callback throws, the TVM transaction aborts under ordinary TVM
  rules. No queue mutation or outbound action from that transaction is
  committed; the item remains in the queue at the same `nonce`; and the
  helper must not catch-and-continue to later items.

This chooses safety over silent loss. It also means a throwing head item
can block FIFO drain until it expires or a later explicit contract path
drops it with a documented error/recovery action. Stage 1 tests must
cover both "throw does not lose the item" and the explicit drop/expiry
path.

Expiry does not synthesize a bounce. If the contract wants an expiry
notification or refund, the drain/cleanup path must send it explicitly.
Until `actor.md` section 5.7 is designed, expiry errors use
`ErrorClass.Transient` or an application-specific class; they do not use
`ErrorClass.BackPressure`.

## 7. Ordering and determinism

Postponement changes when contract code elects to process saved work,
not the order in which validators deliver inbound messages.

The deterministic order is:

1. current inbound message runs;
2. user code may enqueue the current message snapshot;
3. user code may drain at most `maxDrainItems` previously saved items;
4. the transaction commits one final `c4` state and one final action
   list.

The stdlib must not hide additional sends, retries, or self-messages
inside enqueue. Self-message based wakeups are a later protocol/design
choice, not part of Draft v1.

## 8. Static-analysis obligations

Stage 1 is a trust-period implementation: tests may use the
`@stdlib/postponement` helpers before compiler hardening exists, but
Stage 1 contracts are not eligible for the official reference package
until the Stage 2 checks below are in place.

The Slice 4 compiler work should add checks in stages:

1. Warning mode for raw maps that look like postponed queues but do not
   use the stdlib helper.
2. Error mode for direct writes to stdlib queue internals, matching the
   Slice 3 pending-reply-table hardening pattern.
3. Error mode for enqueue calls that omit one of the required budget
   parameters.
4. Error mode for external-message enqueue attempts.
5. Warning mode when a `receive(...) on State` branch rejects a message
   that is declared deferrable by a behaviour manifest.

These checks must run before contract lowering once they inspect
contract/state syntax, and after symbol registration once they need
resolved struct and stdlib types.

## 9. Trait and behaviour integration

Bounded postponement is a behaviour capability, not an inheritance
mechanism. Behaviour manifests may declare:

- which message classes are deferrable in which states;
- the queue field that owns postponed work;
- the budget constants;
- how optional or absent `query_id` is handled (`reject` versus an
  explicit author-supplied idempotency key);
- which error codes represent queue full, duplicate, expired, and
  non-deferrable messages;
- whether the behaviour promises FIFO or keyed replay.

The first trait implementation should be compiler-checked conformance
over ordinary Tol code. It should not introduce dynamic dispatch, vtables,
runtime type reflection, or bytecode-visible trait objects.

## 10. Security review checklist

A Slice 4 postponement implementation is not complete unless tests show:

- queue-full is bounded and deterministic;
- oversized bodies are rejected before storage mutation;
- duplicate `(sender, opcode, query_id)` entries cannot accumulate;
- optional-`query_id` messages without an actual `query_id` either use
  an explicit author idempotency key or are rejected;
- serialized queue cell-tree depth stays below the configured
  `maxCellDepth` and below the TVM hard limit;
- expired entries are evicted without unbounded scanning;
- non-query messages require an explicit idempotency key;
- callback throws abort without losing the head item, and explicit
  drop/expiry is the only non-successful removal path;
- direct user access to queue internals is rejected or warned in the
  same mode as the RFC stage requires;
- draining preserves FIFO order;
- a throwing drain callback does not corrupt queue accounting;
- no existing Slice 1, Slice 2, or Slice 3 wire body changes.

## 11. Open questions for implementation

1. Whether the initial stdlib helper should expose a low-level
   `enqueueCurrentInternal(...)` convenience that reads `InMessage`
   fields, or only a pure `enqueue(item)` API.
2. Whether queue accounting should store body bits/refs eagerly or
   recompute them during cleanup. Eager storage is easier to check but
   costs more cells.
3. Whether a later stage should reserve a self-message opcode for
   optional wakeups. Draft v1 says no because it would become visible
   wire surface.
4. Whether the first shipped dogfood contract should be an auction
   reference or a smaller escrow-style reference. The success criterion
   requires at least one shipped contract, not only a unit test.
