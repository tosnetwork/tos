# TOS Message and Lifecycle Policy

## 0. Status, scope, and references

**Status.** Draft. This document is the policy input for Slice 1 of
[`doc/roadmap.md`](roadmap.md). It must be approved by four owners
before Slice 1 implementation begins:

- Protocol architect
- TVM lead
- Tol compiler lead
- Contract-team representative

**Scope.** This document fixes the cross-cutting wire-level and
lifecycle decisions that the protocol, TVM, and Tol teams must
agree on before they begin implementing
[`doc/actor.md`](actor.md) §5.3 + §5.6 and
[`doc/tol.md`](tol.md) Q1.

**Out of scope.** Higher-level language syntax (`contract`,
`receive(...)`, `message` keywords) is out of scope here; that is
Slice 2. Supervision (§5.1), scheduled messages (§5.2), and
capability addressing (§5.4) are out of scope; they have their own
later policy documents.

**Source-of-truth references.**

- TVM v12 envelope and bounce changes:
  [`doc/GlobalVersions.md`](GlobalVersions.md) §"Version 12".
- Internal message TL-B schema:
  [`crypto/block/block.tlb`](../crypto/block/block.tlb), starting
  at the `int_msg_info$0` constructor.
- Account state TL-B schema: same file, the `AccountState`
  constructors (`account_uninit$00`, `account_active$1`,
  `account_frozen$01`).
- Existing TEP-style standards inventory:
  [`doc/tos-tep-token-standards.md`](tos-tep-token-standards.md),
  [`doc/tos-standards-map.md`](tos-standards-map.md).

## 1. Why this policy exists

`doc/roadmap.md` §3 states the rationale: without a single
agreed-upon policy, the three implementing subsystems (protocol,
TVM, Tol) will independently invent slightly inconsistent
assumptions about message envelope, error classification,
account lifecycle, and query correlation. The integration phase of
Slice 1 will then burn weeks reconciling those drifts.

This document costs one to two weeks to write and review. It saves
that integration cost and locks the substrate that every later
slice depends on.

## 2. Current baseline (TVM v12)

The policy below is built on top of TVM v12, not in place of it.

### 2.1 Internal message envelope

From `block.tlb`:

```
int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
  src:MsgAddressInt dest:MsgAddressInt
  value:CurrencyCollection extra_flags:(VarUInteger 16) fwd_fee:Tomis
  created_lt:uint64 created_at:uint32 = CommonMsgInfo;
```

`extra_flags` is the renamed-and-repurposed former `ihr_fee` field.
TVM v12 defines:

- `extra_flags & 1` — enable the new (v12) bounce body format.
- `extra_flags & 2` — when bouncing, return the whole original
  body rather than only the root cell without refs.
- All higher bits are reserved and must be zero on send. Internal
  messages with reserved bits set are invalid.

### 2.2 v12 bounce body

```
new_bounce_body#fffffffe
    original_body:^Cell
    original_info:^NewBounceOriginalInfo
    bounced_by_phase:uint8 exit_code:int32
    compute_phase:(Maybe NewBounceComputePhaseInfo)
    = NewBounceBody;
```

The system-level bounce already carries: which phase failed
(compute or action), the TVM exit code, gas used, vm steps, and
the original message body. Per `GlobalVersions.md`,
`bounced_by_phase` is one of:

- `0` — compute phase skipped, with `exit_code` ∈ {-1, -2, -3, -4}
  (no state, bad state init hash, no gas, suspended).
- `1` — compute phase failed; `exit_code` is the compute-phase
  result.
- `2` — action phase failed.

This means TVM v12 already provides the structured **system**
error layer described in `actor.md` §5.3. What this policy adds is
the **application** error layer on top of it, plus envelope
discipline.

### 2.3 Account lifecycle states

```
account_uninit$00                       = AccountState;
account_active$1 _:StateInit            = AccountState;
account_frozen$01 state_hash:bits256    = AccountState;
```

TOS recognizes three on-chain account states. There is no
"deleted" state at the TL-B level; deletion is observable only by
the absence of the account entry in the relevant shard's account
dictionary.

### 2.4 Logical time

Each message carries `created_lt:uint64`. Within a sender / dest
pair, the protocol enforces FIFO delivery in `created_lt` order.
This is the only ordering guarantee the protocol provides; in
particular, messages from different senders to the same recipient
have **no** mutually consistent ordering.

## 3. Application-layer envelope

The policy in this section governs the **body** of internal
messages. The protocol layer treats the body as opaque. This
policy makes the application-layer body shape canonical so that
contracts, the Tol standard library, and tooling can rely on it.

### 3.1 Standard body layout

Every internal message body produced by Tol-generated code must
begin with:

```
opcode:uint32  query_id:uint64  payload:...
```

- `opcode` — application-defined operation identifier. The
  remaining bits 32 of every body are reserved for opcode use.
- `query_id` — 64-bit correlation identifier. See §4.
- `payload` — opcode-specific bits.

This layout is bit-compatible with the TEP-74, TEP-62, and
wallet-vN message conventions already in use, so existing
contracts continue to work without change.

### 3.2 Special opcodes

The first 16 bits of `opcode` partition the opcode space:

- `0x0000` — text-comment opcode. The body after the first 32
  bits is interpreted as UTF-8 text, with `query_id` set to zero.
  This matches the existing simple-transfer convention.
- `0x0001`–`0x00FF` — reserved for future protocol-defined system
  opcodes. Implementations must reject these on send unless the
  opcode is documented in this policy.
- `0x0100`–`0xFFFF` — reserved for future ecosystem-wide standards
  (TEP-style allocations).
- `0x00010000`–`0x7FFFFFFF` — application-defined.
- `0x80000000`–`0xFFFFFFFF` — reserved. The high bit indicates a
  reply or notification opcode in some TEP-style standards;
  contracts must not invent new high-bit opcodes outside an
  approved standard.

### 3.3 Optional `reply_to`

Some opcodes carry a destination override for replies. When
present, `reply_to` is a serialized address immediately following
`query_id` in the body, and is part of the opcode-specific
payload. Whether a given opcode carries `reply_to` is fixed by
the opcode's TEP-style definition; this policy does not introduce
a global `reply_to` flag.

When `reply_to` is absent, replies are addressed to the inbound
message's `src`. When `reply_to` is present, replies are addressed
to its value. Tol's standard library must enforce this rule for
every opcode that declares `reply_to`.

### 3.4 Extension reservation in `extra_flags`

Bits 2 and 3 of `extra_flags` are reserved by this policy for
future use:

- Bit 2 — reserved for the application-level error-class extension
  defined in §5. Implementations must not set bit 2 in Slice 1;
  it is allocated for Slice 4 or later.
- Bit 3 — reserved for the supervision-link tag of `actor.md`
  §5.1. Not implementable until Slice 6.

The TVM v12 rule that internal messages with extra_flags bits
beyond `0..3` are invalid remains in force.

## 4. `query_id` rules

### 4.1 Allocation

- 64-bit, allocated by the **sender** of the request.
- A `query_id` of `0` denotes "no correlation expected": the
  sender does not require a reply, and any contract receiving such
  a message should treat the conversation as one-shot.
- All other values are opaque to the protocol. Senders are
  encouraged to use a strictly increasing 64-bit counter scoped
  to their own state, but this is not enforced.

### 4.2 Uniqueness

- A sender **should** ensure uniqueness within a window of
  outstanding requests to the same recipient. The recommended
  window size is the maximum number of in-flight requests the
  sender's contract can have outstanding given its storage
  budget for the correlation table.
- A recipient **must** tolerate duplicate `query_id` values from
  the same sender without crashing or corrupting state. Whether
  duplicates are merged, replayed, or rejected is opcode-specific
  and must be documented per opcode.

### 4.3 Replay across reorgs

Reorgs may cause a `query_id`-bearing message to be replayed
after the chain reorganizes. Recipients must produce the same
side effect on a replayed message as on the original. Idempotency
is the recipient's responsibility, not the sender's.

### 4.4 Reply binding

A reply message is any message whose body's `query_id` matches
the `query_id` of an outstanding request the recipient sent
earlier. The recipient pairs replies by `query_id` lookup in its
local outstanding-request table. Tol's `pipe-check-*` pass added
in Slice 1 Stage 2 enforces that:

- Every handler that returns a reply propagates the inbound
  `query_id` (or explicitly disclaims it).
- Every send-with-reply call produces a `query_id` and reserves a
  table slot.

## 5. Error classification

### 5.1 Two-tier error model

TOS errors are reported on two layers:

- **System tier** — already in the v12 bounce body:
  `bounced_by_phase` and `exit_code`. Owned by the protocol;
  applications cannot extend it.
- **Application tier** — defined here, carried in the message
  body of failure replies (and, when bit 2 of `extra_flags` is
  activated in a later slice, in the bounce body itself). Owned
  by the application; the protocol does not interpret it.

### 5.2 Application error encoding

When an application chooses to send a structured failure response
to its caller, the body has the form:

```
opcode = OP_ERROR (0x00010001 — reserved here)
query_id:uint64
error_class:uint8
error_code:uint16
diagnostic:(Maybe ^Cell)
```

- `error_class` — one of the values defined in §5.3.
- `error_code` — opaque to the protocol, defined per application
  domain (jetton, NFT, governance, etc.). Values 0..1023 are
  reserved for the Tol standard library; 1024+ are application-
  defined.
- `diagnostic` — an optional cell for human-readable detail.
  Implementations must tolerate its absence.

The opcode `0x00010001` is reserved by this policy for
`OP_ERROR`. Existing TEP-style "excess refund" or "error reply"
opcodes are not affected; they continue to use their existing
opcodes and are simply not recognized as OP_ERROR.

### 5.3 Transient vs. permanent

`error_class` carries the actor.md §5.3 transient/permanent
distinction:

| `error_class` | Meaning | Retry plausible? |
|---|---|---|
| `0` | OK / no error | n/a |
| `1` | Transient — out of gas, queue congestion, recipient temporarily unavailable | Yes, with backoff |
| `2` | Permanent — uncaught exception, malformed body, code-rejected | No |
| `3` | Authorization — caller not permitted | Maybe, after re-auth |
| `4` | Protocol — opcode unknown, body malformed at envelope level | No |
| `5`–`15` | Reserved for future expansion | n/a |
| `16`–`255` | Application-specific | Application-defined |

Supervisors (`actor.md` §5.1) must distinguish at least classes
1 and 2 when deciding whether to restart.

### 5.4 Alignment with v12 bounce

A v12 system bounce always includes `bounced_by_phase` and
`exit_code`. Applications that want to give callers a clean
error_class on a system bounce should declare an `OP_ERROR` reply
explicitly in their handler, instead of relying on the TVM
bounce alone. The protocol does not synthesize an `error_class`
from `bounced_by_phase`; that mapping is application policy.

## 6. Account lifecycle

### 6.1 States

The three states from §2.3 are authoritative:

- `account_uninit` — never deployed, or fully evacuated and
  unfunded.
- `account_active` — has code and data and is funded above the
  storage rent threshold.
- `account_frozen` — code and data have been evacuated; only the
  state hash remains. Funds can be deposited; the account becomes
  active again only when a message carrying a matching StateInit
  arrives.

### 6.2 Inbound message handling

| State | Inbound handling | Bounce? |
|---|---|---|
| uninit, no StateInit in msg | Skip compute. | Yes, `bounced_by_phase=0`, `exit_code=-1`. |
| uninit, StateInit in msg with correct deploy address | Deploy + execute. | Bounce only on compute/action failure. |
| active | Execute. | Bounce on compute/action failure. |
| frozen, no StateInit | Skip compute. | Yes, `bounced_by_phase=0`, `exit_code=-1`. |
| frozen, StateInit with mismatching hash | Skip compute. | Yes, `bounced_by_phase=0`, `exit_code=-2`. |
| frozen, StateInit with matching hash | Unfreeze, execute. | Bounce on compute/action failure. |
| suspended (config-controlled) | Skip compute. | Yes, `bounced_by_phase=0`, `exit_code=-4`. |

### 6.3 Lifecycle transitions visible to senders

Senders may observe these transitions only through bounce
delivery. The protocol does not synthesize "your peer is now
frozen" notifications; that is a future feature
(`actor.md` §5.7 cross-shard delivery SLA).

### 6.4 Scheduled and in-flight messages

For the future scheduled-message feature (`actor.md` §5.2), the
following rules are pre-locked here so that Slice 1 envelope
choices remain compatible:

- A scheduled message addressed to an account that is `frozen`
  or absent at delivery time follows the same rules as an
  immediate message: it bounces with `exit_code = -1` or `-2`.
- A scheduled message whose sender no longer exists at delivery
  time is delivered normally; the bounce, if any, is dead-lettered
  per `actor.md` §5.7 (also a future slice).
- Cancellation of a scheduled message before delivery is allowed
  only by the original sender, while it still exists.

## 7. Bounce budgeting

### 7.1 Who pays

The original sender pays. The bounce delivery cost
(`fwd_fee` for the bounce + the receiver's `on_bounce` compute
cost) is reserved out of the message's `value` at send time.

### 7.2 Reservation rule

A sender producing a message with `bounce=true` and `extra_flags &
1` must reserve at least:

```
required_reserve = fwd_fee_estimate(new_bounce_body_size)
                 + minimum_bounce_compute_gas
```

If the receiver's `on_bounce` consumes more than the reserve, the
bounce drops at the action phase. The protocol does not produce
second-degree bounces; this matches the existing TVM rule that
bounced messages cannot themselves bounce.

### 7.3 Forced-bounce and amplification protection

This policy commits to two anti-amplification rules:

- A bounced message must have `bounce=false` and `bounced=true`,
  matching the TVM convention.
- The protocol must not synthesize a bounce-of-a-bounce.
  Application-layer error replies (`OP_ERROR`) are sent by user
  code, and application authors must not chain them
  recursively.

Restart-storm protection at higher levels — the supervision
restart-intensity rule from `actor.md` §6.4 — depends on this
policy's bounce-budget rule and can be implemented on top of it
without further envelope changes.

## 8. Upgrade and migration policy

### 8.1 Compatibility commitments

This policy commits, in writing, to the following:

- The TL-B schema for `CommonMsgInfo` and `int_msg_info$0` will
  not change in any backward-incompatible way as a result of
  Slice 1.
- Existing TEP-74 (Jetton), TEP-62 (NFT), and wallet-vN message
  formats will continue to be valid bit-for-bit.
- Existing op codes will not be reassigned.
- Slice 1 introduces no new TVM opcode and no new bounce-body
  format. Slice 1 is purely an envelope-discipline and
  Tol-stdlib release.

### 8.2 Activation steps for an existing contract

A contract author who wants to opt into the new envelope
discipline goes through three opt-ins:

1. **Send v12 bounces.** Set `extra_flags & 1` on outbound
   messages. Already available; not new in Slice 1.
2. **Use the standard envelope library.** Replace hand-rolled
   `opcode` / `query_id` parsing with the Tol-stdlib
   `Envelope` struct delivered in Slice 1 Stage 2.
3. **Use structured errors.** Replace ad-hoc error replies with
   the `OP_ERROR` reply shape and `error_class` enum from §5.

Each step is independent. A contract may take step 1 only, or
steps 1+2, without taking 3.

### 8.3 Activation steps for a new contract

New contracts written in Tol against the Slice 1 stdlib pick up
all three steps automatically.

## 9. Compatibility with TEP-style standards

This policy formalizes the body shape that TEP-style standards
already use, and adds the `OP_ERROR` reply convention as a
non-breaking extension.

### 9.1 Jetton (TEP-74)

The standard `transfer`, `transfer_notification`, `excesses`,
`internal_transfer`, and `burn` opcodes use the
`opcode:uint32 query_id:uint64 ...` layout from §3.1 unchanged.
A Jetton-wallet contract migrated to the Slice 1 envelope library
sends and receives the same wire bytes as before.

### 9.2 NFT (TEP-62)

The standard `transfer`, `ownership_assigned`,
`get_static_data`, `report_static_data`, and related opcodes use
the same layout. Migrated NFT contracts emit the same wire bytes
as before.

### 9.3 Wallet-vN

Wallet contracts receive external messages, which are not
governed by this policy. Outbound internal messages from wallet
contracts already follow the `opcode:uint32 query_id:uint64 ...`
layout (with `opcode = 0` text comments allowed) and remain
compatible.

### 9.4 TEP allocations

This policy does not allocate new TEP numbers. The `OP_ERROR`
opcode, `error_class` enum, and `Envelope` library are documented
here as TOS-internal until they are promoted through the standard
TEP allocation process.

## 10. Constraints on Slice 1 implementation

The following items are the implementable subset of this policy.
Items outside this list are deferred to later slices regardless
of how clearly the policy describes them.

### 10.1 In Slice 1

- Reservation of `extra_flags` bits 2 and 3 (no semantic effect
  yet; `extra_flags & 12` remains illegal to set on send).
- Tol-stdlib `Envelope` type with auto-derived pack/unpack for
  the `opcode:uint32 query_id:uint64 payload:...` layout.
- Tol-stdlib `Error` type and `OP_ERROR` reply helper, using
  the `error_class` enum from §5.3.
- Tol compiler pass enforcing `query_id` propagation.
- Conformance fixtures for the bounce-handling rules in §6.2.
- Migration of at least two reference contracts (recommended:
  wallet-v5 and the simplest Jetton wallet).
- External RFC announcing the `Envelope`, `Error`, and
  `OP_ERROR` conventions.

### 10.2 Not in Slice 1

- Activation of `extra_flags & 4` to carry an inline error class
  in the v12 bounce body. Deferred to Slice 4 or later.
- Activation of `extra_flags & 8` for supervision links.
  Deferred to Slice 6.
- Scheduled-message protocol primitive (`actor.md` §5.2).
- Cross-shard delivery SLA and dead-letter handling
  (`actor.md` §5.7).
- Capability-based authorization (`actor.md` §5.4).
- High-level Tol syntax (`contract` / `receive(...)` /
  `message`). That is Slice 2.

## 11. Open questions

The following items are explicitly left open and must be resolved
in a follow-up before they affect Slice 1 implementation.

1. Should `error_class` value `5` ("rate limit / back-pressure")
   be reserved now, even though the back-pressure mechanism is
   not in Slice 1? Reserving avoids a future renumber.
2. Should the Tol-stdlib `Envelope` type optionally carry a
   `created_at` and `created_lt` snapshot from `CommonMsgInfo`
   into the user-visible struct, or expose them only via separate
   helpers? Affects the size of user-facing types.
3. Does the `query_id = 0` "no correlation" convention conflict
   with any existing wallet-vN pattern that uses zero for
   simple-transfer comments? Audit before locking.
4. Should `OP_ERROR` carry the original opcode of the failed
   request as a leading field (so the receiver can pair without
   `query_id` lookup)? Add as a field if yes.

These do not block Stage 0 sign-off, but they must be resolved
before Stage 2 begins.

## 12. Sign-off

This document is approved when all four roles below have signed.
Approval means: the listed party agrees to implement the policy
as written for Slice 1, and to escalate any required deviation
through a documented amendment to this file.

| Role | Name | Date |
|---|---|---|
| Protocol architect | | |
| TVM lead | | |
| Tol compiler lead | | |
| Contract-team representative | | |

Amendments after sign-off must update this table and append a
short changelog at the bottom of the file.
