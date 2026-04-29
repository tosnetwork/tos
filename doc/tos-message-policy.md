# TOS Message and Lifecycle Policy

## 0. Status, scope, and references

**Status.** Draft v2 (post-Stage-0-audit). This document is the policy input for Slice 1 of
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

- `0x00000000` — text-comment opcode. The body after the first
  32 bits is interpreted as UTF-8 text. **No `query_id` field is
  present** at the bit-offset 32–96 range; the body shape for this
  opcode is `opcode:uint32 utf8_payload:...`, with no 64-bit
  `query_id` slot. The `query_id = 0` rule of §4.1 therefore does
  not apply to opcode `0x00000000`. This matches existing
  simple-transfer practice across wallet-v3 / wallet-v4 /
  wallet-v5 / DNS / elector / payment-channel / TEP-62 NFT
  contracts (verified during Stage 0 audit).
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

**Caveat: `0xfffffffe` is dual-purposed.** The TVM v12 bounce-body
constructor tag is `new_bounce_body#fffffffe` (see
`crypto/block/block.tlb:168-175`). Existing reference contracts
(`crypto/smartcont/elector-code.fc:407,414`,
`crypto/smartcont/nominator-pool/pool.fc:16,19`,
`crypto/smartcont/liquid-staking/op-codes.func:16`) also use
`0xfffffffe` as an *application opcode* (`recover_stake_error`).
This works on the wire because the two are disambiguated by the
`bounced:Bool` flag in `int_msg_info`, not by the body bits.
However, it is fragile: an inbound message with `bounced=false`
carrying body `0xfffffffe` is an application reply, not a system
bounce. Slice 1 stdlib **must emit a Tol compile-time warning**
when a contract sends a non-bounced message whose body opcode
equals `0xfffffffe`, and **must not** allow the Tol-stdlib
`Envelope` type to be constructed with that opcode without an
explicit override.

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

**Synchronized constants.** The `extra_flags` mask is hard-coded
in three locations today:

- `/home/tomi/tos/crypto/block/transaction.cpp:2948` (action-phase
  outbound check, `& 3`).
- `/home/tomi/tos/crypto/block/transaction.cpp:3632`
  (`prepare_bounce_phase` outbound mask, `& 3`).
- `/home/tomi/tos/tol/send-message-api.cpp:307-342`
  (`BounceMode` enum mapping, magic literals `1` and `3`).

Slice 1 must lift the magic literals into named stdlib constants
(suggested names: `EXTRA_FLAGS_NEW_BOUNCE = 1`,
`EXTRA_FLAGS_FULL_BOUNCE_BODY = 2`) and label all three sites as
synchronized constants. When Slice 4 activates bit 2 (or Slice 6
activates bit 3), all three sites must be updated together.

## 4. `query_id` rules

### 4.1 Allocation

- 64-bit, allocated by the **sender** of the request.
- The rules in this section apply only when `opcode != 0x00000000`.
  For the text-comment opcode `0x00000000`, no `query_id` field
  is present in the body (see §3.2).
- A `query_id` of `0` (on a non-zero opcode) denotes "no
  correlation expected": the sender does not require a reply,
  and any contract receiving such a message should treat the
  conversation as one-shot. Stage 0 audit confirmed no existing
  contract emits a non-comment outbound with `query_id = 0`, so
  this rule does not invalidate any current pattern.
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
  `query_id` (or explicitly disclaims it via the
  `disclaim_query_id()` stdlib helper, shipped together with the
  check pass).
- Every send-with-reply call produces a `query_id` and reserves a
  table slot.

The check pass file is
`/home/tomi/tos/tol/pipe-check-query-id-propagation.cpp`
(injection point: in `tol/tol.cpp` immediately after
`pipeline_check_serialized_fields()` and before
`pipeline_lazy_load_insertions()`, while the AST still preserves
the `in: InMessage` parameter — the subsequent
`pipeline_transform_onInternalMessage()` rewrites that parameter
into opaque aux nodes). Slice 1 ships the pass and the
`disclaim_query_id()` builtin in the same PR; without the
disclaimer, every legitimate fire-and-forget contract would warn.

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
original_op:uint32
error_class:uint8
error_code:uint16
diagnostic:(Maybe ^Cell)
```

- `original_op` — the opcode of the inbound request that this
  error reply pairs to. Lets receivers match by
  `(original_op, query_id)` without keeping a per-`query_id`
  shadow correlation table for every outbound opcode they issue.
  Mirrors the v12 system bounce body, which already exposes the
  original opcode at the start of `original_body` (see
  `crypto/smartcont/tol-stdlib/common.tol:1671-1672`). Cost: 4
  bytes per `OP_ERROR` reply.
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
| `5` | Reserved for back-pressure / rate-limit (Slice 5+; not yet emitted) | Yes, with backoff |
| `6`–`15` | Reserved for future expansion | n/a |
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
- Lifting hard-coded `extra_flags` magic numbers in
  `crypto/block/transaction.cpp:2948,3632` and
  `tol/send-message-api.cpp:307-342` into named stdlib constants
  (`EXTRA_FLAGS_NEW_BOUNCE = 1`,
  `EXTRA_FLAGS_FULL_BOUNCE_BODY = 2`).
- Tol-stdlib `Envelope` type with auto-derived pack/unpack for
  the `opcode:uint32 query_id:uint64 payload:...` layout. The
  prefix length is locked to 32 bits (do not allow Tol's
  `PackOpcode` mechanism to use a shorter prefix for envelope
  bodies).
- Tol-stdlib `Error` type and `OP_ERROR` reply helper carrying
  `(query_id, original_op, error_class, error_code, diagnostic)`,
  using the `error_class` enum from §5.3.
- Tol-stdlib `disclaim_query_id()` builtin so the §4.4 check pass
  can be silenced for legitimate fire-and-forget handlers.
  Shipped in the same PR as the check pass.
- Tol compiler pass `pipe-check-query-id-propagation.cpp`
  enforcing `query_id` propagation, in warning mode (uses
  `error_collector.collect()`, not `.fire()`).
- Tol compiler warning when a non-bounced send carries body
  opcode `0xfffffffe` (the v12 bounce-body tag).
- Conformance fixtures for the bounce-handling rules in §6.2,
  including the four `bounced_by_phase` cases (skip / compute /
  action) and an `extra_flags=0b0100` rejection case.
- Migration of at least two reference contracts. Recommended
  migration order from Stage 0 audit:
  1. **jetton-minter** (smallest, paired with jetton-wallet,
     ~45 LOC touched).
  2. **jetton-wallet** (~80 LOC, exercises the bounce-handler
     delta).
  3. **wallet-v5** (~110 LOC, 16 errors to classify into
     `error_class` values).
- External RFC announcing the `Envelope`, `Error`, and
  `OP_ERROR` conventions, plus the `0xfffffffe` collision caveat.

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

## 11. Open questions (resolved in v2)

The four questions raised in v1 were resolved during the Stage 0
audit. The decisions are captured in the body of the policy; this
section retains the questions and the chosen answers for traceability.

1. *(v1)* Should `error_class` value `5` be reserved now for
   back-pressure / rate-limit? — **Resolved: yes.** See §5.3
   table; `5` is now documented as "Reserved for back-pressure /
   rate-limit (Slice 5+; not yet emitted)". This is a
   document-level reservation; no wire format changes. **Confidence: high.**
2. *(v1)* Should `Envelope` carry `created_at` / `created_lt`?
   — **Resolved: no.** Those fields belong to `CommonMsgInfo`
   (transport layer), not the application-layer body that
   `Envelope` covers. They remain on `InMessage` /
   `InMessageBounced` (`crypto/smartcont/tol-stdlib/common.tol:1913,1934`).
   `Envelope` stays a tight `(opcode, query_id, payload)` triple.
   **Confidence: high.**
3. *(v1)* Does `query_id = 0` conflict with simple-transfer
   patterns? — **Resolved: no conflict.** Stage 0 TEP audit
   verified that text-comment opcode `0x00000000` does not
   carry a `query_id` field at all (no `load_uint(64)` on the
   `op==0` branch in any reviewed contract: wallet-v3/v4/v5,
   DNS, elector, payment-channel, TEP-62 NFT). §3.2 has been
   tightened to make this offset rule explicit. §4.1 has been
   updated to scope `query_id = 0` to opcodes other than
   `0x00000000`. **Confidence: high.**
4. *(v1)* Should `OP_ERROR` carry `original_op`? — **Resolved:
   yes, added.** See §5.2; `original_op:uint32` follows
   `query_id`. The 4-byte cost is justified by symmetry with the
   v12 bounce body (which already exposes the original opcode at
   `original_body` start) and avoids forcing every requesting
   contract to keep a per-`query_id` shadow correlation table.
   **Confidence: medium** — if the contract-team representative
   pushes back during sign-off (e.g. "we already keep correlation
   tables, the field is redundant"), revisit.

There are no v2-introduced open questions. Stage 1 implementation
may begin after §12 sign-off.

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

## 13. Changelog

### Draft v2 (post-Stage-0 audit)

Stage 0 audit completed by five parallel research agents (audit
reports archived at `/tmp/agent-a{1..5}-report.md`). Changes
incorporated into this draft:

- **§3.2** clarified that opcode `0x00000000` carries no
  `query_id` field at all (was previously self-contradictory:
  said `query_id` "set to zero" while no such field exists on
  the wire). Resolves §11.3 with high confidence (A1 audit).
- **§3.2** added the `0xfffffffe` dual-purpose caveat: the v12
  bounce-body constructor tag collides with the existing
  `recover_stake_error` application opcode in `elector-code.fc`
  and `nominator-pool/pool.fc`. Slice 1 stdlib must warn on
  non-bounced sends carrying body opcode `0xfffffffe` (A2 audit).
- **§3.4** added the synchronized-constants requirement:
  `extra_flags` mask is hard-coded in three sites
  (`crypto/block/transaction.cpp:2948`,
  `crypto/block/transaction.cpp:3632`,
  `tol/send-message-api.cpp:307-342`). Slice 1 lifts these into
  named stdlib constants so Slice 4 bit-2 activation is one-line
  (A2 audit).
- **§4.1** scoped the `query_id = 0` rule to non-zero opcodes
  only, removing the implicit conflict with text-comment
  bodies (A1, A4 Q3).
- **§4.4** added the injection point for the new
  `pipe-check-query-id-propagation.cpp` pass and the requirement
  that `disclaim_query_id()` ship in the same PR (A3 audit).
- **§5.2** added `original_op:uint32` field to `OP_ERROR` body
  layout, between `query_id` and `error_class`, with rationale
  pointing at the v12 bounce body's existing original-opcode
  exposure (A4 Q4, medium confidence).
- **§5.3** promoted `error_class = 5` from "Reserved for future
  expansion" to "Reserved for back-pressure / rate-limit
  (Slice 5+; not yet emitted)" (A4 Q1, high confidence).
- **§10.1** expanded Slice 1 in-scope list with concrete items
  surfaced by the audit: lifting magic numbers, locking
  `Envelope` prefix length to 32 bits, `disclaim_query_id()`
  builtin, `0xfffffffe` Tol compiler warning, conformance
  fixtures for v12 `bounced_by_phase` cases, and the
  recommended jetton-minter → jetton-wallet → wallet-v5
  migration order (A2, A3, A5).
- **§11** marked all four questions resolved with their answers,
  evidence pointers, and confidence levels.

Wire format unchanged; TL-B schema unchanged; §8.1 compatibility
commitments preserved. v2 is purely an audit-driven tightening
of v1.

### Draft v1

Initial draft. Authored as Stage 0 input for `doc/roadmap.md`
Slice 1.
