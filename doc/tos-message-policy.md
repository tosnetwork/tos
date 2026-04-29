# TOS Message and Lifecycle Policy

## 0. Status, scope, and references

**Status.** Draft v4 (post-second-review). This document is the policy input for Slice 1 of
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

`block.tlb` declares **two** `int_msg_info$0` constructors, with
identical field layout but different parents:

```
// Inbound — the schema by which the system delivers a message
// to its recipient (line 126):
int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
  src:MsgAddressInt dest:MsgAddressInt
  value:CurrencyCollection extra_flags:(VarUInteger 16) fwd_fee:Tomis
  created_lt:uint64 created_at:uint32 = CommonMsgInfo;

// Outbound — the schema user code (Tol / FunC) constructs when
// sending (line 135). Note the relaxed src type:
int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool
  src:MsgAddress dest:MsgAddressInt
  value:CurrencyCollection extra_flags:(VarUInteger 16) fwd_fee:Tomis
  created_lt:uint64 created_at:uint32 = CommonMsgInfoRelaxed;
```

The two share the wire bit-layout that this policy governs, so every
rule below applies bit-symmetrically to both.

Note the layering, since v3 conflated it: the existing
`createMessage` / message-builder primitives in
`tol/send-message-api.cpp` and the Tol-stdlib are what pack
`CommonMsgInfoRelaxed` on send (and unpack `CommonMsgInfo` on
receive). The Slice 1 `Envelope` type introduced by this policy is
**body-only** — it packs and unpacks the
`(opcode, query_id, payload)` triple defined in §3.1, which sits
inside the message body. `Envelope` does not own the
`CommonMsgInfo*` fields; those remain the responsibility of the
message-builder primitives.

`extra_flags` is the renamed-and-repurposed former `ihr_fee` field.
TVM v12 defines:

- `extra_flags & 1` — enable the new (v12) bounce body format.
- `extra_flags & 2` — when bouncing, return the whole original
  body rather than only the root cell without refs. This bit is
  meaningful only when bit 0 is also set (see §10.1's
  `EXTRA_FLAGS_RICH_BOUNCE` composite constant).
- All higher bits are reserved and must be zero on send. The
  current outbound mask in `crypto/block/transaction.cpp:2948,3632`
  is `extra_flags & 3`, i.e. only bits 0..1 are accepted today;
  bits 2..3 are reserved by this policy for future activation
  (see §3.4).

### 2.2 v12 bounce body

```
// block.tlb:170-175
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

Every **non-comment** internal message body produced through the
Slice 1 `Envelope` library must begin with:

```
opcode:uint32  query_id:uint64  payload:...
```

- `opcode` — application-defined operation identifier. The first
  32 bits of every non-comment body. See §3.2 for the partition.
- `query_id` — 64-bit correlation identifier. See §4.
- `payload` — opcode-specific bits.

The text-comment opcode `0x00000000` is the documented exception
to the layout above and does not carry a `query_id` field; see
§3.2 for the body shape and §4.1 for the corresponding scope of
the `query_id = 0` rule.

This layout is bit-compatible with the TEP-74, TEP-62, and
wallet-vN message conventions already in use, so existing
contracts continue to work without change.

### 3.2 Special opcodes

The full 32-bit `opcode` value partitions the opcode space into
five contiguous ranges:

| Range (32-bit) | Meaning |
|---|---|
| `0x00000000` | text-comment opcode (special-cased; see below) |
| `0x00000001` – `0x000000FF` | reserved for protocol-defined system opcodes (255 slots) |
| `0x00000100` – `0x0000FFFF` | reserved for future ecosystem-wide standards (TEP-style allocations) |
| `0x00010000` – `0x7FFFFFFF` | application-defined |
| `0x80000000` – `0xFFFFFFFF` | high-bit range — see grandfathering note below |

`OP_ERROR = 0x00010001` (§5.2) is reserved by this policy from
the **application-defined** range.

**Enforcement scope.** Restrictions in this section apply only to
**new opcode allocations made through the Slice 1 `Envelope`
library**. The protocol does **not** reject sends with arbitrary
opcodes — doing so would break a non-trivial set of existing
reference contracts. Concretely:

- **Low-system range (`0x00000001`–`0x000000FF`).** The Slice 1
  `Envelope` builder rejects new allocations in this range at
  Tol compile time unless the opcode is enumerated in this
  policy. Hand-rolled FunC code that constructs a body with such
  an opcode continues to work — wire-level validation is
  unchanged.
- **High-bit range (`0x80000000`–`0xFFFFFFFF`).** Some TEP-style
  standards (e.g. excess refund replies) use the high bit to
  mark reply / notification opcodes, but the convention is
  **not** universal. Existing reference contracts already use
  high-bit opcodes outside any TEP, including:
  - `crypto/smartcont/elector-code.fc:169` —
    `0xee6f454c` (`return_stake`).
  - `crypto/smartcont/liquid-staking/op-codes.func:7` —
    `0xee6f454c` (`new_stake_error`).
  - `crypto/smartcont/payment-channel-code.fc:16` —
    `0x912838d1` (`pchan_cmd`).

  A blanket "reject high-bit sends" rule would invalidate these
  contracts. The policy therefore **grandfathers** all existing
  high-bit opcodes; the Slice 1 `Envelope` builder warns (does
  not error) on a fresh high-bit allocation unless the new
  opcode is registered in an approved TEP or enumerated here.
  Future standards may tighten this once the ecosystem-wide
  inventory is complete.

The text-comment slot deserves a special note:

- `0x00000000` — text-comment opcode. The body after the first
  32 bits is interpreted as UTF-8 text. **No `query_id` field is
  present** at the bit-offset 32–96 range; the body shape for this
  opcode is `opcode:uint32 utf8_payload:...`, with no 64-bit
  `query_id` slot. The `query_id = 0` rule of §4.1 therefore does
  not apply to opcode `0x00000000`. This matches existing
  simple-transfer practice across wallet-v3 / wallet-v4 /
  wallet-v5 / DNS / elector / payment-channel / TEP-62 NFT
  contracts (verified during Stage 0 audit).

**Caveat: `0xfffffffe` is dual-purposed.** The TVM v12 bounce-body
constructor tag is `new_bounce_body#fffffffe` (see
`crypto/block/block.tlb:170-175`). Existing reference contracts
(`crypto/smartcont/elector-code.fc:407,414`,
`crypto/smartcont/nominator-pool/pool.fc:19`,
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

**Current v12 enforcement.** Today TVM v12 rejects any `extra_flags`
bit beyond `0..1`. The outbound mask in `crypto/block/transaction.cpp`
is `extra_flags & 3` at both sites cited below. Bits 2 and 3 are
reserved by this policy but **currently invalid to set** — sending
an internal message with `extra_flags & 12 != 0` triggers
`check_skip_invalid(45)`. They become legal only when the
corresponding slice (Slice 4 for bit 2, Slice 6 for bit 3) widens
the mask in lockstep.

**Synchronized constants.** The `extra_flags` mask is hard-coded
in three locations today:

- `crypto/block/transaction.cpp:2948` (action-phase outbound
  check, `& td::make_refint(3)`).
- `crypto/block/transaction.cpp:3632` (`prepare_bounce_phase`
  outbound builder, `& td::make_refint(3)`).
- `tol/send-message-api.cpp:307-342` (`BounceMode` enum mapping,
  magic literals `1`, `2`, and `3`).

Slice 1 must lift the magic literals into named stdlib constants
(`EXTRA_FLAGS_NEW_BOUNCE = 1`, `EXTRA_FLAGS_FULL_BOUNCE_BODY = 2`,
and the composite `EXTRA_FLAGS_RICH_BOUNCE = 3` defined in §10.1)
and label all three sites as synchronized constants. When Slice 4
activates bit 2 (or Slice 6 activates bit 3), the same change must
land in lockstep at:

1. Both `& td::make_refint(3)` masks in `crypto/block/transaction.cpp`
   — widen to `& 7` (Slice 4) or `& 15` (Slice 6).
2. The Tol-stdlib `EXTRA_FLAGS_VALID_MASK` constant introduced in
   Slice 1 alongside the named bit constants.
3. The Slice-1 conformance fixtures that assert
   `extra_flags=0b0100` is rejected (§10.1) — they must be updated
   to assert acceptance under the new mask.

A Slice 4/6 PR that touches only one of these three sites is a
hardening violation; the production-hardening script
(`scripts/check-evm-production-hardening.sh` or its message-policy
analogue) must grep for divergence between them.

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

A reply message is any message whose `(src, body.query_id)` pair
matches an outstanding request the recipient sent earlier.
**The outstanding-request table key must include the expected
responder's address**; matching by `query_id` alone allows a
third address to forge a reply that collides on `query_id`.

The minimum-required key is therefore:

```
key = (expected_responder, query_id)
```

Slice 1 `Envelope` reply-helpers store and lookup against this
two-element key. A stronger three-element form is recommended
when the contract issues different request opcodes to the same
peer concurrently:

```
key = (expected_responder, expected_reply_opcode, query_id)
```

The `expected_reply_opcode` matches against either the inbound
opcode or, for `OP_ERROR` replies, the `original_op` field from
§5.2. The two-element form is the floor; `original_op` is a
**discriminator within** an `(expected_responder, query_id)`
pairing, not a substitute for the responder binding.

The recipient pairs replies by lookup in its local
outstanding-request table. Tol's `pipe-check-*` pass added
in Slice 1 Stage 2 enforces that:

- Every handler that returns a reply propagates the inbound
  `query_id` (or explicitly disclaims it via the
  `disclaim_query_id()` stdlib helper, shipped together with the
  check pass).
- Every send-with-reply call produces a `query_id` and reserves a
  table slot.

The check pass file is
`tol/pipe-check-query-id-propagation.cpp`. Two constraints fix the
injection point in `tol/tol.cpp`:

1. **AST shape constraint.** The pass must run before
   `pipeline_transform_onInternalMessage()` (currently
   `tol/tol.cpp:105`), because the transform rewrites the
   `in: InMessage` parameter into opaque aux nodes that the check
   can no longer reason about.
2. **Error-reporting constraint.** §10.1 specifies the pass uses
   `error_collector.collect()`, not `.fire()` (warnings, not
   compile errors). However, `tol/tol.cpp:102` runs
   `G.error_collector = nullptr;` — any pass injected after that
   line will dereference a null `error_collector` and crash. The
   pass therefore must run **before line 102**, in the band
   between `pipeline_check_serialized_fields()` (line 83) and the
   error-collector teardown.

The intersection of (1) and (2) leaves a single safe band:
**after `pipeline_check_serialized_fields()` (line 83) and before
`G.error_collector = nullptr;` (line 102)**. The
`pipeline_lazy_load_insertions()` and
`pipeline_transform_onInternalMessage()` calls at lines 104–105
are downstream of the teardown and are not valid injection
points. The Slice 1 hardening script must assert that the new
pass appears in `tol/tol.cpp` between the two anchor lines and
not after the teardown.

Slice 1 ships the pass and the `disclaim_query_id()` builtin in
the same PR; without the disclaimer, every legitimate
fire-and-forget contract would warn.

## 5. Error classification

### 5.1 Two-tier error model

TOS errors are reported on two layers:

- **System tier** — already in the v12 bounce body:
  `bounced_by_phase` and `exit_code`. Owned by the protocol;
  applications cannot extend it.
- **Application tier** — defined here, carried in the message
  body of failure replies. A future bounce-body schema bump (see
  §5.4) may also expose `error_class` directly in the bounce
  body; toggling `extra_flags` bit 2 alone is not sufficient
  because the current `NewBounceBody` has no field for it.
  Owned by the application; the protocol does not interpret it.

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
`error_class` on a system bounce should declare an `OP_ERROR`
reply explicitly in their handler, instead of relying on the TVM
bounce alone. The protocol does not synthesize an `error_class`
from `bounced_by_phase`; that mapping is application policy.

**Future inline error_class in the bounce body — schema bump
required.** The current `NewBounceBody` schema
(`block.tlb:170-175`, restated in §2.2) has **no** field for an
application-level `error_class`. A future activation that puts
`error_class` into the bounce body itself therefore requires a
**new bounce-body version** (or a dedicated tagged extension
cell), not just toggling `extra_flags` bit 2. The bit alone has
no place to write the value. Slice 4 (or whichever later slice
takes this on) must therefore ship:

1. A new TL-B constructor — e.g.
   `new_bounce_body_v2#fffffffd ... error_class:uint8 ...
   = NewBounceBody;` — defined in `block.tlb`.
2. A global-version bump (`global_version >= N`) gating the
   constructor's acceptance, parallel to how v12 gated the
   current `new_bounce_body#fffffffe`.
3. The §3.4 mask-widening change synchronized with all three
   `extra_flags` sites.
4. Updated `prepare_bounce_phase()` in `crypto/block/transaction.cpp`
   to populate the new field.

The §3.4 reservation of `extra_flags` bit 2 is necessary but not
sufficient for this feature.

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

The "Bounce?" column below applies only when **the inbound
message has `bounce=true` AND the message's remaining value
covers the bounce's forwarding fee**. Either condition false ⇒
no bounce is produced. Source: `bounce_enabled = in_msg_info.bounce`
at `crypto/block/transaction.cpp:921`; `prepare_bounce_phase()`
returns false at `transaction.cpp:3522` when `!bounce_enabled`;
when funds do not cover `fwd_fee` the bounce phase records
`bp.nofunds = true` and no bounce message leaves the recipient
(`transaction.cpp:3608`).

| State | Inbound handling | Bounce (only if inbound `bounce=true` AND value ≥ `fwd_fee`)? |
|---|---|---|
| uninit, no StateInit in msg | Skip compute. | Yes, `bounced_by_phase=0`, `exit_code=-1`. |
| uninit, StateInit in msg with correct deploy address | Deploy + execute. | Bounce only on compute/action failure. |
| active | Execute. | Bounce on compute/action failure. |
| frozen, no StateInit | Skip compute. | Yes, `bounced_by_phase=0`, `exit_code=-1`. |
| frozen, StateInit with mismatching hash | Skip compute. | Yes, `bounced_by_phase=0`, `exit_code=-2`. |
| frozen, StateInit with matching hash | Unfreeze, execute. | Bounce on compute/action failure. |
| suspended (config-controlled) | Skip compute. | Yes, `bounced_by_phase=0`, `exit_code=-4`. |

If `bounce=false` was set on the inbound message, none of the
"Yes" rows produce a bounce. Value handling follows the normal
non-bounceable transaction flow and may still credit the
recipient account. Senders must not use `bounce=false` when they
need failure signalling or value return.

If `bounce=true` but value is insufficient (`bp.nofunds = true`),
no bounce is produced either. Senders that depend on bounce
delivery for error signalling must size `value` to cover at
least the v12 bounce-message forwarding fee.

The above table partitions by **account state**. Orthogonal to it,
`exit_code = -3` (insufficient gas to enter the compute phase) can
be returned for **any** "Execute" / "Deploy + execute" /
"Unfreeze, execute" row when the inbound `value` does not cover
the storage rent + minimum compute gas. The bounce shape is the
same as the other compute-skipped cases:
`bounced_by_phase = 0`, `exit_code = -3`. Senders that intend to
deploy or unfreeze a peer must size `value` accordingly.

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
  immediate message: if `bounce=true` and funds cover the bounce
  forwarding fee, it bounces with `exit_code = -1` or `-2`;
  otherwise no bounce is produced.
- A scheduled message whose sender no longer exists at delivery
  time is delivered normally; the bounce, if any, is dead-lettered
  per `actor.md` §5.7 (also a future slice).
- Cancellation of a scheduled message before delivery is allowed
  only by the original sender, while it still exists.

## 7. Bounce budgeting

### 7.1 Current TVM behaviour (Slice 1 baseline)

The original sender's message `value` covers all costs
downstream. There is **no reservation of receiver-side bounce
compute gas at send time**. Specifically, when the recipient's
transaction reaches `prepare_bounce_phase()`:

1. The bounce-message forwarding fee `bp.fwd_fees` is computed
   from the bounce-message size (cells + bits) using
   `msg_prices.compute_fwd_fees(...)`
   (`crypto/block/transaction.cpp:3598`).
2. `msg_balance_remaining` is reduced by the recipient's
   compute-phase gas fee and any action-phase fine.
3. If the resulting balance does not cover `bp.fwd_fees`, the
   bounce phase records `bp.nofunds = true` and **no bounce
   message leaves the recipient** (`transaction.cpp:3608`).

Slice 1 is wire-compatible with this behaviour. The Tol-stdlib
helper for sizing `value` on outbound bounce-bearing messages
must therefore use `fwd_fee_estimate(new_bounce_body_size)` —
not include a `minimum_bounce_compute_gas` term — and this is
how the helper is specified.

### 7.2 Sender sizing rule (Slice 1)

A sender producing a message with `bounce=true` and `extra_flags
& EXTRA_FLAGS_NEW_BOUNCE` should size `value` to at least:

```
recommended_value ≥ recipient_storage_rent
                  + recipient_compute_floor   // see exit_code -3 in §6.2
                  + fwd_fee_estimate(new_bounce_body_size)
                    // covers the bounce trip back to the sender
```

`fwd_fee_estimate(new_bounce_body_size)` is the only term that
the protocol enforces today via `bp.nofunds`. The other two are
**recommendations** so that the recipient's transaction does not
trip `exit_code = -3` (no gas) before the inbound is even
delivered. None of the three terms is the receiver's
`onBouncedMessage` compute gas — the protocol does not reserve
that today.

### 7.3 Future: reserved bounce-compute budget (NOT in Slice 1)

A future protocol change could reserve a fixed
`minimum_bounce_compute_gas` from the sender's `value` so the
sender's own `onBouncedMessage` is guaranteed to run. This is
**not** part of Slice 1 and is **not** wire-compatible with the
current `bp.nofunds` flag — adding it requires either:

- a new bounce-body version with an explicit reserved-gas field, or
- a new `extra_flags` bit (e.g. bit 4) that signals the reserve.

Either path is a protocol change with a global-version bump. It
must not silently piggy-back on `extra_flags & 2` (full body) or
on the §3.4 reservation of bits 2 and 3.

### 7.4 Forced-bounce and amplification protection

This policy commits to two anti-amplification rules that hold
under both the current §7.1 behaviour and any future §7.3
extension:

- A bounced message must have `bounce=false` and `bounced=true`,
  matching the TVM convention.
- The protocol must not synthesize a bounce-of-a-bounce.
  Application-layer error replies (`OP_ERROR`) are sent by user
  code, and application authors must not chain them
  recursively.

Restart-storm protection at higher levels — the supervision
restart-intensity rule from `actor.md` §6.4 — composes with §7.1
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
  `tol/send-message-api.cpp:307-342` into named stdlib constants:
  - `EXTRA_FLAGS_NEW_BOUNCE = 1` (bit 0 — enable v12 bounce body).
  - `EXTRA_FLAGS_FULL_BOUNCE_BODY = 2` (bit 1 — return full body
    on bounce; meaningful **only** when bit 0 is also set).
  - `EXTRA_FLAGS_RICH_BOUNCE = EXTRA_FLAGS_NEW_BOUNCE |
    EXTRA_FLAGS_FULL_BOUNCE_BODY = 3` — composite constant that
    contract authors should use when they want a v12 bounce that
    carries the whole original body. This is the value emitted by
    `BounceMode::RichBounce` in `tol/send-message-api.cpp`.
    Setting bit 1 alone (`extra_flags = 2`) is accepted by the
    current wire-level mask but has no useful v12 rich-bounce
    semantics because bit 0 is not set. The high-level
    Tol-stdlib `Envelope` / `createMessage` builder must reject
    it at compile time when the value is a literal, and at
    runtime otherwise.
  - `EXTRA_FLAGS_VALID_MASK = 3` — the current-mask constant
    referenced from the synchronized-constants block of §3.4.
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

### Draft v4 (post-second-review)

A second review against the in-tree source caught four core
defects in v3 plus three layering nits. None of the changes
touches the wire format or the §8.1 compatibility commitments.

- **§6.2 (core) — bounce was written as unconditional.** The v3
  table's "Yes" cells implied the system always emits a bounce
  for the listed states. In current TVM, bounce generation
  requires both inbound `bounce=true` and a remaining message
  value covering the bounce-message `fwd_fee`. v4 conditions
  the entire column on those two predicates and cites the
  enforcement points: `bounce_enabled = in_msg_info.bounce` at
  `crypto/block/transaction.cpp:921`, the
  `prepare_bounce_phase()` early return at
  `transaction.cpp:3522`, and the `bp.nofunds = true` path at
  `transaction.cpp:3608`.
- **§7 (core) — bounce budgeting did not match current TVM.**
  v3's `required_reserve = fwd_fee_estimate(...) +
  minimum_bounce_compute_gas` was wrong: the current protocol
  does not reserve receiver-side bounce-compute gas at send
  time. v4 splits §7 into a §7.1 baseline that describes
  current behaviour (only `bp.fwd_fees` is enforced; shortfall
  flips `bp.nofunds`), a §7.2 sender-sizing rule that drops the
  spurious reserve term, and an explicit §7.3 "future
  reserved-budget extension" that flags the requirement as a
  protocol change with a global-version bump — not a Slice 1
  item.
- **§4.4 (core) — reply binding was forgeable.** Binding by
  `query_id` alone allowed any address to reply to a request
  meant for a specific peer. v4 mandates a minimum
  `(expected_responder, query_id)` table key in the
  outstanding-request structure, recommends the three-element
  `(expected_responder, expected_reply_opcode, query_id)` form
  for contracts that issue multiple concurrent request opcodes
  to the same peer, and clarifies that `original_op` is a
  discriminator within an `(expected_responder, query_id)`
  pairing — not a substitute for sender binding.
- **§3.2 (core) — high-bit opcode policy would have broken
  existing contracts.** v3's blanket "implementations must
  reject" was incompatible with high-bit opcodes already in use
  outside any TEP — `0xee6f454c` in `elector-code.fc:169` and
  `liquid-staking/op-codes.func:7`, `0x912838d1` in
  `payment-channel-code.fc:16`. v4 grandfathers all existing
  high-bit opcodes wire-side and limits the restriction to
  **new** allocations made through the Slice 1 `Envelope`
  builder. The low-system range (`0x00000001`–`0x000000FF`) is
  similarly limited to compile-time builder rejection.
- **§2.1 (nit) — Envelope vs. message conflation.** v3 said
  `Envelope` "packs against the Relaxed form on send and
  unpacks the strict form on receive". `Envelope` is body-only
  — it packs the `(opcode, query_id, payload)` triple. The
  `CommonMsgInfoRelaxed` packing is owned by the existing
  `createMessage` / message-builder primitives in
  `tol/send-message-api.cpp`. v4 splits the two layers
  explicitly.
- **§5.1 / §5.4 (nit) — bit 2 is a schema bump, not a flag.**
  v3 said activating `extra_flags` bit 2 would put
  `error_class` into the bounce body. The current
  `NewBounceBody` has no field for it. v4 enumerates the four
  changes any future inline-error-class slice has to ship: a
  new TL-B constructor (e.g.
  `new_bounce_body_v2#fffffffd ... error_class:uint8 ...`), a
  global-version gate, the synchronized §3.4 mask widening, and
  the matching `prepare_bounce_phase()` write.
- **§3.1 (nit) — "Every internal message body" conflicted with
  the text-comment exception.** v4 scopes the layout sentence
  to non-comment bodies emitted via the Slice 1 `Envelope`
  library and points back to §3.2 / §4.1 for the
  `0x00000000` exception.

Wire format unchanged; TL-B schema unchanged; §8.1 compatibility
commitments preserved. v4 closes the four sign-off blockers
identified in the second review and tightens three layering
issues.

### Draft v3 (post-source-review)

A line-by-line correctness review against the in-tree source
caught seven defects in v2. None of them changes the wire format,
the TL-B schema, or the §8.1 compatibility commitments; they
tighten under-specified text and fix citation drift.

- **§2.1** previously quoted only the inbound `int_msg_info$0`
  constructor at `block.tlb:126`. The outbound form
  (`= CommonMsgInfoRelaxed`) at `block.tlb:135` is now also
  shown, with a note that the policy applies bit-symmetrically to
  both. The Slice 1 `Envelope` type packs against the Relaxed
  form on send and the strict form on receive.
- **§2.2** corrected the `new_bounce_body#fffffffe` line range
  from `block.tlb:168-175` → `:170-175`.
- **§3.2** rewrote the opcode partition. v2 mixed "first 16
  bits" prefixes with full 32-bit value ranges, which made
  `OP_ERROR = 0x00010001` mathematically fall into both the
  protocol-system range (16-bit prefix `0x0001`) and the
  application-defined range (32-bit value). v3 uses a single
  contiguous 32-bit table; `OP_ERROR` is now unambiguously
  reserved by this policy from the application-defined range.
- **§3.2** corrected the `nominator-pool/pool.fc` citation from
  `:16,19` → `:19`. Line 16 contains `new_stake_error`, not
  `recover_stake_error = 0xfffffffe`.
- **§3.4** replaced the inaccurate "TVM v12 rule that internal
  messages with extra_flags bits beyond `0..3` are invalid" with
  the source-true statement that the current outbound mask in
  `transaction.cpp:2948,3632` is `& 3` (bits 0..1 only). v3
  also makes the Slice 4 / Slice 6 mask-widening obligation
  explicit: both `& td::make_refint(3)` sites in
  `transaction.cpp` plus the Tol-stdlib `EXTRA_FLAGS_VALID_MASK`
  plus the §10.1 conformance fixtures must be updated in lockstep
  when bit 2 (Slice 4) or bit 3 (Slice 6) activates. A hardening
  grep is required to catch divergence.
- **§4.4** tightened the `pipe-check-query-id-propagation.cpp`
  injection point. v2 specified "after
  `pipeline_check_serialized_fields()` and before
  `pipeline_lazy_load_insertions()`", but `tol/tol.cpp:102` runs
  `G.error_collector = nullptr;` between those two anchors. Since
  §10.1 requires the pass to use `error_collector.collect()`,
  injection after line 102 would dereference a null pointer. v3
  pins the safe band to "after line 83 and before line 102",
  i.e. before the error-collector teardown, and requires a
  hardening assertion on the position.
- **§6.2** added a `exit_code = -3` (insufficient gas to enter
  compute) note. The state-partitioned table was fully accurate
  but missed the orthogonal gas-shortage case, which can apply
  to any "Execute" / "Deploy + execute" / "Unfreeze, execute"
  row.
- **§10.1** added the composite `EXTRA_FLAGS_RICH_BOUNCE = 3`
  and `EXTRA_FLAGS_VALID_MASK = 3` constants. The bit-named
  constants in v2 (`EXTRA_FLAGS_NEW_BOUNCE = 1`,
  `EXTRA_FLAGS_FULL_BOUNCE_BODY = 2`) were correct as bit names
  but easy to misuse: bit 1 in isolation has no defined meaning
  in v12 (full-body semantics require bit 0). The composite
  constant is what `BounceMode::RichBounce` actually emits.

Wire format unchanged; TL-B schema unchanged; §8.1 compatibility
commitments preserved. v3 is purely a precision tightening of v2
against the in-tree source and is suitable for sign-off.

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
