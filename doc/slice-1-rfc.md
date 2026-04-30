# TOS Slice 1 — External RFC

## §0. Status and scope

**Status.** External RFC, dated 2026-04-30. Companion announcement to
Slice 1 of the actor-layer roadmap. Governance: single-signer
(authorized owner of record per
[`doc/tos-message-policy.md`](tos-message-policy.md) §12.1 — i.e.
the operational mode in which one engineer holds the four functional
roles — Protocol architect, TVM lead, Tol compiler lead, and
contract-team representative — under one signature for the duration of
TOS's single-engineer phase). Slice 1 ships on the `actor-layer`
branch.

This document is the **external** announcement of Slice 1. The
contract-author migration playbook lives at
[`doc/tos-message-envelope-migration.md`](tos-message-envelope-migration.md);
the wire-and-lifecycle policy that Slice 1 implements lives at
[`doc/tos-message-policy.md`](tos-message-policy.md). The roadmap that
sequences the work lives at [`doc/roadmap.md`](roadmap.md).

**What Slice 1 ships.**

- A Tol-stdlib `Envelope` type covering the
  `opcode:uint32 query_id:uint64 payload:...` body layout that
  TEP-style contracts already use.
- A Tol-stdlib `Error` type and `OP_ERROR = 0x00010001` reply helper
  carrying `(query_id, original_op, error_class, error_code,
  diagnostic)`.
- A Tol compile-time check pass
  (`tol/pipe-check-query-id-propagation.cpp`) that warns when an
  inbound `query_id` is dropped without an explicit
  `disclaim_query_id()`.
- Named `extra_flags` constants
  (`EXTRA_FLAGS_NEW_BOUNCE`, `EXTRA_FLAGS_FULL_BOUNCE_BODY`,
  `EXTRA_FLAGS_RICH_BOUNCE`, `EXTRA_FLAGS_VALID_MASK`) replacing the
  three hard-coded `& 3` magic literals in
  `crypto/block/transaction.cpp` and `tol/send-message-api.cpp`. The
  mask itself stays at `& 3`.
- Three reference-contract migrations: `jetton-minter`,
  `jetton-wallet`, and `wallet-v5`, each rewritten in Tol against the
  new stdlib while keeping its FunC source in place as the canonical
  compatibility reference.
- Slice 1 conformance fixtures and a deterministic
  `Envelope` / `OP_ERROR` fuzz smoke wired into CI.

**What Slice 1 does *not* ship.**

- No wire-format change. The TL-B schema in `crypto/block/block.tlb`
  is untouched.
- No new TVM opcode.
- No new bounce-body constructor; `new_bounce_body#fffffffe` from
  TVM v12 is the only bounce body recognised on the wire.
- No high-level Tol syntax keywords (`contract`, `receive(...)`,
  `message`). Those are Slice 2.
- No activation of `extra_flags` bits 2 or 3. Both remain reserved
  and currently invalid to set on send.
- No new TEP allocation. `OP_ERROR`, `Envelope`, and `error_class`
  are documented as TOS-internal until promoted through the standard
  TEP process.

## §1. What changes for an external contract author

Slice 1 is opt-in per contract. The migration path mirrors policy
§8.2 — three independent steps:

1. **Send v12 bounces.** Set `extra_flags & 1` on outbound messages
   (i.e. `EXTRA_FLAGS_NEW_BOUNCE`). This is already available on the
   wire today and predates Slice 1; nothing about it changes.
2. **Adopt the Tol-stdlib `Envelope` library.** Replace hand-rolled
   `opcode` / `query_id` parsing with the `Envelope` type and
   `lazy <Struct>.fromSlice(...)` parser pattern shipped in Slice 1
   Stage 2. Existing FunC contracts remain valid — `Envelope` is a
   Tol-side ergonomic improvement, not a wire requirement.
3. **Replace ad-hoc error replies with `OP_ERROR`.** Use the
   stdlib `Error` and `ErrorClass` types in place of bespoke
   "error reply" opcodes when the contract chooses to report
   structured failure to its caller.

Each step is independent. A contract may take only step 1, or steps
1 and 2 without 3, or all three. New contracts written from scratch
in Tol against the Slice 1 stdlib pick up all three automatically.

**Existing FunC contracts continue to work bit-for-bit.** Slice 1
does not require any FunC contract to be redeployed. The migration
of the three reference contracts in §5 is a Tol-side ergonomic
rewrite over the same wire bytes; the FunC source files remain in
the tree as the canonical compatibility witnesses.

## §2. The §8.1 commitment, called out explicitly

The four `tos-message-policy.md` §8.1 compatibility commitments,
quoted verbatim:

> - The TL-B schema for `CommonMsgInfo` and `int_msg_info$0` will
>   not change in any backward-incompatible way as a result of
>   Slice 1.
> - Existing TEP-74 (Jetton), TEP-62 (NFT), and wallet-vN message
>   formats will continue to be valid bit-for-bit.
> - Existing op codes will not be reassigned.
> - Slice 1 introduces no new TVM opcode and no new bounce-body
>   format. Slice 1 is purely an envelope-discipline and
>   Tol-stdlib release.

What this means concretely for an external author:

- A Jetton, NFT, or wallet-vN contract deployed today continues to
  send and receive the same body bytes after the network has Slice
  1 deployed. A signed wallet external message still hashes the
  same. A Jetton transfer notification still carries the same bits
  in the same order.
- An opcode previously assigned for an application purpose will
  not be reassigned by Slice 1. The Slice 1 `OP_ERROR` opcode
  `0x00010001` is allocated fresh from the application-defined
  range (see policy §3.2); it does not collide with any existing
  TEP-style allocation.
- The TL-B schema in `crypto/block/block.tlb` is unchanged. No
  client tool, indexer, or off-chain parser needs to relearn the
  envelope.
- The bounce-body schema is unchanged: `new_bounce_body#fffffffe`
  remains the only bounce-body constructor.

## §3. Envelope, Error, OP_ERROR — the new vocabulary

Three Tol-stdlib types are introduced. Each is a thin abstraction
over an existing wire shape.

### Envelope

`Envelope` packs and unpacks the canonical body layout from policy
§3.1: `opcode:uint32 query_id:uint64 payload:...`. The type is
**body-only** — it does not own `CommonMsgInfo` fields (destination,
value, fees, timestamps, bounce flags, `extra_flags`); those remain
the responsibility of the existing `createMessage` /
message-builder primitives in `tol/send-message-api.cpp`. The
prefix length is locked at 32 bits so envelope bodies always begin
with the canonical opcode word. See policy §3.1 for the formal
spec.

### Error and ErrorClass

`Error` carries the `OP_ERROR` reply payload:
`(query_id, original_op, error_class, error_code, diagnostic)`.
`ErrorClass` is the enum from policy §5.3 — the application-tier
distinction between transient, permanent, authorization, protocol,
and back-pressure failures. See policy §5.2 and §5.3 for field
definitions and class semantics.

### OP_ERROR

`OP_ERROR = 0x00010001` is reserved by the policy from the
application-defined opcode range. A contract that wants to give its
caller a structured failure reply emits an `OP_ERROR` body via the
stdlib helper. The protocol does not synthesize `OP_ERROR` from a
system bounce; that mapping is application policy. Contracts that
do not opt into Slice 1 continue to use whatever error-reply
convention they used before. See policy §5.2 for the formal body
shape and §5.4 for the relationship to v12 system bounces.

## §4. The 0xfffffffe collision caveat

The TVM v12 bounce-body constructor tag is `new_bounce_body#fffffffe`
(see `crypto/block/block.tlb:170-175`). Several existing reference
contracts use the same numeric value `0xfffffffe` as an *application
opcode* (`recover_stake_error`):

- `crypto/smartcont/elector-code.fc:407,414`
- `crypto/smartcont/nominator-pool/pool.fc:19`
- `crypto/smartcont/liquid-staking/op-codes.func:16`

This works on the wire because the bounce body and the application
body are disambiguated by the `bounced:Bool` flag in
`int_msg_info`, not by the opcode bits. The collision is fragile
but harmless for the existing contracts.

**Guidance for external authors.** Quoted from policy §3.2:

> Slice 1 stdlib **must emit a Tol compile-time warning** when a
> contract sends a non-bounced message whose body opcode equals
> `0xfffffffe`, and **must not** allow the Tol-stdlib `Envelope`
> type to be constructed with that opcode without an explicit
> override.

In practice:

- **Do not mint a new application opcode at `0xfffffffe`.** New
  contracts should pick any other 32-bit value. If you find
  yourself wanting to override the warning, that is almost
  certainly a sign the design wants a different opcode.
- The three contracts above are **grandfathered**. Their existing
  behaviour is preserved bit-for-bit; the warning is for new
  allocations only.
- The Tol stdlib emits a compile-time warning if a contract reaches
  a non-bounced send with body opcode `0xfffffffe`. Treat the
  warning as load-bearing.

## §5. Reference migrations

Slice 1 ships three reference migrations, in the audit-driven order
from policy §10.1 (smallest delta first, so the playbook
accumulates confidence before the largest contract):

| Contract | FunC cells | Tol cells | Ratio | §10.1 budget |
|---|---:|---:|---:|---|
| `jetton-minter` | 11 | 9 | 0.82 | within ≤ 15% |
| `jetton-wallet` | 17 | 10 | 0.59 | within ≤ 15% |
| `wallet-v5` | 20 | 22 | 1.10 | within ≤ 15% |

The §10.1 ≤ 15% bytecode-size budget allows a Tol migration to add
up to 15% over the FunC baseline. All three migrations are within
budget; the two Jetton contracts are well below baseline thanks to
the auto-derived `Envelope` parser.

For the per-contract migration playbook — what to record before
writing Tol, how to choose `createMessage` vs. raw builders, the
`error_class` assignment table, the wallet-vN special case, and
the review checklist — see
[`doc/tos-message-envelope-migration.md`](tos-message-envelope-migration.md).
That document is the contract-author handbook; this RFC is the
external announcement.

A short note on what each migration demonstrates:

- **`jetton-minter`** establishes the basic `Envelope` + `OP_ERROR`
  rewrite pattern over a small TEP-74 surface (mint, change-admin,
  change-content, claim-jetton-from-jetton-minter). Three
  tol-tester cases cover positive, auth-fail, and unknown-opcode
  paths.
- **`jetton-wallet`** is the first migration that exercises the
  bounce-handler delta: `onBouncedMessage` parsing the bounced-body
  prefix and `original_op` to drive a recovery action. Three
  tol-tester cases cover positive, auth-fail, and protocol-fail
  paths.
- **`wallet-v5`** preserves the wallet-v5 signed external/internal
  request bodies and C5 action-list validation per policy §9.3
  (wallet external messages are outside the §3.1 envelope by
  design) while classifying all 16 FunC throw sites into §5.3
  `error_class` values. Three tol-tester cases cover positive,
  error-map, and protocol-fail paths.

The FunC source for each of the three contracts remains in the tree
unchanged. The Tol migration is a sibling reference, not a
replacement.

## §6. Compatibility and rollback

**Compatibility.** A network running Slice 1 produces and accepts
the same internal-message bytes as one not running Slice 1. The
TL-B schema in `crypto/block/block.tlb` is unchanged. Existing
indexers, wallet integrations, exchange deposits, and bridge
relayers do not need to relearn the envelope. New contracts may
freely take advantage of `Envelope`, `Error`, and `OP_ERROR`; old
contracts continue to work without change.

**Per-contract rollback.** Because the migration is opt-in per
contract and changes no wire bytes, rolling back a Slice 1
migration is a redeploy of the original FunC contract. The
canonical FunC sources for the three reference contracts
(`crypto/func/auto-tests/legacy_tests/jetton-minter/jetton-minter.fc`,
`crypto/func/auto-tests/legacy_tests/jetton-wallet/jetton-wallet.fc`,
`crypto/smartcont/wallet-v5-code.fc`) remain in the tree and are
the bit-identical fallbacks.

**Protocol-level rollback.** There is none, because there is
nothing to activate at the protocol layer. Slice 1 has no
"activation height" — the slice ships an envelope discipline and a
Tol-stdlib release, not a network upgrade. Validators do not need
a coordinated bump; node operators do not need to set a flag. The
named-constants refactor in `crypto/block/transaction.cpp` is a
pure code-cleanup that preserves the existing `& 3` mask.

**Future rollbacks.** When a future slice changes wire behaviour —
for example the §5.4 schema bump that introduces
`new_bounce_body_v2#fffffffd` and an inline `error_class` field, or
the supervision-link bit activation in Slice 6 — that slice will
ship its own activation policy, RFC, and global-version gate. None
of those are Slice 1.

## §7. Known gaps and follow-ups

The following are explicitly out of Slice 1 scope:

- **Pre-migration FunC-vs-Tol black-box gas parity.** The Slice 1
  CI gas gate (`scripts/check-slice-1-gas.py`,
  `doc/slice-1-gas-baselines.json`) covers Tol-side regressions
  against the Slice 1 baseline at 10% threshold. Equivalent
  pre-migration FunC black-box gas fixtures do not exist in-tree
  and require a transaction-level emulator harness that the
  existing FunC test surface does not provide. The gap is scoped
  precisely in [`doc/slice-1-gas-gap.md`](slice-1-gas-gap.md) and
  is the blocker for the ninth Slice 1 checklist item; a sibling
  workstream is closing it in the same release window.
- **Slice 2 — high-level syntax.** The `contract`, `receive(...)`,
  and `message` keywords are Slice 2 territory. They compile to
  the Slice 1 envelope; nothing in the wire format changes. Slice
  2 design may run in parallel with Slice 1 release work, but
  Slice 2 implementation requires a Slice 1 release tag.
- **Inline `error_class` in the bounce body.** A future slice may
  ship a new bounce-body constructor (e.g.
  `new_bounce_body_v2#fffffffd ... error_class:uint8 ...`),
  activate `extra_flags` bit 2, and bump the global version. Per
  policy §5.4 and §3.4, this is **explicitly Slice 4 or later**,
  not now. Slice 1 reserves the bit but does not use it.
- **Supervision-link tag.** `extra_flags` bit 3 is reserved for
  the supervision protocol of `actor.md` §5.1 and activates in
  Slice 6.
- **Scheduled messages, cross-shard delivery SLA, capability
  addressing, back-pressure rate-limiting (`error_class = 5`).**
  Each is owned by a later slice and a later policy document; see
  `doc/roadmap.md` §11 for the unscheduled-work table.

For internal-team progress tracking, see `doc/roadmap.md` §5
(first-slice deliverables checklist).

## §8. References

- [`doc/tos-message-policy.md`](tos-message-policy.md) — wire and
  lifecycle policy v6 (single-signer governance), source of the
  §3.1 envelope, §3.2 opcode partition, §5.2 `OP_ERROR` body, §5.3
  `error_class` enum, §8.1 compatibility commitments, §8.2
  three-step opt-in, and §10.1 ≤ 15% bytecode budget.
- [`doc/tos-message-envelope-migration.md`](tos-message-envelope-migration.md)
  — internal contract-author migration playbook drafted from the
  three Stage 3 reference migrations.
- [`doc/roadmap.md`](roadmap.md) — actor-layer implementation
  roadmap and Slice 1 deliverables checklist (§5).
- [`doc/actor.md`](actor.md) — actor-model strengthening
  directions; Slice 1 implements §5.3 (structured errors) and
  §5.6 (request/reply correlation).
- [`doc/tol.md`](tol.md) — Tol language execution path; Slice 1
  is the language surface of Q1 (envelope).
- [`doc/slice-1-gas-gap.md`](slice-1-gas-gap.md) — Stage 4 gas
  evidence gap and follow-up specification for the FunC↔Tol
  black-box parity work that will close the ninth Slice 1
  checkbox.
