# TOS Message Envelope Migration Playbook

## 0. Status and Scope

**Status.** Internal playbook, drafted 2026-04-30 from the Slice 1
Stage 3 migrations on `actor-layer`.

**Source policy.** This document is subordinate to
[`tos-message-policy.md`](tos-message-policy.md) v6. The policy fixes
the wire contract; this playbook describes how contract authors should
move existing code to the Tol Slice 1 stdlib without changing that wire
contract.

**Reference migrations.**

| Contract | Tol file | Tests | Bytecode delta |
|---|---|---|---|
| `jetton-minter` | [`../crypto/smartcont/jetton-minter.tol`](../crypto/smartcont/jetton-minter.tol) | `jetton-minter-{positive,auth-fail,unknown-opcode}.tol` | FunC 11 cells / Tol 9 cells / ratio 0.82 |
| `jetton-wallet` | [`../crypto/smartcont/jetton-wallet.tol`](../crypto/smartcont/jetton-wallet.tol) | `jetton-wallet-{positive,auth-fail,protocol-fail}.tol` | FunC 17 cells / Tol 10 cells / ratio 0.59 |
| `wallet-v5` | [`../crypto/smartcont/wallet-v5.tol`](../crypto/smartcont/wallet-v5.tol) | `wallet-v5-{positive,error-map,protocol-fail}.tol` | FunC 20 cells / Tol 22 cells / ratio 1.10 |

**Out of scope.** This is not the external RFC, not a new TEP
allocation, and not a Slice 2 syntax guide. Do not use the future
`contract`, `receive(...)`, or `message` syntax in Slice 1 migrations.
The supported surface is `onInternalMessage`, optional
`onBouncedMessage`, `lazy <Struct>.fromSlice(...)`, raw builders where
wire compatibility requires them, and the stdlib `Error` /
`ErrorClass` types.

## 1. Non-Negotiable Rules

1. Preserve the wire bytes. `tos-message-policy.md` §8.1 is the hard
   wall. A migration may improve Tol structure, tests, and error
   classification, but it must not reorder fields, narrow address
   types, change body inline/ref placement, or pick new opcodes.
2. Remember that `Envelope` is body-only. It covers
   `opcode:uint32 query_id:uint64 payload:...` from §3.1. It does not
   own `CommonMsgInfo`, destination, value, fees, timestamps, bounce
   flags, or `extra_flags`.
3. Model the existing body, do not wrap it in a second envelope. For
   TEP-style bodies, the per-opcode Tol struct is the envelope:
   `struct (OP_TRANSFER) TransferRequest { queryId: uint64; ... }`.
4. Propagate `query_id` only when the contract emits a correlated
   reply. If the request is fire-and-forget, mutates state, forwards a
   raw legacy message, or delegates correlation to existing TEP
   semantics, call `disclaim_query_id()`.
5. Use `createMessage` only when it is bit-identical. If it narrows
   `MsgAddress` to `MsgAddressInt`, chooses a different inline/ref body
   placement, or rewrites a legacy builder shape, keep a hand-packed
   raw builder.
6. Wallet external messages are outside §3.1. `wallet-vN` signed
   external bodies must remain exactly as the wallet standard defines
   them; only internal bodies that already have an opcode/query_id
   shape opt into the Slice 1 envelope discipline.

## 2. Migration Inventory

Before writing Tol, make a table from the FunC source:

| Item | What to record | Why it matters |
|---|---|---|
| Inbound opcodes | Name, numeric value, body fields, empty/comment exceptions | Locks the `struct (OP)` tags and positive tests |
| Throw sites | Source line, throw code, condition, semantic reason | Produces the §5.3 error-class table |
| Outbound messages | Destination type, value mode, body bits, refs, send mode | Decides `createMessage` vs raw builder |
| Storage layout | Field order, integer widths, dictionary widths, address type | Prevents silent state migration |
| Bounce path | Whether FunC ignored, parsed, or handled bounced bodies | Prevents generated Tol bounce policy drift |
| Bytecode baseline | FunC BoC cells and bytes | Enforces the §10.1 15% budget |

Keep the FunC file in place. The migrated Tol file is a reference
implementation, not a deletion of the canonical compatibility source.

## 3. Struct Shape

Use one request struct per inbound opcode. Put the opcode in the
struct tag and `queryId` as the first field:

```tol
const OP_TRANSFER: uint32 = 0x0f8a7ea5

@overflow1023_policy("suppress")
struct (OP_TRANSFER) TransferRequest {
    queryId: uint64;
    amount: coins;
    destination: any_address;
    responseDestination: any_address;
    customPayload: dict;
    forwardTosAmount: coins;
    forwardPayload: RemainingBitsAndRefs;
}
```

Guidelines:

- Give opcode constants an explicit `uint32` type. This keeps struct
  tags fixed-width and makes the generated body start with the
  policy-mandated 32 bits.
- Use `any_address` when the FunC source used `load_msg_addr()` or
  stored a `MsgAddress` slice. Do not replace it with `address` unless
  the original contract already required `MsgAddressInt`.
- Use `RemainingBitsAndRefs` for tail payloads whose exact bit/ref
  shape is caller-controlled.
- Use `@overflow1023_policy("suppress")` only when the source format
  is intentionally variable-width and the compiler cannot prove the
  upper bound. The annotation is a compatibility escape hatch, not a
  default.

## 4. Handler Pattern

The basic Slice 1 handler pattern is:

```tol
fun onInternalMessage(in: InMessage) {
    if (in.body.isEmpty()) {
        return;
    }

    var body = in.body;
    val op = body.loadUint(32);

    if (op == OP_TRANSFER) {
        disclaim_query_id();
        val msg = lazy TransferRequest.fromSlice(in.body);
        sendTokens(msg, in.senderAddress, in.valueCoins, in.originalForwardFee);
        return;
    }

    throw FUNC_THROW_UNKNOWN_OPCODE;
}
```

Important details:

- Parse the header from a local copy of `in.body`; parse the full
  request from the original slice so the opcode tag remains available
  to `lazy <Struct>.fromSlice(...)`.
- If the handler emits a structured reply with `createMessage`, copy
  `msg.queryId` into the reply body.
- If the handler does not emit a correlated reply, call
  `disclaim_query_id()` in that opcode branch. The Slice 1 static pass
  accepts either propagation or an explicit disclaimer.
- For bounced messages, choose the policy that matches FunC. If FunC
  had a separate bounce path, implement `onBouncedMessage`. If FunC
  manually dispatched the same body regardless of bounce flag, use
  `@on_bounced_policy("manual")`. If FunC effectively ignored bounced
  bodies, `@on_bounced_policy("ignore")` is acceptable only after
  confirming the observable behavior is the same.

## 5. Outbound Messages

Prefer the highest-level sender that preserves bytes.

Use `createMessage` when all of these hold:

- destination is `MsgAddressInt`;
- body inline/ref placement matches the legacy format or is not part
  of the compatibility surface;
- the send mode and bounce/extra_flags behavior match the FunC
  builder;
- the reply body can carry `queryId: msg.queryId`.

Keep a raw builder when any of those fail. The Stage 3 jetton
migrations kept raw builders because the FunC references use
`MsgAddress` slices for owner/master/response fields and because the
existing body placement is part of the observable TEP-74 behavior.

Raw builders still need explicit query-id discipline:

```tol
fun sendExcesses(responseAddress: any_address, queryId: uint64): void {
    sendRawMessage(
        beginCell()
            .storeUint(0x10, 6)
            .storeAddressAny(responseAddress)
            .storeCoins(0)
            .storeUint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
            .storeUint(OP_EXCESSES, 32)
            .storeUint(queryId, 64)
            .endCell(),
        SEND_MODE_IGNORE_ERRORS + SEND_MODE_CARRY_ALL_REMAINING_MESSAGE_VALUE
    );
}
```

If the compiler cannot prove that a raw send propagates the inbound
`query_id`, either refactor the reply body into a typed struct or call
`disclaim_query_id()` in the inbound branch and document why the
legacy send is still wire-compatible.

## 6. Error Classification

Every migrated contract should expose a pure helper that maps legacy
FunC throw codes into the stdlib `Error` body:

```tol
@pure
fun jettonMinterErrorForThrow(funcThrow: int, originalOp: uint32, queryId: uint64): Error {
    if (funcThrow == FUNC_THROW_ADMIN_REQUIRED) {
        return Error {
            queryId,
            originalOp,
            errorClass: ErrorClass.Authorization,
            errorCode: JETTON_ERROR_ADMIN_REQUIRED,
            diagnostic: null,
        };
    }
    return Error {
        queryId,
        originalOp,
        errorClass: ErrorClass.Protocol,
        errorCode: JETTON_ERROR_UNKNOWN_OPCODE,
        diagnostic: null,
    };
}
```

Classify by the semantic cause, not by the numeric throw value:

| Cause | Preferred class | Examples from Stage 3 |
|---|---|---|
| Sender is not admin/owner/extension, invalid signature | `Authorization` | minter `throw(73)`, wallet `throw(705)`, wallet-v5 `throw(135)` |
| Unknown opcode, malformed envelope/body, wrong workchain, invalid global id | `Protocol` | minter `throw(0xffff)`, wallet `throw(708)`, wallet-v5 `throw(148)` |
| Duplicate/missing extension, stale seqno, expired request, insufficient token balance | `Permanent` | wallet-v5 `throw(143)`, wallet-v5 `throw(136)`, wallet `throw(706)` |
| Insufficient attached value or sender-side capacity pressure | `BackPressure` | wallet `throw(709)` for underfunded transfer value |
| Temporary infrastructure failure | `Transient` | Not exercised by Stage 3 reference contracts |

Use application-specific `error_code` values at 1024 or above. Keeping
an existing large FunC code such as `0xffff` is fine because it is
outside the stdlib-reserved 0..1023 range.

Known policy tension: `tos-message-policy.md` v6 describes
`BackPressure` as reserved/not emitted in Slice 1, but the
`jetton-wallet` Stage 3 migration uses it for insufficient attached
value. Resolve that wording before publishing the external RFC; until
then, new migrations should follow the in-tree reference contract and
call out the assignment in their header table.

## 7. Wallet-vN Special Case

Wallet contracts are the exception that prevents a purely mechanical
TEP-style migration:

- signed external messages are outside the Slice 1 internal-message
  envelope and must remain unchanged;
- signed internal wallet requests retain the wallet-vN body shape;
- C5 action-list validation is a wallet behavior, not an Envelope
  behavior, so keep low-level parsing if that is what FunC did;
- use `@on_bounced_policy("manual")` when FunC's `recv_internal`
  ignored the bounced flag and dispatched by body prefix only.

`wallet-v5.tol` therefore includes the stdlib `Error` mapping and
query-id disclaimer for `extension_action`, but it does not convert
external signed requests into `Envelope` structs.

## 8. Test Requirements

A useful migration test set has three layers:

| Test | Minimum coverage |
|---|---|
| Positive body tests | At least one body shape per inbound opcode; assert opcode, `queryId`, and variable-tail layout |
| Negative/error-map tests | At least one auth failure, one protocol failure, and all ambiguous throw-code branches |
| OP_ERROR body tests | Serialize `beginCell().storeUint(OP_ERROR, 32).storeAny(err)` and assert field order from §5.2 |
| Bytecode budget | Compile FunC and Tol to BoC, record cells and ratio in the Tol header |
| Existing suite | Run `tol-tester.py tests` and `test-emulator` |

For Stage 3 the expected local checks were:

```bash
/home/tomi/tos/build/tol/tol crypto/smartcont/<contract>.tol

cd /home/tomi/tos/tol-tester
FIFTPATH=/home/tomi/tos/crypto/fift/lib \
FIFT_EXECUTABLE=/home/tomi/tos/build/crypto/fift \
TOL_EXECUTABLE=/home/tomi/tos/build/tol/tol \
  python3 tol-tester.py tests

cmake --build /home/tomi/tos/build --target test-emulator -j 32
/home/tomi/tos/build/test-emulator
```

## 9. Header Template

Every migrated contract should start with a grep-friendly header:

```text
// =============================================================================
// Slice 1 Stage N — <contract> Tol migration.
//
// Policy reference: doc/tos-message-policy.md v6 §3.1 (standard body layout),
// §5.2 (OP_ERROR body), §5.3 (error_class), and §8.1 (bit-for-bit
// compatibility for existing <standard> formats).
//
// Bytecode delta captured at write time:
//   FunC cells: <n>
//   Tol cells:  <n>
//   ratio:      <tol/func>
//
// §5.3 error-class assignment table:
//   FunC line | FunC throw(N) | ErrorClass | error_code
//   ...
//
// Compatibility note: <why any raw builder, any_address, bounce policy,
// or wallet external-message exception is intentional>.
// =============================================================================
```

The header is not ceremonial. It is the review surface for the next
contract author and the data source for the gas/bytecode dashboard in
Stage 4.

## 10. Review Checklist

Before merging a migration:

- [ ] The FunC source remains unchanged.
- [ ] Every inbound opcode has a Tol struct or an explicit
      grandfathered exception.
- [ ] Every legacy throw site appears in the header table.
- [ ] Every error code is 1024+ unless preserving a legacy code that
      is already outside the stdlib-reserved range.
- [ ] Every `query_id` is propagated to correlated replies or
      explicitly disclaimed.
- [ ] Raw builders are justified by a compatibility note.
- [ ] Address types match the source wire format.
- [ ] Bounce handling matches the FunC observable behavior.
- [ ] Bytecode delta is at or below 1.15, or the overage is documented
      with a concrete trim proposal.
- [ ] `tol-tester.py tests` and `test-emulator` are green.
