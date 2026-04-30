# TOS Language Syntax Policy (Slice 2)

## 0. Status, scope, and references

**Status.** Draft v1 (2026-04-30). This document is the policy
input for Slice 2 of [`doc/roadmap.md`](roadmap.md). It must be
approved by the §11 authorized owner before Slice 2 implementation
begins, under the single-signer governance model of
[`doc/tos-message-policy.md`](tos-message-policy.md) §12.1.

**Scope.** Locks the syntactic-semantic contract for the Slice 2
high-level Tol surface — `contract` declarations, `receive(...)`
blocks, state machines (`receive(...) on State` + `become`),
`get fun`, and the lowering rules from those constructs to the
existing TVM substrate established in Slice 1. The policy fixes
what contract authors write and what wire bytes the compiler
emits; it does **not** specify the compiler's internal IR or
parser implementation.

**Out of scope.** Cross-contract synchronous-feeling calls,
supervision (`actor.md` §5.1), scheduled messages (`actor.md`
§5.2), capability addressing (`actor.md` §5.4), and any new
TVM opcode or new bounce-body constructor are explicitly
deferred. The full out-of-scope list is in §8.

**Source-of-truth references.**

- [`doc/tos-message-policy.md`](tos-message-policy.md) v6
  — wire-level envelope, error class, query_id rules; Slice 2
  compiles ONTO this substrate.
- [`doc/actor.md`](actor.md) §5.5 — design rationale for
  language-level state machines and `become`.
- [`doc/tol.md`](tol.md) Q2 — execution path's high-level goals.
- [`doc/roadmap.md`](roadmap.md) Slice 2 (week 27–52)
  — sequencing context.
- [`crypto/smartcont/jetton-minter.tol`](../crypto/smartcont/jetton-minter.tol),
  [`crypto/smartcont/jetton-wallet.tol`](../crypto/smartcont/jetton-wallet.tol),
  [`crypto/smartcont/wallet-v5.tol`](../crypto/smartcont/wallet-v5.tol)
  — the three Slice 1 reference migrations whose dispatch
  ladders Slice 2 lifts into syntax.

## 1. First principles: why move actor shape from convention to compiler-enforced contract

Slice 1 shipped the actor substrate: the `Envelope` and `Error`
types, the `OP_ERROR` reply convention, the
`disclaim_query_id()` builtin, and the
`pipe-check-query-id-propagation` warning pass
(`tos-message-policy.md` §3.1, §4.4, §5.2, §5.3). Three
reference contracts migrated against that substrate
(`doc/tos-message-envelope-migration.md`).

The migrations make the cost of **convention-only actor shape**
visible. Every migrated contract independently re-implements the
same dispatch pattern. Concretely, in
[`crypto/smartcont/jetton-minter.tol`](../crypto/smartcont/jetton-minter.tol)
lines 225–311, every contract author writes:

```tol
fun onInternalMessage(in: InMessage) {
    if (in.body.isEmpty()) return;
    var header = in.body;
    val op = header.loadUint(32);
    val queryId = header.loadUint(64);
    val storage = loadData();

    if (op == OP_X) { val msg = lazy XReq.fromSlice(in.body); /* ... */ }
    if (op == OP_Y) { val msg = lazy YReq.fromSlice(in.body); /* ... */ }
    /* ... */
    throw UNKNOWN_OPCODE;
}
```

This repetition is not surface aesthetic. Each instance carries
five concrete costs that compound across the ecosystem:

1. **Exhaustiveness drift.** The `throw UNKNOWN_OPCODE` is
   manual. A new opcode added to the contract's vocabulary
   without a matching `receive` ladder branch becomes a silent
   bounce instead of a compile error.
2. **Query-id propagation drift.** `disclaim_query_id()` is
   sprinkled in opcode arms by hand. A reader cannot tell from
   the receiver block alone whether `query_id` propagation is
   correct without walking the body.
3. **State encoding drift.** Contracts that have states (auction
   open / settling / closed; channel funded / closed; etc.)
   encode the state as a hand-rolled bit field in `c4`. The
   compiler does not know which state is current; reachability
   and exhaustiveness checks are impossible.
4. **Dispatch-table inefficiency.** A linear `if` cascade
   compiles to a chain of comparisons. The compiler could emit a
   jump-table dispatch, but only if the language exposes the
   set of opcode handlers as a closed set.
5. **Reader-time entropy.** Every contract author re-derives a
   personal dialect of the same actor pattern. New contributors
   spend reading time learning each contract's local convention
   instead of recognizing a shared shape.

The first-principles answer is the same step Erlang/OTP took
when it lifted raw `spawn` + manual `receive` patterns into the
`gen_server` and `gen_statem` behaviours: **promote the actor
pattern from convention to a compiler-enforced contract**. The
policy below does exactly that for Tol, anchored on the wire
contract `tos-message-policy.md` v6 already locked.

The single test of every Slice 2 design choice is therefore:
**does it eliminate one of the five costs above without forking
the wire contract**? Choices that fail either test are out of
scope (§8).

## 2. Current baseline (what Tol has on 2026-04-30)

Slice 2 builds on existing Tol features. The baseline is fully
in-tree; the new vocabulary in §3 is additive, not replacing.

### 2.1 Struct-with-prefix — the existing opcode binding

Tol already supports binding a 32-bit opcode to a struct via
the `(0xNN)` prefix annotation:

```tol
struct (0x00000015) MintRequest {
    queryId: uint64;
    toAddress: any_address;
    amount: coins;
    masterMsg: cell;
}
```

Pack/unpack code is auto-derived. The opcode is part of the
struct's wire layout, so `lazy MintRequest.fromSlice(in.body)`
reads the 32-bit prefix as the discriminant. This baseline IS
the foundation Slice 2 dispatch builds on.

### 2.2 `lazy <Struct>.fromSlice(...)` — the existing parsing call

Slice 1's stdlib supports `lazy` parsing of envelope-shaped
bodies. The existing migrated contracts use it pervasively:

```tol
val msg = lazy MintRequest.fromSlice(in.body);
```

Slice 2 lowering generates this call automatically inside the
dispatch table; authors stop writing it by hand.

### 2.3 `onInternalMessage(in: InMessage)` — the current entry

The TVM-level entry point for internal messages. Slice 2 keeps
this as the **escape hatch** (§6.1) and as the **lowering
target** (§4): every Slice 2 `contract { receive(...) ... }`
compiles to one synthetic `onInternalMessage` function.

### 2.4 `createMessage<TBody>` — the existing reply path

Slice 1's outbound message constructor with auto-derived
`extra_flags` handling. Slice 2 receivers' reply emissions go
through this same primitive.

### 2.5 `disclaim_query_id()` — the Slice 1 builtin

Compile-time marker that suppresses the
`pipe-check-query-id-propagation` warning. Slice 2 receivers
declared with the `@disclaim_query_id` annotation (§3.2) emit a
single call to this builtin in their lowered form, so the
warning surface remains semantically identical.

### 2.6 `@method_id(N)` annotation — the existing get-method binding

Tol contracts expose getters via:

```tol
@method_id(101) fun balance(): int { ... }
```

Slice 2 promotes this to first-class `get fun` (§3.5).

## 3. The new vocabulary

### 3.1 `contract` declaration

A `contract` is the unit that binds **storage**, **receivers**,
and **getters** into one compiler-checked surface. Concrete
shape:

```tol
contract JettonMinter {
    storage: JettonMinterStorage

    receive(msg: MintRequest) {
        require(in.senderAddress == storage.adminAddress,
                ErrorClass.Authorization);
        // ... business logic
        save({ ...storage, totalSupply: storage.totalSupply + msg.amount });
    }

    receive(msg: ChangeAdmin) {
        require(in.senderAddress == storage.adminAddress,
                ErrorClass.Authorization);
        save({ ...storage, adminAddress: msg.newAdminAddress });
    }

    get fun balance(): coins {
        return storage.totalSupply;
    }
}
```

The compiler synthesizes:
- `onInternalMessage(in: InMessage)` (the §4 lowering target)
- `c4` storage-cell layout that round-trips `JettonMinterStorage`
- A get-method table that includes `balance` with an
  auto-derived `method_id` (§3.5)

A `contract` block must contain exactly one `storage:` line, at
least one `receive(...)`, and zero or more `get fun`. No
free-standing `fun` declarations or top-level statements are
permitted inside a `contract` block; helpers go to
file-scope `fun`s as today.

### 3.2 `receive(msg: T)` — the only dispatch form

Slice 2 supports exactly **one** receive form: typed dispatch.

```tol
receive(msg: <TypeName>) { ... }
```

`<TypeName>` must be a struct with a `(0xNN)` opcode prefix
(§2.1). The compiler builds the opcode → handler map at
compile time; an opcode not listed in any `receive` is a
**compile error**, not a runtime bounce. A
"catch-all" receiver is declared with the reserved type
`UnknownOpcode`:

```tol
receive(msg: UnknownOpcode) {
    // body has body.opcode and body.rawBody available
    throw ErrorClass.Protocol;  // or send OP_ERROR reply
}
```

If no `UnknownOpcode` receiver is declared, the compiler
synthesizes a default body that throws the policy §5.3
`error_class = Protocol` exit code.

**Why no string-literal `receive("op_name")` form.** Hashing
a name to an opcode is wire-instability: a future rename of
the receiver changes the opcode and breaks
`tos-message-policy.md` §8.1. Authors who want a
name-indexed dispatch declare a `const OP_NAME = 0xNN` and
attach it to a struct.

**Annotations on `receive`.**

- `@disclaim_query_id` — equivalent to a single
  `disclaim_query_id()` call at the receiver's start; the
  Slice 1 `pipe-check-query-id-propagation` pass treats the
  receiver as fire-and-forget. Without it, the receiver must
  propagate `msg.queryId` to every reply or call
  `disclaim_query_id()` explicitly inside the body.
- `@bounce_only` — receiver only fires on bounced messages.
  Lowers to a branch inside `onBouncedMessage`, not
  `onInternalMessage`.

### 3.3 Storage is a single named struct

A `contract` declares storage as exactly one struct:

```tol
storage: JettonMinterStorage
```

`JettonMinterStorage` is defined as a top-level `struct`. The
compiler derives `loadData` / `saveData` from it. Inside a
receiver body, `storage` is read-only; mutations happen
through `save(...)` which takes a struct literal that the
compiler validates as having all fields of `JettonMinterStorage`.

**Why one struct, not multiple top-level fields.** A single
root makes pack/unpack auto-derivation deterministic;
multiple top-level fields invite partial-update footguns where
a receiver forgets to write some field and the c4 layout
becomes inconsistent. Authors compose by nesting.

### 3.4 `receive(...) on State` — state machines

A contract MAY declare a state machine:

```tol
contract Auction {
    states: Open, Settling, Closed
    @initial state Open

    storage: AuctionStorage

    receive(msg: BidRequest) on Open {
        require(msg.amount > storage.highBid, ErrorClass.Permanent);
        save({ ...storage, highBid: msg.amount, highBidder: msg.bidder });
        keep_state;
    }

    receive(msg: SettleRequest) on Open {
        require(currentTime() >= storage.deadline, ErrorClass.Authorization);
        // payouts ...
        become Settling;
    }

    receive(msg: PayoutAck) on Settling {
        if (storage.payoutsRemaining == 1) {
            become Closed;
        } else {
            save({ ...storage, payoutsRemaining: storage.payoutsRemaining - 1 });
            keep_state;
        }
    }
}
```

**Storage layout.** A `states:` declaration adds one synthetic
field to the storage struct:

```tol
struct AuctionStorage {
    @synthetic state: AuctionState  // injected; do not declare manually
    highBid: coins;
    highBidder: any_address;
    deadline: uint32;
    payoutsRemaining: uint8;
}
```

The state field is a tag (enum-like layout, §1 first-principles
choice). Receivers do not touch it directly; `become State`
emits the tag write at commit phase.

**Field scoping with `@on(State1, State2)`.**

```tol
struct AuctionStorage {
    payoutsRemaining: uint8 @on(Settling)
    finalWinner: address    @on(Closed)
}
```

A field annotated `@on(...)` is a **compile error** to read or
write outside the listed states. This realizes the
`actor.md` §5.5 invariant-preservation guarantee without
requiring sum-type storage. The c4 layout still includes the
field unconditionally (enum-like cost model); the check is
purely at the language layer.

**`become` and `keep_state`.** Every receiver in a
state-bearing contract MUST end every control-flow path with
either:
- `become <NextState>;` — transition, emits c4 state-tag
  update at commit
- `keep_state;` — no transition, no tag update

Absence of either is a **compile error**. The default of
"silently stay" is a known Erlang `gen_statem` foot-gun and is
explicitly excluded.

**Static checks emitted by `tol/pipe-check-state-machine.cpp`
(new in Slice 2):**

1. **Exhaustiveness.** For each `(receive type × state)` pair
   not declared, the compiler synthesizes an
   `ErrorClass.Protocol` reply and emits a warning (not error;
   warnings are silenced by `@implicit_protocol_for(Type, State)`
   on the contract declaration).
2. **Reachability.** Each declared state must be reachable via
   `become` from `@initial` or another reachable state. An
   unreachable state is a compile error.
3. **Field scoping.** Per `@on(...)` rules above.
4. **Initial-state singleton.** Exactly one state may carry
   `@initial`; zero or two are compile errors.

### 3.5 `get fun` — first-class get methods

```tol
contract JettonMinter {
    /* ... */

    get fun balance(): coins {
        return storage.totalSupply;
    }

    @method_id(0x67e5) get fun adminAddress(): address {
        return storage.adminAddress;
    }
}
```

`get fun` declares a contract get-method. The compiler
auto-derives `method_id` from `compute_method_id(name)` (the
same hashing the existing TVM stdlib uses for naming
conventions in TEP standards). An explicit
`@method_id(N)` annotation overrides the auto-derived value;
this is the migration escape hatch for contracts whose external
ABI is fixed by an existing TEP standard.

Inside a `get fun`, `storage` is read-only; mutations are a
compile error. There is no `save(...)` available.

### 3.6 No `init()` block — first received message IS init

Tol does NOT introduce a `init()` keyword for contract
deployment. The TON/TOS deployment convention is unchanged:
a contract is materialized when an internal message carrying
`StateInit` arrives at its address, and the first executed
receiver IS the deployment handler.

Authors who want explicit deploy logic add a `Deploy` opcode
struct + receiver:

```tol
struct (0x00000001) Deploy {
    queryId: uint64;
    initialAdmin: any_address;
}

contract JettonMinter {
    storage: JettonMinterStorage

    receive(msg: Deploy) {
        // first-message init logic
        save({
            totalSupply: 0,
            adminAddress: msg.initialAdmin,
            content: emptyCell(),
            jettonWalletCode: emptyCell(),
        });
    }

    /* ... other receivers ... */
}
```

This matches existing TON/TOS deployment exactly; Slice 2 adds
no new deployment-time machinery.

### 3.7 `require(cond, ErrorClass.X)` — sugar over `throw`

Receivers commonly check preconditions and throw on failure.
Slice 2 sugar:

```tol
require(in.senderAddress == storage.adminAddress, ErrorClass.Authorization);
```

Lowers to:

```tol
if (!(in.senderAddress == storage.adminAddress)) {
    throw <error_code derived from ErrorClass.Authorization>;
}
```

The error_code is derived per `tos-message-policy.md` §5.3
(low-numbered for stdlib classes, high-numbered for
application-specific). `require(...)` may take an optional
third argument `, error_code: int` for explicit application
codes:

```tol
require(msg.amount <= storage.highBid, ErrorClass.Permanent, 1097);
```

## 4. Compilation model (lowering contract)

The Slice 2 surface is **fully lowered to the existing Slice 1
substrate** at compile time. No new TVM opcode, no new TL-B
constructor, no new c4 layout discriminator. Concretely:

### 4.1 `contract X { storage: S; receive(msg: T1)... receive(msg: Tn) ... }` lowers to

```tol
fun onInternalMessage(in: InMessage) {
    if (in.body.isEmpty()) return;

    val op = in.body.preloadUint(32);   // peek; do not consume
    val storage = loadData();

    // dispatch table (compiler chooses if-cascade or jump-table by N)
    if (op == op_of(T1)) {
        val msg = lazy T1.fromSlice(in.body);
        // user body for receive(msg: T1)
        return;
    }
    if (op == op_of(T2)) {
        val msg = lazy T2.fromSlice(in.body);
        // user body
        return;
    }
    /* ... */

    // synthesized UnknownOpcode handler if author did not declare one
    throw <ErrorClass.Protocol code>;
}
```

For state-bearing contracts, each receiver body is wrapped in
a state-tag check:

```tol
if (op == op_of(BidRequest)) {
    val state = storage.state;
    if (state != AuctionState.Open) {
        throw <ErrorClass.Protocol code>;  // wrong state
    }
    val msg = lazy BidRequest.fromSlice(in.body);
    // user body, with `become` / `keep_state` lowered to:
    //   become Settling   →   save({ ..., state: AuctionState.Settling })
    //   keep_state        →   no save tag write (other field saves still emit)
    return;
}
```

### 4.2 `save(struct_literal)` lowers to

`saveData(struct_literal)` per existing Slice 1 stdlib. State
tag updates from `become State` are merged into the literal at
codegen time; authors do NOT spell `state: AuctionState.Settling`
in the `save(...)` call.

### 4.3 `get fun X(): T` lowers to

The existing `@method_id(compute_method_id("X")) fun X(): T`
form. No change to the get-method execution path; only the
authoring surface differs.

### 4.4 Wire bytes

Slice 2 emits the same wire bytes a hand-written Slice 1
contract would, given the same opcode set, struct layouts, and
receiver bodies. This is the §6.1 commitment, verified by the
§7 migration plan's bytecode-cell-delta target.

## 5. Static analysis additions

Three new compiler passes in `tol/pipe-check-*.cpp`, all
running in the policy-mandated band between
`pipeline_check_serialized_fields()` and the
`G.error_collector = nullptr;` teardown (`tos-message-policy.md`
§4.4 hardening rule):

1. **`pipe-check-receive-exhaustiveness.cpp`.** For each
   `contract` block, builds the (state × opcode) coverage map
   and emits a warning for every unhandled cell. Silenced
   per-contract by `@implicit_protocol_for(Type, State)`.
2. **`pipe-check-state-reachability.cpp`.** Builds the
   `become` graph from the `@initial` state. Unreachable
   states = compile error.
3. **`pipe-check-field-scoping.cpp`.** For each `@on(...)`
   field, traces every read / write. Cross-state access =
   compile error.

The existing Slice 1 `pipe-check-query-id-propagation.cpp`
remains unchanged in trigger condition (still keys off the
`lazy <Struct>.fromSlice(in.body)` pattern), but its check
walks INTO synthesized `onInternalMessage` bodies generated by
the §4 lowering. This is implementation detail; the user-facing
warning surface is unchanged.

## 6. Backwards compatibility commitments

Slice 2 is **additive**. The following commitments hold:

### 6.1 Wire-bit-identical to Slice 1

A contract written in Slice 2 syntax that declares the same
opcode set, struct layouts, and receiver semantics as a Slice 1
hand-written equivalent emits **bit-identical wire bytes**.
This is verified by re-migrating the three Slice 1 reference
contracts to Slice 2 syntax (Slice 3 work) and comparing
compiled BoCs cell-for-cell.

`tos-message-policy.md` §8.1 commitments are inherited
verbatim.

### 6.2 Existing Tol files keep compiling

Any `.tol` file that does NOT use the new keywords
(`contract`, `receive`, `become`, `keep_state`, `states:`,
`@initial`, `@on`, `get fun`, `require`) keeps compiling
exactly as before. The existing
`tol-tester/tests/handle-msg-*.tol` test corpus is unaffected.

### 6.3 Mixing new and old in one file

A `.tol` file MAY contain both a `contract X { ... }` block
and stand-alone `fun` / `struct` declarations. It MAY NOT
declare both `contract X` AND a top-level
`fun onInternalMessage(...)` — that combination is a compile
error to prevent split-brain dispatch.

### 6.4 Existing Slice 1 stdlib stays

`Envelope`, `Error`, `OP_ERROR`, `ErrorClass`,
`disclaim_query_id()`, and the
`pipe-check-query-id-propagation` warning all remain. Slice 2
uses them internally; authors who prefer the Slice 1
hand-written style can continue to import and use them
directly.

## 7. Migration path for Slice 1 reference contracts

The three Slice 1 reference migrations (`jetton-minter.tol`,
`jetton-wallet.tol`, `wallet-v5.tol`) are **NOT re-migrated as
part of Slice 2**. Slice 2 ships the syntax; Slice 3
("Q3 + Q4" in `roadmap.md`) does the dogfooding re-migration.

The Slice 3 migration MUST verify:
- Bytecode-cell delta against the Slice 1 hand-written form
  is within ±5%. (§4.4 wire-bit-identity is the strict goal;
  ±5% is the bytecode-cell layout slack permitted to absorb
  jump-table vs if-cascade choice.)
- All Slice 1 conformance fixtures
  (`emulator/test/slice-1-*-fixtures.cpp`) keep passing
  unchanged.
- The FunC↔Tol gas parity gate
  (`scripts/check-slice-1-gas.py` schema v2) keeps passing
  with each Slice 2-migrated contract.
- The `pipe-check-query-id-propagation` warning surface is
  unchanged for each migrated contract (no new warnings, no
  regressions).

## 8. Out of scope for Slice 2

These are explicitly NOT delivered in Slice 2 and have their
own future-slice docs:

- Cross-contract synchronous-feeling calls
  (`actor.md` §5.6 / §6.5 — Slice 4+).
- Supervision (`actor.md` §5.1 — Year 3).
- Scheduled messages and the `send_at(...)` primitive
  (`actor.md` §5.2 — Year 3).
- Capability addressing (`actor.md` §5.4 — Year 3 research).
- Sum-type storage (each state carrying its own data shape).
  Slice 2 ships enum-like layout with `@on(...)` field
  scoping; sum-type is a future extension.
- Hot code upgrade primitives beyond the existing `SETCODE`
  TVM opcode.
- New TVM opcode, new bounce-body constructor, or any
  `extra_flags` mask widening (`tos-message-policy.md` §3.4
  Slice 4 / Slice 6 schedule unchanged).
- Auto-import of stdlib symbols inside `contract` blocks
  beyond what Slice 1 already auto-imports
  (`@stdlib/common`).
- A `message` keyword. The existing `struct (0xNN) Foo`
  syntax is canonical for opcode-bearing types; introducing
  a redundant `message` keyword fragments the language for
  no functional gain.

## 9. Open questions (for second review)

The §3 decisions are locked. The following items are
deliberately left open for the v2-review pass; they affect
implementation tactics but do not invalidate the lowering
contract or backwards-compatibility commitments above.

1. **Jump-table threshold.** At what receiver count does the
   compiler switch from if-cascade to dictionary-based
   dispatch? Recommend ≥ 6 receivers; finalize after Slice 3
   gas measurements.
2. **`require(cond, ErrorClass.X, code)` argument order.**
   `(cond, class, code)` reads naturally; `(cond, code, class)`
   matches the existing `throw N` convention. Pick before
   parser work.
3. **`@implicit_protocol_for(Type, State)` syntax.** Is the
   silencer per-pair, per-state, per-Type, or contract-wide
   `@implicit_protocol_default`? Gather data from Slice 3
   migration of state-bearing contracts before locking.
4. **`UnknownOpcode` reserved type.** Lives in `@stdlib/common`
   alongside `Envelope`/`Error`? Or in a new
   `@stdlib/contract`? Affects import discipline.
5. **`@bounce_only` receiver lowering target.** Branches into
   `onBouncedMessage` directly, or shares dispatch with the
   inbound path under a flag? The latter is simpler; the
   former is more obvious. Pick after profiling Slice 3.
6. **`save(...)` partial-update sugar.** `save({ ...storage,
   x: y })` is the spread form; do we also support
   `save.x(y)` for single-field updates? Not blocking; defer
   to later DX iteration.

These do not block Stage 0 sign-off but should be resolved
before the parser PR lands.

## 10. Constraints on Slice 2 implementation

The following items are the implementable subset of this
policy. Items outside this list are deferred regardless of how
clearly the policy describes them.

### 10.1 In Slice 2

- New parser productions for `contract`, `receive`,
  `become`, `keep_state`, `states:`, `@initial`, `@on`,
  `get fun`, `require`. AST node additions in `tol/ast.h`.
- Three new compiler passes
  (`pipe-check-receive-exhaustiveness.cpp`,
  `pipe-check-state-reachability.cpp`,
  `pipe-check-field-scoping.cpp`), all in the policy-mandated
  band between `pipeline_check_serialized_fields()` and the
  `error_collector = nullptr;` teardown.
- AST → legacy-Expr-Op IR lowering producing the exact
  `onInternalMessage` shape described in §4.1.
- `UnknownOpcode` reserved type in `@stdlib/common`.
- New `tol-tester/tests/contract-*.tol` cases covering: a
  minimal one-receive contract, a multi-receive contract, a
  state-bearing contract with `become`/`keep_state`, an
  exhaustiveness-warning case, a reachability-error case, a
  field-scoping-error case, and a get-fun auto-method-id case.
- Updated `pipe-check-query-id-propagation` to walk the
  synthesized `onInternalMessage` produced by lowering;
  warning surface unchanged.
- Updated `tol.md` Q2 reflecting the locked surface.

### 10.2 Not in Slice 2

- Re-migration of `jetton-minter.tol` / `jetton-wallet.tol` /
  `wallet-v5.tol` to Slice 2 syntax. That is Slice 3.
- The Slice 4 + Slice 6 `extra_flags` mask widening
  (`tos-message-policy.md` §3.4).
- The future `new_bounce_body_v2` schema bump
  (`tos-message-policy.md` §5.4).
- Sum-type storage (§8).
- Cross-contract synchronous-feeling calls (§8).
- Supervision, scheduled messages, capability addressing
  (§8).

## 11. Sign-off

This document is approved when the §11 row below is filled in
under the single-signer governance model of
`tos-message-policy.md` §12.1. Approval means: the listed party
agrees to implement the policy as written for Slice 2, and to
escalate any required deviation through a documented amendment
to this file.

| Role | Name | Date |
|---|---|---|
| Authorized owner (single-signer per `tos-message-policy.md` §12.1) | | |

### 11.1 Single-signer disclosure

The Slice 2 policy inherits the Slice 1 single-signer
disclosure verbatim: `tos-message-policy.md` §12.1 records that
TOS is in a single-engineer phase; the same authorized owner
who signed v6 of the message policy signs this document.

When a second engineer joins, the authorized owner row is
re-assigned and a fresh signature is appended; the original
signature stays for traceability.

## 12. Changelog

### Draft v1 (2026-04-30)

Initial draft. Authored as Stage 0 input for `doc/roadmap.md`
Slice 2 (week 27–52). The §3 decisions on dispatch form,
storage shape, state-machine layout, transition discipline,
init handling, and opcode-binding are locked from
first-principles analysis: (a) eliminate one of the five
convention costs identified in §1, and (b) preserve the
`tos-message-policy.md` §8.1 wire commitment. Open questions in
§9 are tactical, not structural.
