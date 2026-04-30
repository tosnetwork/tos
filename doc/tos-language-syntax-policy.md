# TOS Language Syntax Policy (Slice 2)

## 0. Status, scope, and references

**Status.** Draft v2 (2026-04-30, post-codex-security-review).
This document is the policy input for Slice 2 of
[`doc/roadmap.md`](roadmap.md). It must be approved by the §11
authorized owner before Slice 2 implementation begins, under the
single-signer governance model of
[`doc/tos-message-policy.md`](tos-message-policy.md) §12.1.

v2 closes 4 BLOCKER and 9 HIGH findings raised by the v1
security review (`/tmp/codex_output.md` archived 2026-04-30).
The four §3 lock decisions from v1 stand; v2 specifies the
lowering order, deployment path, unknown-opcode policy, and
disclaim-query-id pass scoping that v1 left under-specified.
See §13 changelog for the full delta.

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

`<TypeName>` must be a struct with a `(0x________)` opcode
prefix that is **exactly 32 bits wide on the wire**. v2
mandate: the compiler accepts only 32-bit opcode prefixes
inside contract `receive(...)` declarations. Today's Tol
infers prefix length from literal width
(`tol/pipe-register-symbols.cpp:45` — `struct (0x15)` is an
8-bit prefix); for receivers the compiler must reject any
struct whose declared prefix bit-length is not exactly 32 with
a message pointing at this section. Authors write
`struct (0x00000015)`, not `struct (0x15)`. This restriction
applies only inside `contract` blocks; free-floating structs
keep their existing prefix-length inference.

Two **separate** unknown-opcode rules — v2 split:

1. **Compile-time exhaustiveness over the *declared* opcode
   set.** The compiler builds the closed map of
   declared-receiver opcodes for the contract. It does NOT
   synthesise a compile error from the open 32-bit opcode
   space; that space is unbounded.
2. **Runtime handling of opcodes not in the declared map.**
   Each `contract` declaration MUST resolve to one of the
   following modes; ambiguity is a compile error. The default
   is **`@unknown_silent_drop`**, matching the dominant
   existing wire convention (`wallet-v5-code.fc:211`,
   FunC `recv_internal` returning silently on unrecognised
   bodies).

   - `@unknown_silent_drop` (default): unknown-opcode message
     causes the synthesised `onInternalMessage` to return
     normally with no actions emitted. Wire-equivalent to the
     existing FunC silent-drop pattern.
   - `@unknown_throw(<error_code>)`: throws the named error.
     For migration parity with `jetton-minter.fc` which uses
     `throw 0xffff` on unknown opcode, authors write
     `@unknown_throw(0xffff)` on the contract. The
     `error_code` is a literal `int` so the wire-level exit
     code is bit-identical to the FunC original.
   - `receive(msg: UnknownOpcode) { ... }`: explicit catch-all
     receiver with full receiver-body privileges (read storage,
     send replies, etc.). Mutually exclusive with the
     `@unknown_*` annotations.

   `UnknownOpcode` itself is a **compiler pseudo-type with no
   wire encoding**; it is never serialised, never has an opcode
   tag, and cannot be used as a `createMessage<TBody>` body
   type. It exists only as a syntactic marker for the
   catch-all receiver.

**Why no string-literal `receive("op_name")` form.** Hashing
a name to an opcode is wire-instability: a future rename of
the receiver changes the opcode and breaks
`tos-message-policy.md` §8.1. Authors who want a
name-indexed dispatch declare a `const OP_NAME = 0xNN` and
attach it to a struct.

**Annotations on `receive`.**

- `@disclaim_query_id` — see §3.2.1 below for per-receiver
  scoping rules.
- `@bounce_only` — receiver only fires on bounced messages.
  Lowers to a branch inside `onBouncedMessage`, not
  `onInternalMessage`.
- `@deploy` — receiver runs **before** `loadData()` in the
  lowered dispatch (§4.1). Marks an initialiser receiver that
  must `save(...)` to materialise storage. At most one
  `@deploy` receiver per contract; multiple is a compile
  error. See §3.6.

#### 3.2.1 `@disclaim_query_id` — per-receiver scope

The Slice 1 `pipe-check-query-id-propagation` pass currently
uses one `disclaimed` boolean per `onInternalMessage` function
(`tol/pipe-check-query-id-propagation.cpp:174`). v2 commits
that the Slice 2 lowering and the pass are extended together
so the disclaim flag is **per-receiver**, not
per-`onInternalMessage`. Concretely:

- The contract→`onInternalMessage` lowering MUST run **before**
  `pipeline_check_query_id_propagation()`. §10.1 lists this as
  an explicit ordering constraint.
- The lowered `onInternalMessage` exposes each receiver's body
  as a sub-tree the check can attribute its `disclaimed`
  signal to. The simplest implementation tags the lowered
  if-arm with a synthetic AST marker (e.g.
  `@__receiver_scope(T)`) the check pass keys off.
- One receiver's `@disclaim_query_id` MUST NOT silence
  warnings emitted from a sibling receiver in the same
  contract.

This is a Slice 2 hard requirement, not a future enhancement.

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
field to the storage struct, named `__state` with double-leading
underscore — a name reserved by the compiler that user code
**cannot** declare. A user-declared field named `__state` is a
compile error pointing at this rule; user code reading
`storage.__state` is also a compile error (use the implicit
state guard on `receive(...) on State` instead).

```tol
struct AuctionStorage {
    // __state: AuctionState  ← injected by the compiler; not user-visible
    highBid: coins;
    highBidder: any_address;
    deadline: uint32;
    payoutsRemaining: uint8;
}
```

The state tag is a real Tol `enum` over the contract's declared
states (`states: Open, Settling, Closed`). v2 binds explicitly
to Tol's existing enum unpack runtime check
(`tol/pack-unpack-serializers.cpp:1341`): if a corrupted c4 cell
deserialises to an out-of-range tag, the runtime throws at
`loadData()` BEFORE any receiver body runs. This means an
attacker who plants a malicious StateInit cannot bypass `@on`
scoping by writing a tag value not in the declared enum range.

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

**`become` and `keep_state` — tail-position rules (v2).**
Every receiver in a state-bearing contract MUST end every
control-flow path with either:
- `become <StaticStateName>;` — transition, emits c4 state-tag
  update at commit phase.
- `keep_state;` — no transition, no tag update.

Absence of either is a **compile error**. The default of
"silently stay" is a known Erlang `gen_statem` foot-gun and is
explicitly excluded.

Both forms are **tail position only**:

- After `become` or `keep_state`, the receiver body terminates
  immediately. Subsequent statements in the same control-flow
  arm are unreachable code and a compile error. This rules out
  `become Closed; read storage.payoutsRemaining;` and the
  `@on`-scope-violation class of bugs codex flagged.
- `become` accepts only a **static identifier** that names a
  declared state. Runtime-target forms like
  `become if (cond) Settling else Closed;` are a compile
  error; authors write `if (cond) become Settling; else become
  Closed;` so the §5
  `pipe-check-state-reachability.cpp` static graph remains
  sound.

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
auto-derives `method_id` from
`calculate_tvm_method_id_by_func_name(name)` —
`crc16(name) | 0x10000` per
`tol/pipe-register-symbols.cpp:78`. **This hash is not
collision-resistant** for arbitrary identifier sets; v2 commits
that the new `pipe-check-receive-exhaustiveness.cpp` pass also
detects same-contract method_id collisions across both
auto-derived `get fun` IDs and explicit `@method_id(N)`
annotations and reports the colliding pair as a compile error.
Different contracts producing the same auto-derived ID is **not**
a problem; method IDs live in each contract's own
`DECLMETHOD` dictionary
(`tol/pipe-generate-fif-output.cpp:255-261`).

An explicit `@method_id(N)` annotation overrides the
auto-derived value; this is the migration escape hatch for
contracts whose external ABI is fixed by an existing TEP
standard.

**v2 implementation note.** Today
`tol/ast-from-tokens.cpp:1712` rejects `@method_id` on
`get fun` declarations and `pipe-generate-fif-output.cpp:261`
only checks `flagContractGetter` collisions. §10.1 lists both
relaxations as Slice 2 PR work.

Inside a `get fun`, `storage` is read-only; mutations are a
compile error. There is no `save(...)` available.

### 3.6 No `init()` block — `@deploy` receiver runs before `loadData()`

Tol does NOT introduce an `init()` keyword for contract
deployment. The TON/TOS deployment convention is unchanged:
a contract is materialised when an internal message carrying
`StateInit` arrives at its address. v1 said "the first executed
receiver IS the deployment handler" without specifying how that
receiver could safely run before `loadData()` had something to
load — v2 fixes this with an explicit `@deploy` annotation.

**`@deploy` annotation.** Authors mark exactly one receiver
with `@deploy` to declare the bootstrap path:

```tol
struct (0x00000001) Deploy {
    queryId: uint64;
    initialAdmin: any_address;
}

contract JettonMinter {
    storage: JettonMinterStorage

    @deploy
    receive(msg: Deploy) {
        // c4 is uninitialized here; storage is NOT in scope.
        // The receiver constructs the initial storage value
        // explicitly via save(...). After this receiver returns,
        // c4 holds the materialised JettonMinterStorage.
        save({
            totalSupply: 0,
            adminAddress: msg.initialAdmin,
            content: emptyCell(),
            jettonWalletCode: emptyCell(),
        });
    }

    receive(msg: ChangeAdmin) { /* normal — `storage` available */ }
}
```

**Lowering rule (§4.1 v2).** The synthesised
`onInternalMessage` dispatches to the `@deploy` receiver
**before** calling `loadData()`. Inside the `@deploy`
receiver body the identifier `storage` is **not in scope**;
references to `storage.X` are a compile error. The receiver
must construct the initial storage via `save(struct_literal)`
and then return.

**Failure mode of a non-Deploy first message.** TVM activates
an uninit account when an inbound message carries a
matching-hash `StateInit` and the message provides enough gas
(`crypto/block/transaction.cpp:2201`); see §6.2 of
`tos-message-policy.md` for the full state-machine. v2 commits
the following deterministic behaviour for a Slice 2 contract
receiving a non-`@deploy` opcode as its first message:

- The synthesised `onInternalMessage` reaches the `loadData()`
  call with c4 empty.
- `loadData()` throws (TVM exit code -1 — "no state" — per
  the v12 bounce body's `bounced_by_phase=0` skip path) and
  the contract bounces if `bounce=true` and the message value
  covers `fwd_fee` (`tos-message-policy.md` §6.2).
- The contract's storage is **not** materialised; subsequent
  inbound messages still see an uninit account.

This is the same observable behaviour an existing FunC
contract has when a non-Deploy message arrives first; Slice 2
does not introduce a new attack surface here. The §4.1 lowering
v2 ordering preserves it.

**Constraints on `@deploy`.**

- At most one `@deploy` receiver per contract; multiple is a
  compile error.
- A contract MAY omit `@deploy` entirely; in that case the
  contract relies on external deployment infrastructure to
  populate c4 before the first message (the existing TON/TOS
  pattern for ext-msg-driven wallets).
- `@deploy` is mutually exclusive with `@bounce_only` and
  `@unknown_silent_drop`-defaulted contracts that have no
  `@deploy` receive must accept the c4-empty-throw bounce
  path on a non-Deploy first message.

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

**Error-code derivation (v2).** Each `require(...)` site
without an explicit third argument is assigned a per-contract
auto-numbered error_code in the application range
(`tos-message-policy.md` §5.2 reserves 0..1023 for stdlib).
v2 specifies the algorithm:

- Auto-numbering starts at `1024` and increments by 1 in
  source order across the contract's receivers, getters, and
  helpers; `@method_id`-pinned overrides do not consume slots.
- Two `require(cond, ErrorClass.X)` calls in the same contract
  receive distinct codes by construction, so the bounce
  message tells operators **which site** fired even when both
  share an `ErrorClass`.
- Slice 3 dogfood migration captures the assigned codes in
  each migrated contract's header table, so the wire-level
  error_code is documented per
  `tos-message-policy.md` §5.3.

`require(...)` accepts an optional third argument
`, error_code: int` for explicit application codes — same
escape hatch as `@method_id(N)`:

```tol
require(msg.amount <= storage.highBid, ErrorClass.Permanent, 1097);
```

This is the Slice 1 reference-migration pattern documented in
`crypto/smartcont/jetton-minter.tol:21` (the explicit
`JETTON_ERROR_*` constants table). v2 makes the pattern
optional rather than mandatory.

### 3.8 `receive_external(msg: T)` — signed-external messages

`wallet-v5` (and any future wallet contract) handles external
messages with Ed25519 signature checks and a seqno; this is
distinct from the internal-message `receive(...)` form. Slice 2
covers external messages with a sibling form:

```tol
struct (0x73696E74) SignedRequest {  // 'sint' prefix per wallet-v5 §3.3
    publicKey: uint256;
    signature: bits512;
    seqno: uint32;
    body: cell;
}

contract WalletV5 {
    storage: WalletV5Storage

    receive_external(msg: SignedRequest) {
        // signature/seqno validation goes here
        require(msg.publicKey == storage.publicKey, ErrorClass.Authorization);
        // ... application logic
    }
}
```

`receive_external` lowers to a synthesised `onExternalMessage`
function (the existing TVM external-message entry) instead of
`onInternalMessage`. All §3.2 rules (32-bit opcode prefix,
`@disclaim_query_id`, `@unknown_*` modes) apply identically.

**v2 scope note.** Slice 2 ships `receive_external` only in the
vocabulary. Built-in signature/seqno helpers (e.g.
`require(verify_ed25519(msg.signature, msg.body, msg.publicKey),
ErrorClass.Authorization)`) are stdlib additions and follow the
same Q3 stdlib timeline as the rest of Slice 3 dogfood. Authors
who need them in Slice 2 use raw TVM intrinsics from
`@stdlib/tvm-lowlevel` (the existing escape hatch).

## 4. Compilation model (lowering contract)

The Slice 2 surface is **fully lowered to the existing Slice 1
substrate** at compile time. No new TVM opcode, no new TL-B
constructor, no new c4 layout discriminator. Concretely:

### 4.1 `contract X { storage: S; receive(msg: T1)... receive(msg: Tn) ... }` lowers to

The lowering matches the operation order of the Slice 1
hand-written reference contracts byte-for-byte
(`crypto/smartcont/jetton-minter.tol:225-232`):

```tol
fun onInternalMessage(in: InMessage) {
    if (in.body.isEmpty()) return;

    // Header parse via a copy slice — keeps in.body intact so
    // each `lazy <T>.fromSlice(in.body)` re-parses from the top
    // including the 32-bit opcode prefix.
    var header = in.body;
    val op = header.loadUint(32);
    val queryId = header.loadUint(64);   // present iff op != 0; see §3.2 of msg policy

    // @deploy receivers run BEFORE loadData() so an empty c4
    // does not throw before init can populate it.
    if (op == op_of(DeployT)) {
        val msg = lazy DeployT.fromSlice(in.body);
        // user body for @deploy receive(msg: DeployT)
        // `storage` identifier is NOT in scope here; user must save(...).
        return;
    }

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

    // Unknown-opcode handling — depends on contract's §3.2 mode:
    //   @unknown_silent_drop (default): just `return;`
    //   @unknown_throw(<N>):              throw N;
    //   receive(msg: UnknownOpcode):       inlined catch-all body
}
```

**Operation-order rationale.** The header parse runs before
`loadData()` so that a malformed body too short to carry both
the 32-bit op and the 64-bit query_id underflows at the same
TVM opcode (`SDU` / `LDU 64`) and at the same exit code as the
Slice 1 hand-written form. v1's `preloadUint(32)` followed by
`loadData()` could load storage on a malformed body before
the queryId underflow fired — observable bounce-shape
divergence per the codex review. v2 closes that gap.

The §3.2 unknown-opcode mode determines the **last branch only**;
the dispatch table for declared receivers does not vary by
mode.

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
3. **`pipe-check-field-scoping.cpp` (v2 expanded).** For each
   `@on(...)` field, traces every read **and every taint
   propagation** outside the listed states. The check is **not**
   purely syntactic in v2; it tracks at minimum these aliasing
   forms:

   - **Local-binding alias.** `val foo = storage.payoutsRemaining`
     inside `@on(Settling)` taints `foo` with the field's
     state-set. Reading `foo` in a control-flow successor whose
     proven state is not in `{Settling}` is a compile error.
     Concretely: a `become Closed; use(foo);` sequence — even
     across a function-call boundary — must error.
   - **`become`-induced state shift.** When `become S` is
     reached, the analysis flips the proven state to `S` for the
     dataflow successor. Since v2 §3.4 mandates that `become`
     is tail-position (no statements after it in the same arm),
     this collapses to "the after-`become` continuation is
     unreachable inside the receiver"; the check reduces to a
     same-receiver-only graph plus the `@initial` entry edge.
   - **Serialisation escape — explicitly forbidden.** Receiver
     bodies inside a `contract` block MAY NOT call any of:
     `storage.toCell()`, `(storage as Cell)`, raw `c4 PUSH`
     intrinsics, or any `@stdlib/tvm-lowlevel` helper that
     reaches into c4 directly. Authors who need raw c4 access
     for a one-shot migration drop out of the `contract` block
     and use the Slice 1 `onInternalMessage` form (§6.3 escape
     hatch). v2 commits the compile-time prohibition; the check
     pass enforces it.

   v2 acknowledges that perfect aliasing analysis is undecidable
   and that determined adversarial authors can still construct
   bypasses (e.g. via reflection helpers that may exist in
   future stdlib). The Slice 2 commitment is that the **dominant
   accidental bypass paths** — local-binding alias and direct
   serialisation — are caught. New reflection / serialisation
   primitives added in future stdlib must extend this taint set
   atomically with their introduction.

The existing Slice 1 `pipe-check-query-id-propagation.cpp`
extension for Slice 2 is described in §3.2.1 (per-receiver
disclaim scoping). The Slice 2 contract→`onInternalMessage`
lowering MUST run before the existing pass; §10.1 lists this
as the first ordering constraint.

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

**v2 caveat for `createMessage<TBody>` reply construction.**
The existing Slice 1 reference migrations
(`crypto/smartcont/jetton-minter.tol:21`,
`crypto/smartcont/jetton-wallet.tol:27`) document that
`createMessage<TBody>` is **not** used for outbound replies
that must be bit-identical to legacy FunC senders, because the
typed wrapper narrows `MsgAddress` to `address` and may
reorder body inline / ref placement. v2 inherits the same
constraint:

- Slice 2 receiver bodies that emit replies subject to the
  §8.1 wire commitment use **raw cell builders** (the existing
  `beginCell().storeUint(...).endCell()` chain), not
  `createMessage<TBody>`.
- The Slice 2 lowering does not implicitly rewrite raw
  builder sites into `createMessage<TBody>` calls.
- Authors who prefer `createMessage<TBody>` for new reply paths
  outside §8.1's scope (e.g. application-defined opcodes that
  did not exist before Slice 1) MAY use it; the check pass
  permits it but does not introduce it.

**v2 caveat for `UnknownOpcode` wire encoding.** Per §3.2 v2,
`UnknownOpcode` is a compiler pseudo-type. It has **no
struct prefix**, **no wire encoding**, and **never appears**
on the wire. It cannot be passed as a `createMessage<TBody>`
body type; doing so is a compile error.

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
- Per-receiver gas budgets / inbound value floors. These are
  DoS-protection primitives; they belong in a future Slice 4+
  policy that also covers cross-shard delivery SLA
  (`actor.md` §5.7). Slice 2 receivers continue to use
  hand-written `require(in.valueCoins >= MIN_VALUE,
  ErrorClass.Permanent)` checks where wire compatibility
  permits.
- Reentrancy / `COMMIT` semantics primitive. TVM has no
  synchronous reentrance during compute, but `COMMIT`
  (`crypto/smartcont/tol-stdlib/common.tol:421`) persists
  c4 / c5 even if later code throws. Slice 2 receiver bodies
  inherit the existing TVM commit model exactly; a Tol-level
  `commit_partial` or `rollback_after_send` primitive is
  out of scope. Authors are advised in the migration playbook
  to avoid `COMMIT` mid-receiver unless the existing FunC
  reference contract did so.
- Built-in signature/seqno helpers for `receive_external`
  (§3.8). Slice 2 ships the keyword; the canonical Ed25519 +
  seqno helpers ship as Q3 stdlib alongside the Slice 3
  dogfood migration of `wallet-v5`.

## 9. Open questions (for second review)

The §3 decisions remain locked. v2 closes the four BLOCKER
findings and nine HIGH findings raised by the v1 codex
security review; the questions below are the remaining
tactical items. They affect implementation tactics but do not
invalidate the lowering contract or backwards-compatibility
commitments above.

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
4. **`UnknownOpcode` reserved type — namespace.** Lives in
   `@stdlib/common` alongside `Envelope`/`Error`, or in a new
   `@stdlib/contract`? v2 already locks that it is a compiler
   pseudo-type with no wire encoding (§3.2, §6.1); the only
   open item is which import path declares it.
5. **`@bounce_only` receiver lowering target.** Branches into
   `onBouncedMessage` directly, or shares dispatch with the
   inbound path under a flag? The latter is simpler; the
   former is more obvious. Pick after profiling Slice 3.
6. **`save(...)` partial-update sugar.** `save({ ...storage,
   x: y })` is the spread form; do we also support
   `save.x(y)` for single-field updates? Not blocking; defer
   to later DX iteration.
7. **Auto-numbered `require` error_code reservation window.**
   v2 §3.7 starts auto-numbering at 1024. Should the window
   be per-contract independent or globally namespaced (so
   external observers can map a returned code to a single
   contract)? Recommendation pending audit-team input.
8. **`@deploy` + state-bearing contract interaction.** If a
   contract has both `states:` and a `@deploy` receiver, does
   `become` inside `@deploy` set the initial state, or is the
   `@initial` annotation authoritative? v2 expects the latter
   (`become` in `@deploy` is a redundant compile error if the
   target equals `@initial`'s state) but the rule is not yet
   exercised by any reference migration.

These do not block Stage 0 sign-off but should be resolved
before the parser PR lands.

## 10. Constraints on Slice 2 implementation

The following items are the implementable subset of this
policy. Items outside this list are deferred regardless of how
clearly the policy describes them.

### 10.1 In Slice 2

- New parser productions for `contract`, `receive`,
  `receive_external`, `become`, `keep_state`, `states:`,
  `@initial`, `@on`, `@deploy`, `@unknown_silent_drop`,
  `@unknown_throw`, `get fun`, `require`. AST node additions
  in `tol/ast.h`.
- **Parser fix in `tol/ast-from-tokens.cpp:1712`** — currently
  rejects `@method_id(N)` on `get fun`; v2 RFC §3.5 requires
  this combination to be accepted. Same PR that adds
  `get fun` accepts `@method_id` on it.
- **Method-id collision detector in
  `tol/pipe-generate-fif-output.cpp:261`** — currently checks
  `flagContractGetter` collisions only; v2 §3.5 requires
  detection across both auto-derived and `@method_id`-pinned
  IDs in the same contract.
- **32-bit opcode prefix enforcement in
  `tol/pipe-register-symbols.cpp:45`** — variable prefix
  width remains the default for free-floating structs; inside
  `contract { receive(...) }`, the compiler rejects any
  struct with a non-32-bit declared prefix and points the
  author at §3.2 for the rule.
- Three new compiler passes
  (`pipe-check-receive-exhaustiveness.cpp`,
  `pipe-check-state-reachability.cpp`,
  `pipe-check-field-scoping.cpp` — v2-expanded with taint
  analysis per §5), all in the policy-mandated band between
  `pipeline_check_serialized_fields()` and the
  `error_collector = nullptr;` teardown.
- **Pass-ordering hardening in `tol/tol.cpp` 60-114.** The new
  contract→`onInternalMessage` lowering pass runs **before**
  `pipeline_check_query_id_propagation()`. Slice 2 PR adds an
  ordering assertion in `tol.cpp` (a static assert / runtime
  position check, mirror of the §4.4 hardening already in
  place for `pipe-check-query-id-propagation` itself).
- **`pipe-check-query-id-propagation.cpp:174` per-receiver
  scope.** v2 §3.2.1 requires the existing pass's single
  `disclaimed` boolean to be replaced with per-receiver
  tracking. The lowering tags each synthesised dispatch arm
  with a receiver-scope marker the check pass keys off.
- AST → legacy-Expr-Op IR lowering producing the exact
  `onInternalMessage` shape described in §4.1, in particular
  the v2 operation order (header parse → `@deploy` branch →
  `loadData()` → dispatch).
- **Synthesised state enum** declared as a real Tol `enum`
  per the contract's `states:` list, packed via the existing
  `tol/pack-unpack-serializers.cpp:1341` runtime tag-validity
  check. This binds the policy's "out-of-range tag throws at
  loadData" guarantee to existing infrastructure rather than
  introducing a new check.
- `UnknownOpcode` reserved type in `@stdlib/common` as a
  compiler pseudo-type with no wire encoding (§3.2 v2 + §6.1
  v2 caveat).
- New `tol-tester/tests/contract-*.tol` cases covering: a
  minimal one-receive contract, a multi-receive contract, a
  state-bearing contract with `become`/`keep_state`, an
  exhaustiveness-warning case, a reachability-error case, a
  field-scoping-error case, an alias-bypass case (negative —
  must error), a get-fun auto-method-id case, an
  `@deploy`-receiver-runs-before-loadData case, an
  `@unknown_silent_drop` wallet-v5-style case, an
  `@unknown_throw(0xffff)` minter-style case, and a
  `receive_external` skeleton.
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

### Draft v2 (2026-04-30, post-codex-security-review)

Closes the four BLOCKER and nine HIGH findings from the v1
codex security review (`/tmp/codex_output.md`). The §3
first-principles decisions stand; v2 adds the lowering-order
specificity, deployment-path soundness, unknown-opcode
compatibility, and pass-ordering rules that v1 had under-
specified. The wire-bit-identity commitment (§6.1) is
preserved verbatim.

Concrete deltas from v1 to v2:

- **§3.2 (BLOCKER+HIGH).** Two BLOCKERs and three HIGHs
  closed.
  - 32-bit opcode prefix is now enforced for receivers; the
    free-floating-struct prefix-width inference at
    `tol/pipe-register-symbols.cpp:45` is overridden inside
    `contract { receive(...) }` blocks.
  - Unknown-opcode handling split into two rules:
    compile-time exhaustiveness over the *declared* opcode
    set, and runtime handling via three modes
    (`@unknown_silent_drop` default — wire-equivalent to
    wallet-v5's silent return; `@unknown_throw(<N>)` — pinned
    code for jetton-minter's `0xffff`; explicit
    `receive(msg: UnknownOpcode)` catch-all). v1 said the
    open 32-bit opcode space was a compile error, which was
    never honourable.
  - `UnknownOpcode` declared as a compiler pseudo-type with
    no wire encoding (§3.2, §6.1 v2 caveat).
  - New §3.2.1 fixes the disclaim_query_id BLOCKER: per-
    receiver scoping and explicit pass-ordering constraint.
- **§3.4 (HIGH+HIGH).** Both HIGHs closed.
  - `become` is now a tail position; statements after it in
    the same arm are unreachable code and a compile error.
    Closes the "post-`become` storage read" footgun.
  - `become` accepts only static identifiers; runtime-target
    forms like `become if (cond) A else B` are a compile
    error so the §5 reachability graph remains sound.
  - Synthetic state field renamed from `state` to `__state`
    (compiler-reserved namespace) to avoid collision with
    user-declared fields. The v1 wording of "do not declare
    manually" is now a compile-time enforced rule.
  - State tag is bound to Tol's existing `enum` runtime
    tag-validity check
    (`tol/pack-unpack-serializers.cpp:1341`); a corrupted c4
    cell with out-of-range tag throws at `loadData()` BEFORE
    any receiver body runs.
- **§3.5 (HIGH+MEDIUM).** Both closed.
  - `compute_method_id` named explicitly as
    `crc16(name) | 0x10000` per
    `tol/pipe-register-symbols.cpp:78`; not collision-
    resistant for arbitrary identifier sets.
  - v2 requires same-contract collision detection across
    both auto-derived and `@method_id`-pinned IDs
    (currently `tol/pipe-generate-fif-output.cpp:261` checks
    only `flagContractGetter`).
  - v2 requires the parser fix at
    `tol/ast-from-tokens.cpp:1712` to accept `@method_id`
    on `get fun`.
- **§3.6 (BLOCKER×2).** Both BLOCKERs closed.
  - New `@deploy` annotation marks a receiver that runs
    BEFORE `loadData()` (§4.1 v2 lowering order). The
    `storage` identifier is not in scope inside the receiver;
    user code constructs initial storage via `save(...)`.
  - First-non-Deploy-message failure mode documented:
    deterministic bounce via the v12 `bounced_by_phase=0`
    skip path. No new attack surface is introduced; the
    behaviour matches existing FunC contracts.
- **§3.7 (HIGH+MEDIUM).** Both closed.
  - Auto-numbered error_code algorithm specified: per-contract
    counter starting at 1024, deterministic in source order.
    Two `require(..., ErrorClass.X)` sites in the same
    contract are wire-distinguishable for debugging.
- **§3.8 (HIGH).** New section adds `receive_external(msg: T)`
  for wallet-v5-style signed external messages, lowered to
  `onExternalMessage`. Built-in signature/seqno helpers
  remain Q3 stdlib follow-up.
- **§4.1 (BLOCKER).** Lowering order rewritten to match the
  Slice 1 reference shape verbatim
  (`crypto/smartcont/jetton-minter.tol:225-232`):
  empty-check → header-copy parse (op + queryId) →
  `@deploy` branch (no loadData) → `loadData()` → dispatch.
  Closes the "v1 loaded storage on malformed bodies before
  queryId underflow" wire-divergence BLOCKER.
- **§5 (HIGH).** `pipe-check-field-scoping.cpp` upgraded
  from purely-syntactic to taint-tracking: local-binding
  aliases are tainted with the source field's state-set;
  serialisation-escape primitives (`storage.toCell()`, raw
  c4 intrinsics) are forbidden inside `contract { ... }`
  blocks.
- **§6.1 (HIGH+MEDIUM).** Wire-shape commitment expanded with
  the explicit `createMessage<TBody>` caveat: receiver bodies
  emitting §8.1-pinned replies use raw cell builders, not the
  typed wrapper. The Slice 1 jetton-minter / jetton-wallet
  comments at lines 21 / 27 are the precedent.
- **§8.** Out-of-scope list expanded: per-receiver gas
  budgets / value floors (Slice 4+ DoS-protection layer);
  reentrancy / `COMMIT` rollback primitive; built-in
  signature/seqno helpers.
- **§9.** Open questions revised: items 4, 7, 8 are new;
  item 4 narrows from "is `UnknownOpcode` a real type?" (now
  locked: pseudo-type) to "which import path declares it?".
- **§10.1.** Concrete v2 implementation list now includes the
  three parser/codegen file fixes (line numbers cited),
  pass-ordering hardening, and the additional tol-tester
  cases for `@deploy` / `@unknown_*` / `receive_external` /
  alias-bypass-negative.

Wire format unchanged; TL-B schema unchanged;
`tos-message-policy.md` §8.1 commitments preserved verbatim.
v2 is purely a security-driven tightening of v1 against the
in-tree code and the existing reference migrations.

### Draft v1 (2026-04-30)

Initial draft. Authored as Stage 0 input for `doc/roadmap.md`
Slice 2 (week 27–52). The §3 decisions on dispatch form,
storage shape, state-machine layout, transition discipline,
init handling, and opcode-binding are locked from
first-principles analysis: (a) eliminate one of the five
convention costs identified in §1, and (b) preserve the
`tos-message-policy.md` §8.1 wire commitment. Open questions in
§9 are tactical, not structural.
