# FunC v0.5.0 AI Primer

Version: v1 (companion to `doc/func_v0.5.0.tex` v4 + `doc/func_v0.5.0-corpus.md` v2)
Purpose: compressed, directly-useable material for feeding a large language model so it writes correct TOS/FunC v0.5.0 v4 smart-contract code on the first pass.

This document is designed to be pasted — in whole or by section — into a system prompt, a project instruction file, a RAG chunk store, or a fine-tuning corpus. It is the practical distillation of the full language specification. When in doubt the full spec wins.

---

## 0. What FunC v0.5.0 v4 Is (one-paragraph primer)

FunC v0.5.0 is a smart-contract language for the TOS blockchain that compiles to TVM via Fift. It is the successor to FunC 0.4.6. v4 is the simplified surface: one `contract { }` block groups state + errors + messages + entries + getters; `require!(cond, err)` replaces `throw_unless(N, cond)`; typed message declarations replace manual opcode parsing; `Signed<T>` stdlib type handles wallet signatures; `asm { ... }` is the only escape hatch to raw Fift. There is **no `?` operator**, **no `Result<T, E>` default**, **no `&self`/`&mut self` borrows**, **no async/await**, **no macros except `require!` / `emit` / `asm`**. Failures abort the whole transaction; the wrapper around each entry function auto-loads state before the body and auto-commits state after the body on normal return.

---

## 1. HARD RULES (paste first into any system prompt)

```
================================================================
FunC v0.5.0 v4 — HARD RULES
================================================================

You MUST NOT use:
  - `?` postfix operator (doesn't exist in v4)
  - `Result<T, E>` in return types of ordinary stdlib or user code
    (only in the rare case of a genuinely recoverable cross-contract
     branch)
  - `Ok(...)` / `Err(...)` as pervasive idioms (only appear in the
     niche Result paths)
  - `&self`, `&mut self`, `&T`, `&mut T` — there are no borrows
  - `async`, `await`, `.then()`, `.await()` — TVM is async by protocol
     but the source language is not
  - macros other than `require!`, `emit`, and `asm` — no `macro_rules!`,
     no procedural macros
  - `Vec<u8>` when you mean byte data — use `Slice` or `Bytes`
  - `Box<T>`, `Rc<T>`, `Arc<T>` — there is no heap model
  - `impure` keyword — removed
  - `throw_unless(N, cond)` — replaced by `require!(cond, Name)`
  - `entry` keyword — removed; use `external fn` / `internal fn` /
     `bounce fn` / `get fn` inside a contract block
  - manual `let mut state = load_state()` / `save_state(state)` —
     the wrapper does this for you; use `state.field` directly
  - custom generics / trait impls in day-to-day contract code (they
     exist for stdlib authors but are almost never needed in a
     contract)
  - `String` / `&str` — use `Bytes` if you need strings, but most
     contracts don't
  - `unsafe` blocks — `unsafe` is only a top-level function qualifier
  - Solidity-style `require(cond, "string message")` — require! takes
     an error enum variant, not a string

You MUST use:
  - `#![edition = "0.5.0"]` at the top of each source file
  - `contract Name { ... }` block as the top-level shape
  - `state { field: T, ... }` inside the contract block
  - `error Name1 = N1, Name2 = N2, ...;` for error codes
  - `message MyMsg(op = 0xHEX) { fields }` for wire-bound messages
  - `require!(cond, ErrorName)` for validation
  - `emit Event { field1, field2 }` for emitting events
  - `match msg { Variant::A(x) => ..., Variant::B(y) => ... }` for
     dispatch
  - Typed message as entry parameter:
       external fn recv(msg: Signed<Payload>) { ... }
       internal fn recv(msg: MyEnum)        { ... }
       bounce   fn on_bounce(ctx: BounceContext<T>) { ... }
       get      fn name() -> T { state.x }
  - `state.field` directly inside entry body (no manual load)
  - `ctx.sender` / `ctx.value` / `ctx.forward_fee` inside internal fn
    body (not inside external fn — external has no ctx)
  - `send(dst, body, SendOptions { ... })` for typed outgoing messages
  - `asm { """ FIFT_OPCODES """ }` inside `unsafe fn` for anything
    the high-level surface can't express

Failures are aborts. Do not wrap validation in Result. When you see
"the operation might fail", write `require!(cond, ErrorName)` — the
exit code is the numeric discriminant of `ErrorName`.
================================================================
```

---

## 2. CANONICAL CONTRACT SKELETON

```func
#![edition = "0.5.0"]

contract MyContract {
    // --- Persistent state (auto-loaded before each entry) ---
    state {
        seqno:      u32,
        owner:      Address,
        pubkey:     u256,
    }

    // --- Error codes (preserve legacy numeric values for ABI parity) ---
    error WrongSeqno     = 33,
          NotOwner       = 34,
          BadSignature   = 35,
          Expired        = 35,
          WrongGlobalId  = 36;

    // --- Wire-level message schemas ---
    message Transfer(op = 0x0f8a7ea5) {
        query_id: u64,
        amount:   Coins,
        to:       Address,
    }

    // --- Entry points (implicit state and ctx in scope) ---
    external fn recv(msg: Signed<Payload>) {
        require!(msg.check(state.pubkey), BadSignature);
        accept_message();
        // body logic...
    }

    internal fn on_transfer(msg: Transfer) {
        require!(ctx.sender == state.owner, NotOwner);
        // body logic...
        send(
            msg.to,
            (),
            SendOptions {
                value:       msg.amount,
                bounce:      BounceMode::Body256,
                body_layout: BodyLayout::Auto,
                mode:        SendMode::PayFeesSeparately,
            },
        );
        state.seqno += 1;
    }

    bounce fn on_bounce(ctx: BounceContext<Transfer>) {
        // refund or compensate
    }

    get fn seqno()  -> u32  { state.seqno }
    get fn pubkey() -> u256 { state.pubkey }
}
```

This is the skeleton every v0.5.0 contract begins with. When asked to write a new contract, generate this shape first, then fill in details.

---

## 3. SYNTAX CHEAT SHEET

| Task | v0.5.0 v4 syntax |
|------|------------------|
| Immutable binding | `let x = 1;` |
| Mutable binding | `let mut x = 1;` |
| Type annotation | `let x: u32 = 1;` |
| Tuple destructuring | `let (a, b) = (1, 2);` |
| Struct field update | `state.seqno = state.seqno + 1;` or `state.seqno += 1;` |
| Constructor call | `Transfer { query_id: 0, amount: c, to: a }` |
| Path access | `WalletMsg::Transfer(t)` |
| Pattern match (exhaustive) | `match v { V::A(x) => ..., V::B => ... }` |
| Optional unpack | `if let Some(x) = opt { ... }` |
| Loop with optional | `while let Some(x) = iter.next() { ... }` |
| Early exit on failure | `require!(cond, ErrorName);` |
| Emit event | `emit EventName { field1, field2 };` |
| Function call | `foo(a, b)` |
| Method call | `slice.load_uint(32)` |
| Mutable method call | `let mut s = slice; s.load_uint(32);` |
| Cast | `x as u32` |
| Comparison | `a == b`, `a < b`, etc. (non-chainable) |
| Logical | `a && b`, `a || b`, `!a` |
| Bitwise | `a & b`, `a | b`, `a ^ b`, `a << b` |
| Option sugar | `Address?` means `Option<Address>` |
| Asm escape (inline) | `asm(x) -> (u256) { """ HASHSU """ }` |
| Asm escape (whole fn) | `fn hash() -> u256 unsafe asm "HASHSU";` |

---

## 4. COMMON PATTERNS LIBRARY (15 recipes)

### 4.1 Read persistent state
```func
get fn my_field() -> T { state.my_field }
```

### 4.2 Write persistent state (inside any entry)
```func
internal fn foo(msg: Whatever) {
    state.counter += 1;
    // wrapper auto-commits on normal return
}
```

### 4.3 Check sender is owner
```func
internal fn privileged(msg: Op) {
    require!(ctx.sender == state.owner, NotOwner);
    // ...
}
```

### 4.4 Check signature on an external wallet
```func
external fn recv(msg: Signed<Payload>) {
    require!(msg.check(state.pubkey), BadSignature);
    accept_message();
    // ...
}
```

### 4.5 Dispatch on multiple internal message opcodes
```func
enum MyMsg {
    A(MessageA),   // each variant wraps a message(op = ...) declaration
    B(MessageB),
    C(MessageC),
}

internal fn recv(msg: MyMsg) {
    match msg {
        MyMsg::A(a) => on_a(mut state, a),
        MyMsg::B(b) => on_b(mut state, b),
        MyMsg::C(c) => on_c(mut state, c),
    }
}
```

### 4.6 Send a typed outgoing message
```func
send(
    destination,
    MyOutboundBody { field1: v1, field2: v2 },
    SendOptions {
        value:       Coins::from_nanos(1_000_000_000),
        bounce:      BounceMode::Body256,
        body_layout: BodyLayout::Auto,
        mode:        SendMode::PayFeesSeparately,
    },
);
```

### 4.7 Send with no body
```func
send(dst, (), SendOptions { value: amount, bounce: BounceMode::Body256,
    body_layout: BodyLayout::Auto, mode: SendMode::PayFeesSeparately });
```

### 4.8 Emit an event
```func
message Transferred(op = 0xdeadbeef) {
    from: Address, to: Address, amount: Coins,
}

emit Transferred { from: state.owner, to: dst, amount: amount };
```

### 4.9 Iterate a Dict in sorted order
```func
for (key, value) in state.my_dict.iter_sorted() {
    // process (key, value)
}
```

### 4.10 Trim a Dict from the bottom (conditional)
```func
while let Some((min_key, _)) = state.my_dict.pop_min() {
    if min_key >= cutoff {
        state.my_dict.insert(min_key, ());   // put back and stop
        break;
    }
    // min_key is processed/discarded
}
```

### 4.11 Insert / remove / contains
```func
state.dict.insert(key, value);
state.dict.remove(&key);
let present = state.dict.contains(&key);
let maybe_v = state.dict.get(&key);     // -> Option<V>
```

### 4.12 Optional-value handling
```func
if let Some(addr) = msg.response_to {
    send(addr, ReceiptBody { query_id: msg.query_id }, opts);
}
```

### 4.13 Declare a helper that mutates state
```func
fn on_transfer(mut state: MyState, sender: Address, req: Transfer) {
    require!(sender == state.owner, NotOwner);
    state.balance -= req.amount;
}

// Call from entry body:
internal fn recv(msg: Transfer) {
    on_transfer(mut state, ctx.sender, msg);
}
```

### 4.14 Bounce handler
```func
bounce fn on_bounce(ctx: BounceContext<OutboundTransfer>) {
    // The receiving wallet rejected our transfer. Refund.
    state.balance += ctx.body.amount;
}
```

### 4.15 Escape to asm for a TVM opcode the stdlib doesn't wrap
```func
fn bit_reverse_u64(x: u64) -> u64 unsafe asm "64 REVERSE";
// single-line form — the quoted string is one Fift instruction

fn slice_double_hash(s: Slice) -> u512 unsafe asm {
    """
    HASHSU
    DUP
    HASHSU
    """
}
// multi-line form for multi-instruction sequences
```

---

## 5. STDLIB QUICK REFERENCE

### `std::prelude` (auto-imported)
```
Option<T>, Some, None
Result<T, E>, Ok, Err            // niche use only
require! macro
emit macro
```

### `std::cell`
```
Cell<T>              // typed cell reference
RawCell, Builder, Slice, RawSlice
to_cell(x) -> Cell<T>
from_cell(c: Cell<T>) -> T       // aborts on decode failure
load_any<T>(s: Slice) -> T       // aborts on decode failure
store_any<T>(b: Builder, v: T) -> Builder
```

### `std::slice` / `std::builder` (methods)
```
impl Slice {
    load_uint(mut self, bits: u16) -> u256    // aborts on underflow
    load_int (mut self, bits: u16) -> i257
    load_ref (mut self)            -> RawCell
    load_addr(mut self)            -> Address
    load_bits(mut self, n: u16)    -> bits(n)
    remaining_bits(self) -> u16
    remaining_refs(self) -> u8
    refs(self) -> u8      // alias
    end_parse(self)       // asserts empty
    hash(self) -> u256    // slice_hash
}

impl Builder {
    Builder::new() -> Builder
    store_uint   (mut self, v: u256,  bits: u16) -> Self
    store_int    (mut self, v: i257,  bits: u16) -> Self
    store_ref    (mut self, c: RawCell)          -> Self
    store_address(mut self, a: Address)          -> Self
    store_coins  (mut self, c: Coins)            -> Self
    store_slice  (mut self, s: Slice)            -> Self
    end_cell(self) -> RawCell
}
```

### `std::address`
```
Address, StdAddress
parse_std_addr(a: Address) -> (i8, u256)   // (workchain, addr_hash)
Address::derive(code: Cell<_>, data: Cell<_>) -> Address
```

### `std::coins`
```
Coins
Coins::zero() -> Coins
Coins::from_nanos(n: u128) -> Coins
Coins::is_zero(self) -> bool
Coins arithmetic: +, -, *, /, <, <=, >, >=, ==, !=
```

### `std::bytes`
```
Bytes                      // byte-aligned Slice
LenPrefixedBytes           // u16 length + bytes
```

### `std::vec`
```
Vec<T>                     // stack = TVM tuple; wire = u16 prefix + items + tail refs
EitherRefOrInline<T>       // TL-B (Either X ^X)
```

### `std::dict`
```
Dict<K, V>
impl<K: Hashable, V> Dict<K, V> {
    insert(mut self, k: K, v: V)
    remove(mut self, k: &K) -> Option<V>
    get(self, k: &K) -> Option<V>
    contains(self, k: &K) -> bool
    pop_min(mut self) -> Option<(K, V)>
    pop_max(mut self) -> Option<(K, V)>
    iter_sorted(self) -> impl Iter<Item = (K, V)>
    is_empty(self) -> bool
}
```

### `std::crypto`
```
check_signature(hash: u256, sig: bits512, pubkey: u256) -> bool
slice_hash(s: Slice) -> u256
sha256(data: Bytes) -> u256
keccak256(data: Bytes) -> u256
```

### `std::chain`
```
now() -> u32                   // current unix time
global_id() -> i32             // chain global id
accept_message()               // accept external, exit 10k-gas quota
balance() -> Coins             // contract's own balance
get_data() -> RawCell          // persistent data cell (low-level; authors rarely call)
set_data(c: RawCell)           // (low-level; authors rarely call)
raw_reserve(amount: Coins, mode: u8)
```

### `std::message`
```
Signed<T> { signature: bits512, body: T }
impl<T: CellEncode> Signed<T> { check(self, pubkey: u256) -> bool }

BounceContext<T = Slice> { sender: Address, value: Coins, body: T }

send<T: CellEncode>(dst: Address, body: T, opts: SendOptions) effect(send)
send_raw(msg: RawCell, mode: u8) effect(send)

struct SendOptions {
    value: Coins,
    bounce: BounceMode,
    body_layout: BodyLayout,
    mode: SendMode,
}

enum BounceMode { NoBounce, Body256, Rich }
enum BodyLayout { Auto, Inline, ByRef }
enum SendMode {
    Ordinary             = 0,
    PayFeesSeparately    = 1,
    IgnoreErrors         = 2,
    CarryInboundValue    = 64,
    CarryAllBalance      = 128,
    DestroyIfZero        = 32,
}
// SendMode values are bit flags; combine with |
```

### `std::iter`
```
trait Iter     { type Item; fn next(mut self) -> Option<Self::Item>; }
trait IntoIter { type Item; type IntoIterTy: Iter<Item = Self::Item>;
                 fn into_iter(self) -> Self::IntoIterTy; }
```

---

## 6. TEP OPCODE CONSTANTS (wire standards)

### Jetton (TEP-74)
```
0x0f8a7ea5  Transfer                 (wallet <- owner)
0x178d4519  InternalTransfer         (wallet <- wallet)
0x7362d09c  TransferNotification     (recipient <- wallet)
0x595f07bc  Burn                     (wallet <- owner)
0x7bdd97de  BurnNotification         (master <- wallet)
0xd53276db  Excesses                 (caller <- wallet)
0x2c76b973  ProvideWalletAddress     (master <- anyone)
0xd1735400  TakeWalletAddress        (caller <- master)
```

### NFT (TEP-62)
```
0x5fcc3d14  NFTTransfer
0x05138d91  OwnershipAssigned
0x2fcb26a2  GetStaticData
0x8b771735  ReportStaticData
```

### Wallet
```
0x706c7567  Plugin ping    ("plug")
0x64737472  Dstr           ("dstr", destroy)
```

### Generic
```
0x00000000  Text comment (followed by UTF-8 payload)
0xffffffff  Bounce-message header
```

Authors commonly define custom opcodes in the `0x10000000`..`0xefffffff` range to avoid collision with TEP standards.

---

## 7. EXIT CODE TABLE

```
0            Success (reserved)
1 - 10       TVM internal
  8            Range check
  9            Cell underflow
  10           Dict operation
11 - 31      TOS protocol reserved
  11           Unknown op
  13           Invalid standard address
32 - 400     TON wallet + Jetton conventions (legacy, preserve for ABI parity)
  32           Unknown query id / duplicate query id
  33           Wrong seqno
  34           Wrong subwallet id / wrong argument
  35           Bad signature / expired
  36           Wrong global id
  37           Insufficient funds
  38           Insufficient gas
  100          (Jetton) Not enough Tons
  101          (Jetton) Unauthorised
  102          (Jetton) Not enough Jettons
401 - 65535  User-defined
```

Always assign legacy codes where existing tooling expects them; only reach into 401+ for truly new error categories.

---

## 8. ANTI-PATTERNS (what AI generators get wrong)

Watch for these specific errors. Each is a strong signal that generated code is wrong.

### 8.1 Reached for `?`
```
WRONG:  let x = body.load_uint(32)?;
RIGHT:  let x = body.load_uint(32);
```

### 8.2 Wrapped value in `Result`
```
WRONG:  pub fn save_state(s: State) -> Result<(), CellError>
RIGHT:  pub fn save_state(s: State) -> ()          // aborts on fail
WRONG:  return Err(WalletError::WrongSeqno);
RIGHT:  require!(cond, WrongSeqno);
```

### 8.3 Used `throw_unless` (legacy 0.4.6)
```
WRONG:  throw_unless(33, cond);
RIGHT:  require!(cond, WrongSeqno);   // needs error WrongSeqno = 33;
```

### 8.4 Used `&self` / `&mut self`
```
WRONG:  impl MyState { fn bump(&mut self) { self.x += 1; } }
RIGHT:  fn bump(mut s: MyState) -> MyState { s.x += 1; s }
  or inline:  state.x += 1;     // inside entry body, state is implicit
```

### 8.5 Declared entry with `entry` keyword (v3 style, removed)
```
WRONG:  entry internal fn recv_internal(...) -> ... { ... }
RIGHT:  internal fn recv(msg: MyMsg) { ... }       // inside contract block
```

### 8.6 Manually loaded / saved state inside entry body
```
WRONG:  internal fn foo(msg: M) {
            let mut state = load_state();
            state.x += 1;
            save_state(state);
        }
RIGHT:  internal fn foo(msg: M) {
            state.x += 1;         // wrapper handles load + save
        }
```

### 8.7 Used context wrapper types
```
WRONG:  internal fn recv(ctx: InternalContext<Transfer>) { ... }
RIGHT:  internal fn recv(msg: Transfer) { ... }     // ctx is implicit
```

### 8.8 Used string in `require!`
```
WRONG:  require!(cond, "wrong seqno");
RIGHT:  error WrongSeqno = 33;
        require!(cond, WrongSeqno);
```

### 8.9 Used `impure` qualifier
```
WRONG:  fn helper() impure { ... }
RIGHT:  fn helper() { ... }             // effect inferred by default
  or:   fn helper() effect(read) { ... }  // optional explicit restriction
```

### 8.10 Attempted synchronous call
```
WRONG:  let balance = other_contract.get_balance();   // TVM has no sync call
RIGHT:  // send a query message, handle the reply in another entry
        send(other, GetBalanceQuery { }, opts);
        // ... in a subsequent internal fn on_balance_reply(msg: BalanceReply) { ... }
```

### 8.11 Called `accept_message()` inside `internal fn`
```
WRONG:  internal fn recv(msg: M) { accept_message(); /* does nothing useful */ }
RIGHT:  // internal messages are already "accepted"; only external fn needs it
```

### 8.12 Forgot `accept_message()` in `external fn`
```
WRONG:  external fn recv(msg: Signed<Payload>) {
            // signature check then heavy work WITHOUT accept_message
        }
RIGHT:  external fn recv(msg: Signed<Payload>) {
            require!(msg.check(state.pubkey), BadSignature);
            accept_message();                // MUST come before expensive ops
            // ... actual work here, paid from contract balance ...
        }
```

### 8.13 Wrote `Option<T>` constructor with dot access
```
WRONG:  Option::Some(x)         // not needed
RIGHT:  Some(x)                 // prelude-imported
WRONG:  opt.Some(x)             // not a method call
```

### 8.14 Used `switch` / C-style if-else chain instead of `match`
```
WRONG:  if (op == A) { ... }
        else if (op == B) { ... }
        else { ... }
RIGHT:  match msg {
            MyMsg::A(a) => ...,
            MyMsg::B(b) => ...,
        }
```

### 8.15 Generic trait bound in a contract-local helper
```
WRONG:  fn send_typed<T: CellEncode>(t: T) { ... }    // trait bound in user code
RIGHT:  // stdlib already has send<T: CellEncode>(...); just use it
```

### 8.16 Declared `pub fn` for a helper that only the contract uses
```
SUSPECT:  pub fn _internal_helper(...)
BETTER:   fn _internal_helper(...)       // not pub unless cross-module
```

### 8.17 Wrote bounce handler without bounds check
```
WRONG:  bounce fn on_bounce(ctx: BounceContext<BigMsg>) { ... }
          // where BigMsg > 256 bits — compile error BounceBodyTooWide
RIGHT:  either narrow the message, or use:
        bounce fn on_bounce(ctx: BounceContext<Slice>) { /* manual parse */ }
```

### 8.18 Put a non-trailing `Slice` field
```
WRONG:  message M { body: Slice, tail: u32 }       // TailFieldNotLast
RIGHT:  message M { tail: u32, body: Slice }       // Slice must be last
```

### 8.19 Mixed up `send` and `send_raw`
```
send(dst, typed_body, opts)    // HIGH-LEVEL: body auto-encoded, envelope built
send_raw(raw_cell, mode)       // LOW-LEVEL: caller already built the full message cell
```

### 8.20 Assumed immutable `state` in `get fn`
```
VALID:  get fn x() -> u32 { state.x }     // reading state is fine
WRONG:  get fn x() -> u32 { state.x += 1; state.x }   // writing is a compile error;
                                                       // `get` effect ceiling forbids write
```

---

## 9. VERIFICATION CHECKLIST

Before returning generated code, self-check against this list:

```
SYNTAX:
[ ] Source starts with #![edition = "0.5.0"]
[ ] Top-level item is `contract Name { ... }` (unless intentionally a library)
[ ] Inside contract block: state { }, error ..., message ..., fn items
[ ] No `?` operator anywhere
[ ] No `Result<T, E>` in ordinary function return types (only niche use)
[ ] No `&self` / `&mut self` / `&T` / `&mut T`
[ ] No `impure`, no `throw_unless`, no `entry` keyword
[ ] No manual `load_state()` / `save_state()`
[ ] No `InternalContext<T>` / `ExternalContext<T>` wrappers
[ ] Helpers that mutate state take `mut state: MyState` parameter
[ ] All `match` statements are exhaustive or have a `_` arm

SEMANTIC:
[ ] external fn declares `Signed<T>` or a plain typed message
[ ] external fn calls `accept_message()` after signature check
[ ] internal fn uses `ctx.sender` / `ctx.value` as needed (not external fn)
[ ] bounce fn's typed body fits 256 bits with zero refs
[ ] Error codes preserve legacy numbers where existing tooling expects them
[ ] Trailing `Slice` / `Cell` field is the LAST field of its message
[ ] `send(...)` calls include complete `SendOptions { value, bounce,
    body_layout, mode }`
[ ] `asm { ... }` blocks appear only inside `unsafe fn`

ABI:
[ ] Each `message M(op = 0x...)` has the correct TEP or custom opcode
[ ] Exit codes in 0..31 are reserved; do not assign user errors there
[ ] Getter names are stable (they produce method_ids via crc16)
[ ] No field reordering in persistent state unless doing a migration
```

---

## 10. WHEN TO ESCAPE TO `asm`

Use `asm { ... }` only when the high-level surface genuinely cannot express the operation. Common legitimate cases:

- **TVM opcodes the stdlib hasn't wrapped** (rare; most are wrapped)
- **Performance-critical inner loop** where wrapper overhead matters
- **Bit-level manipulation** that doesn't map to named ops
- **Experimental opcodes** not yet in stdlib

Do NOT escape to `asm` for:

- "I'm not sure what the stdlib function is called" — look it up in §5
- "I want manual gas control" — the stdlib functions are already bare intrinsics
- "This is a 0.4.6 pattern I know" — port to high-level instead
- Anything the common-patterns library (§4) already covers

Example of a legitimate `asm` escape:

```func
// Compute crc32 of a slice — TVM has CRC32 opcode but stdlib may not wrap it.
fn crc32(s: Slice) -> u32 unsafe asm "CRC32";
```

Example of what NOT to do:

```func
// BAD — just use the stdlib send.
fn send_ton(dst: Address, amount: Coins) unsafe {
    asm {
        """
        NEWC
        ...32 lines of hand-written message construction...
        SENDRAWMSG
        """
    }
}
```

---

## 11. HOW TO USE THIS PRIMER

### 11.1 As a system prompt (Claude, GPT, Gemini, etc.)

Paste the content of **§1 HARD RULES** directly into the system prompt. Paste **§2 Canonical Contract Skeleton** below it. These two sections together (about 150 lines) are the minimum set that prevents the most common errors.

Optionally include **§3 Cheat Sheet** if context budget allows; it catches another class of errors.

### 11.2 As Cursor / Copilot instructions

Put the full content of **§1**, **§2**, **§3**, and **§8 Anti-Patterns** into `.cursor/rules/func-v0.5.0.md` or equivalent. The anti-patterns in particular prevent the IDE's auto-completion from falling back to Rust/TypeScript habits.

### 11.3 As Claude Project instructions

Paste **§§0–5** into Project Instructions. Upload the full `doc/func_v0.5.0.tex` and `doc/func_v0.5.0-corpus.md` as project knowledge. The primer is the fast-path; the full spec is the fallback.

### 11.4 As RAG chunks

Split this document by section headings (`##`). Each section is a self-contained chunk. Good chunk boundaries are at:

- §1 HARD RULES (one chunk)
- §4 COMMON PATTERNS (one chunk per recipe, 15 chunks)
- §5 STDLIB (one chunk per module, ~10 chunks)
- §8 ANTI-PATTERNS (one chunk per item, 20 chunks)

This yields ~50 small focused chunks, ideal for similarity retrieval.

### 11.5 As fine-tuning data

Pair each pattern in §4 with 3 variations. Pair each anti-pattern in §8 with a "wrong / right" correction. Combined with the full corpus (§12 below), this gives ~200 high-quality instruction-response pairs.

---

## 12. A FULL WORKING EXAMPLE TO PATTERN-MATCH ON

A complete Jetton wallet (synthetic, from TEP-74) in the v4 surface. Use this as the canonical "good code" reference when generating similar contracts.

```func
#![edition = "0.5.0"]

contract JettonWallet {
    state {
        balance:     Coins,
        owner:       Address,
        master:      Address,
        wallet_code: Cell<JettonWalletCode>,
    }

    error InsufficientBalance = 706,
          NotOwner            = 705,
          NotMaster           = 707,
          NotJettonWallet     = 708;

    message Transfer(op = 0x0f8a7ea5) {
        query_id:             u64,
        amount:               Coins,
        destination:          Address,
        response_destination: Address?,
        custom_payload:       Cell<RawCell>?,
        forward_tos_amount:   Coins,
        forward_payload:      EitherRefOrInline<RawCell>,
    }

    message InternalTransfer(op = 0x178d4519) {
        query_id:             u64,
        amount:               Coins,
        from:                 Address,
        response_destination: Address?,
        forward_tos_amount:   Coins,
        forward_payload:      EitherRefOrInline<RawCell>,
    }

    message Burn(op = 0x595f07bc) {
        query_id:             u64,
        amount:               Coins,
        response_destination: Address?,
    }

    enum JettonMsg {
        Transfer(Transfer),
        InternalTransfer(InternalTransfer),
        Burn(Burn),
    }

    internal fn recv(msg: JettonMsg) {
        match msg {
            JettonMsg::Transfer(t)         =>
                on_transfer(mut state, ctx.sender, ctx.value, t),
            JettonMsg::InternalTransfer(i) =>
                on_internal_transfer(mut state, ctx.sender, i),
            JettonMsg::Burn(b)             =>
                on_burn(mut state, ctx.sender, b),
        }
    }

    bounce fn on_bounce(ctx: BounceContext<InternalTransfer>) {
        // Sibling wallet rejected the transfer — refund.
        state.balance += ctx.body.amount;
    }

    get fn get_wallet_data() -> (Coins, Address, Address, Cell<JettonWalletCode>) {
        (state.balance, state.owner, state.master, state.wallet_code)
    }
}

fn on_transfer(
    mut state:  JettonWalletState,
    sender:     Address,
    msg_value:  Coins,
    req:        Transfer,
) {
    require!(sender == state.owner,        NotOwner);
    require!(state.balance >= req.amount,  InsufficientBalance);
    state.balance -= req.amount;

    let dest_wallet = derive_jetton_wallet_address(
        state.master, state.wallet_code, req.destination
    );
    send(
        dest_wallet,
        InternalTransfer {
            query_id:             req.query_id,
            amount:               req.amount,
            from:                 state.owner,
            response_destination: req.response_destination,
            forward_tos_amount:   req.forward_tos_amount,
            forward_payload:      req.forward_payload,
        },
        SendOptions {
            value:       msg_value - req.forward_tos_amount,
            bounce:      BounceMode::Body256,
            body_layout: BodyLayout::Auto,
            mode:        SendMode::PayFeesSeparately,
        },
    );
}

fn on_internal_transfer(
    mut state: JettonWalletState, sender: Address, req: InternalTransfer,
) {
    require!(sender == state.master ||
             sender == derive_jetton_wallet_address(
                 state.master, state.wallet_code, req.from
             ),
             NotJettonWallet);
    state.balance += req.amount;
    // further handling: notification, excesses refund, etc.
}

fn on_burn(
    mut state: JettonWalletState, sender: Address, req: Burn,
) {
    require!(sender == state.owner,       NotOwner);
    require!(state.balance >= req.amount, InsufficientBalance);
    state.balance -= req.amount;
    // notify master...
}
```

Pattern points to absorb:

- `contract` block groups everything
- `state { }` names persistent layout
- `error Name = N, ...` names exit codes
- Each `message M(op = 0x...)` is a wire schema
- `enum JettonMsg { Variant(M), ... }` groups multiple ops for dispatch
- `internal fn recv(msg: EnumType)` receives the whole group; `match` dispatches
- Helpers outside the contract block take `mut state` as parameter
- Inside entry body, `state.x` and `ctx.sender` are in scope implicitly
- `require!(cond, Name)` is the only failure mechanism used
- `send(dst, body, SendOptions { ... })` for outbound messages
- `bounce fn on_bounce(ctx: BounceContext<T>)` for refund-on-failure
- `get fn ...` for public read queries

---

## 13. QUICK REFERENCE: DO / DON'T SUMMARY CARD

```
            DO                                  DON'T
─────────────────────────────────────────────────────────────────
require!(cond, ErrorName)             |   throw_unless(33, cond)
state.x += 1                          |   let mut s = load_state();
                                      |     save_state(s)
error Name = 33                       |   magic 33 in throw_unless
message M(op=X) { ... }               |   const OP = X; manual parse
internal fn recv(msg: T)              |   entry internal fn recv(...)
ctx.sender (internal only)            |   ctx.sender in external fn
send(dst, body, opts)                 |   manual NEWC ... SENDRAWMSG
Signed<T>.check(pubkey)               |   hand-rolled sig verify
asm { """ ... """ } (unsafe fn)       |   asm all over the place
match msg { ... }                     |   if (op == A) else if ...
if let Some(x) = opt                  |   if (opt != null_sentinel)
mut state: State                      |   &mut self
Option<T> / T?                        |   nullable int with sentinel
```

---

**END OF PRIMER.**

For the full language spec see `doc/func_v0.5.0.tex` (v4, 74 pages).
For the authoritative lowering rules see `doc/func_v0.5.0-lowering.tex` (26 pages).
For worked contracts see `doc/func_v0.5.0-corpus.md` (v2, 5 contracts).
For the stdlib design context see `doc/tos-func-stdlib-design.md`.
