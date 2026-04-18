# FunC 0.5.0 Canonical Corpus

Version: v1 (Draft)
Status: Companion reference to `doc/func_v0.5.0.tex` and `doc/func_v0.5.0-lowering.tex`.
Non-normative for language semantics; normative for conformance testing.

## 1. Purpose

This document defines a fixed set of reference smart contracts — the **canonical corpus** — that a FunC 0.5.0 compiler must compile correctly to claim specification conformance.

The corpus plays three roles:

1. **Living test of the specification.** The 10 Canonical Decisions in `doc/func_v0.5.0.tex` are tight paper rules. Rewriting real-world contracts under those rules is the only way to expose hidden conflicts between rules, insufficient ergonomics, and lowering pitfalls.
2. **Cross-compiler conformance baseline.** Future 0.5.0 compilers (reference implementation, Tolk-compatible backend, third-party contributors) must produce byte-identical TVM output for the corpus. Any divergence is either a spec bug or an implementation bug.
3. **Authoring template.** Each corpus entry ships as a three-part artefact: the 0.4.6 original, the 0.5.0 canonical rewrite, and a prose migration note. That is simultaneously a tutorial for contract authors migrating existing code and a library of reusable patterns.

Corpus membership is not arbitrary. Each entry was chosen because it exercises a specific combination of 0.5.0 features, and together the corpus covers every Canonical Decision at least once.

## 2. Corpus Membership

| ID | Contract | Source (0.4.6) | Exercises |
|----|----------|----------------|-----------|
| C1 | Simple wallet (wallet3) | `crypto/smartcont/wallet3-code.fc` | baseline migration; `entry external` lazy decode; `get fn` with `method_id`; `effect(read, write, send)`; typed persistent state |
| C2 | Plugin wallet (wallet-v4) | `crypto/smartcont/wallet-v4-code.fc` | `entry internal` + `entry bounce` dispatch; typed enum with explicit opcodes; `match` dispatch; `Dict<K, V>`; legacy exit codes 33–36 mapped to typed `Err` |
| C3 | Highload wallet (highload-wallet-v2) | `crypto/smartcont/highload-wallet-v2-code.fc` | dict iteration via 0.5.0 iterator trait; `do...until` → `while let`; query-id deduplication pattern; getter returning a three-state `Option`-like value |
| C4 | Jetton wallet (synthetic, TEP-74) | (TEP-74 canonical) | `MasterWorker` pattern; `message M(op = X)`; typed `send`; `InternalContext<JettonMsg>`; `BounceMode::Body256`; round-trip with master |
| C5 | Multisig (sketch) | `crypto/smartcont/multisig-code.fc` | proposal queue; signer dict; threshold rotation; outlined only, full rewrite deferred |
| — | Elector (deferred) | `crypto/smartcont/elector-code.fc` | too large for v1; scheduled for v2 of the corpus after 0.5.0 reference compiler lands |

Not every 0.4.6 contract under `crypto/smartcont/` is in the corpus. The selection rule is: each entry must exercise at least one feature not covered by an earlier entry; redundant examples (e.g. `simple-wallet-code.fc`, `wallet-code.fc`) are dropped in favour of wallet3 as the single canonical minimal wallet.

## 3. Conformance Rules

A FunC 0.5.0 compiler **is corpus-conformant** iff, for every entry, it produces:

- **the same TVM code cell hash** as the reference compiler for the provided 0.5.0 source;
- **the same exported getter method-id set** (Canonical Decision 6);
- **the same ABI manifest** (opcode bindings, event topics, error-code map) as declared in the per-entry `expected-abi.json` sidecar.

Byte-identical code-cell output is the gold standard. Minor differences in fift-level pretty printing are tolerated only insofar as they do not change the computed cell hash.

The corpus harness lives at `tools/tos-stdlib/corpus/`. For each entry `Cn` it provides:

```
crypto/smartcont/v050/Cn/
├── v046-original.fc          // the 0.4.6 source (identical to the file in crypto/smartcont/)
├── v050-canonical.fc          // the 0.5.0 rewrite
├── expected-bytecode.boc      // canonical TVM output
├── expected-abi.json          // method_ids, opcodes, error codes
├── fixtures/                  // input/output test vectors
└── README.md                  // migration notes + test instructions
```

This markdown document is the specification of what `v050-canonical.fc` and the sidecars should contain. The files under `crypto/smartcont/v050/` are generated from this corpus document as the 0.5.0 reference compiler matures.

## 4. C1 — Simple Wallet (wallet3)

### 4.1 0.4.6 reference

```func
;; Simple wallet smart contract with global_id anti-replay protection

int get_global_id() asm "GLOBALID";

() recv_internal(slice in_msg) impure {
  ;; do nothing for internal messages
}

() recv_external(slice in_msg) impure {
  var signature = in_msg~load_bits(512);
  var cs = in_msg;
  var msg_global_id = cs~load_int(32);
  throw_unless(36, msg_global_id == get_global_id());
  var (subwallet_id, valid_until, msg_seqno) =
      (cs~load_uint(32), cs~load_uint(32), cs~load_uint(32));
  throw_if(35, valid_until <= now());
  var ds = get_data().begin_parse();
  var (stored_seqno, stored_subwallet, public_key) =
      (ds~load_uint(32), ds~load_uint(32), ds~load_uint(256));
  ds.end_parse();
  throw_unless(33, msg_seqno == stored_seqno);
  throw_unless(34, subwallet_id == stored_subwallet);
  throw_unless(35, check_signature(slice_hash(in_msg), signature, public_key));
  accept_message();
  cs~touch();
  while (cs.slice_refs()) {
    var mode = cs~load_uint(8);
    send_raw_message(cs~load_ref(), mode);
  }
  set_data(begin_cell()
    .store_uint(stored_seqno + 1, 32)
    .store_uint(stored_subwallet, 32)
    .store_uint(public_key, 256)
    .end_cell());
}

int seqno() method_id { return get_data().begin_parse().preload_uint(32); }

int get_public_key() method_id {
  var cs = get_data().begin_parse();
  cs~load_uint(64);
  return cs.preload_uint(256);
}
```

### 4.2 0.5.0 canonical rewrite

```func
#![edition = "0.5.0"]

use std::cell::{Cell, RawCell, Builder};
use std::slice::Slice;
use std::address::Address;
use std::result::Result;
use std::message::send_raw;
use std::crypto::check_signature;
use std::chain::{now, global_id, accept_message};

pub struct WalletState {
    seqno: u32,
    subwallet_id: u32,
    public_key: u256,
}

pub enum WalletError : u16 {
    UnknownQueryId = 32,
    WrongSeqno = 33,
    WrongSubwalletId = 34,
    BadSignature = 35,
    Expired = 35,          // legacy reuses 35; see migration note
    WrongGlobalId = 36,
}

pub fn load_state() -> Result<WalletState, ParseError> effect(read) {
    let mut ds = get_data()?.begin_parse();
    let state = WalletState {
        seqno:        ds.load_uint(32)?  as u32,
        subwallet_id: ds.load_uint(32)?  as u32,
        public_key:   ds.load_uint(256)? as u256,
    };
    ds.end_parse()?;
    Ok(state)
}

pub fn save_state(state: WalletState) -> Result<(), CellError> effect(write) {
    let cell = Builder::new()
        .store_uint(state.seqno        as u256, 32)?
        .store_uint(state.subwallet_id as u256, 32)?
        .store_uint(state.public_key,           256)?
        .end_cell()?;
    set_data(cell)
}

// Non-bounced fresh internal messages are silently accepted. Bounced messages
// are dropped because no `entry bounce` is defined. Unknown ops are also
// dropped per Canonical Decision 6.
entry internal fn recv_internal(
    _ctx: InternalContext<RawSlice>,
) -> Result<(), WalletError> pure {
    Ok(())
}

entry external fn recv_external(
    ctx: ExternalContext,
) -> Result<(), WalletError> effect(read, write, send) {
    let mut body = ctx.body_slice;
    let signature = body.load_bits(512)?;
    let msg_global_id = body.load_int(32)?;
    if msg_global_id != global_id() {
        return Err(WalletError::WrongGlobalId);
    }
    let subwallet_id = body.load_uint(32)? as u32;
    let valid_until  = body.load_uint(32)? as u32;
    let msg_seqno    = body.load_uint(32)? as u32;
    if valid_until <= now() {
        return Err(WalletError::Expired);
    }

    let state = load_state()?;
    if msg_seqno != state.seqno {
        return Err(WalletError::WrongSeqno);
    }
    if subwallet_id != state.subwallet_id {
        return Err(WalletError::WrongSubwalletId);
    }
    if !check_signature(ctx.body_slice_hash(), signature, state.public_key) {
        return Err(WalletError::BadSignature);
    }

    accept_message();

    // forward every (mode:u8, ref:^Cell) pair remaining in the body
    while body.remaining_refs() > 0 {
        let mode = body.load_uint(8)? as u8;
        let raw  = body.load_ref()?;
        send_raw(raw, mode)?;
    }

    save_state(WalletState { seqno: state.seqno + 1, ..state })?;
    Ok(())
}

get fn seqno() -> Result<u32, ParseError> effect(read) {
    Ok(load_state()?.seqno)
}

get fn get_public_key() -> Result<u256, ParseError> effect(read) {
    Ok(load_state()?.public_key)
}
```

### 4.3 Migration notes (C1)

- **Entry split.** 0.4.6 has one `recv_internal` and one `recv_external`. 0.5.0 splits into `entry internal`, `entry bounce`, and `entry external`. A wallet that wants the original behaviour (ignore all incoming internal bodies, drop bounces) defines only `entry internal` as a no-op and omits `entry bounce` entirely. Omitting is not the same as defining: an omitted entry is silently dropped by the generated wrapper.
- **`entry external` is lazy by default.** Per Canonical Decision 9, `ctx` has only `body_slice`, not a typed `body`. Authors perform manual parse; the signature is verified before `accept_message`, preserving the 10 000-gas external quota.
- **Error codes preserved via explicit discriminants.** The enum `WalletError : u16` declares `WrongSeqno = 33`, `WrongSubwalletId = 34`, etc., identical to the `throw_unless(33, ...)` literals in 0.4.6. Canonical Decision 5 then guarantees that `return Err(WalletError::WrongSeqno)` throws exit code 33 at the wrapper boundary — the wallet remains ABI-compatible with existing indexers and signing tooling.
- **`~method` → `.method` + `let mut`.** `cs~load_uint(32)` becomes `body.load_uint(32)?` on a `let mut body`. The `mut self` rule in the spec plus the error-path rollback (Canonical Decision 8 interaction in `doc/func_v0.5.0-lowering.tex` §4.3) means that on `Err`, `body` is restored, which matches the 0.4.6 `throw_unless` behaviour that aborts before any subsequent `body` access.
- **Implicit state increment.** `state.seqno + 1` in a `WalletState { ..., ..state }` struct-update is the 0.5.0 way to spell "bump one field, preserve the rest". This replaces re-specifying each field as in the original `save_data(seqno+1, stored_subwallet, public_key)`.
- **`accept_message` placement unchanged.** The call happens in the same gas-phase position as 0.4.6 — after signature verification, before any expensive body iteration. This is preserved precisely to satisfy the external-message gas model.
- **Getter method-id preserved.** `get fn seqno()` and `get fn get_public_key()` both compile to `crc16(name) | 0x10000` per Canonical Decision 6, matching the 0.4.6 `method_id` output byte-for-byte.

Expected byte-level output: the only differences from 0.4.6 output are the six hash bytes of the source cell (because the source text itself changed). Every functional opcode, stack shuffle, getter selector, and exit code must remain bit-identical.

## 5. C2 — Plugin Wallet (wallet-v4)

### 5.1 0.4.6 reference

See `crypto/smartcont/wallet-v4-code.fc` (121 lines). Key shape:

- Persistent state: `(seqno: u32, subwallet_id: u32, public_key: u256, plugins: Dict)`.
- Plugin key: packed `(workchain: i8, addr_hash: u256)` as a 264-bit slice.
- `recv_internal` responds to op `0x706c7567` ("plug") by paying out stored plugin amount.
- `recv_external` dispatches on a `u8` op: `0` = simple send, `1` = install plugin, `2` = remove plugin.

### 5.2 0.5.0 canonical rewrite

```func
#![edition = "0.5.0"]

use std::dict::Dict;
use std::address::{Address, parse_std_addr};
use std::result::Result;
use std::message::send_raw;
use std::chain::{accept_message, global_id, now, raw_reserve};
use std::crypto::check_signature;

pub type PluginKey = (i8, u256);    // workchain + address hash

pub struct WalletState {
    seqno: u32,
    subwallet_id: u32,
    public_key: u256,
    plugins: Dict<PluginKey, ()>,
}

pub enum WalletError : u16 {
    DuplicateQueryId = 32,
    WrongSeqno       = 33,
    WrongSubwalletId = 34,
    BadSignature     = 35,
    Expired          = 35,
    WrongGlobalId    = 36,
    UnknownOp        = 40,
}

// -------- persistent-state codec --------

pub fn load_state() -> Result<WalletState, ParseError> effect(read) {
    let mut ds = get_data()?.begin_parse();
    let state = WalletState {
        seqno:        ds.load_uint(32)?  as u32,
        subwallet_id: ds.load_uint(32)?  as u32,
        public_key:   ds.load_uint(256)?,
        plugins:      ds.load_dict()?,
    };
    Ok(state)
}

pub fn save_state(state: WalletState) -> Result<(), CellError> effect(write) {
    Builder::new()
        .store_uint(state.seqno        as u256, 32)?
        .store_uint(state.subwallet_id as u256, 32)?
        .store_uint(state.public_key,           256)?
        .store_dict(state.plugins)?
        .end_cell()?
        .set_as_data()
}

// -------- plugin request (internal) --------

pub message PluginPayout(op = 0x706c7567) {
    tos_amount: Coins,
}

entry internal fn on_plugin_payout(
    ctx: InternalContext<PluginPayout>,
) -> Result<(), WalletError> effect(read, send) {
    let state = load_state()?;
    let (wc, hash) = parse_std_addr(ctx.sender)?;
    if !state.plugins.contains(&(wc, hash)) {
        return Ok(());  // unknown plugin -> silent ignore
    }
    raw_reserve(ctx.body.tos_amount, 2)?;
    send_raw(
        Builder::new()
            .store_uint(0x18, 6)?
            .store_address(ctx.sender)?
            .store_coins(0.into())?
            .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)?
            .end_cell()?,
        128,
    )?;
    Ok(())
}

// -------- external request --------

pub enum ExternalOp : u8 {
    SimpleSend    = 0,
    InstallPlugin = 1,
    RemovePlugin  = 2,
}

entry external fn recv_external(
    ctx: ExternalContext,
) -> Result<(), WalletError> effect(read, write, send) {
    let mut body = ctx.body_slice;
    let signature = body.load_bits(512)?;

    let msg_global_id = body.load_int(32)?;
    if msg_global_id != global_id() {
        return Err(WalletError::WrongGlobalId);
    }
    let subwallet_id = body.load_uint(32)? as u32;
    let valid_until  = body.load_uint(32)? as u32;
    let msg_seqno    = body.load_uint(32)? as u32;
    let op_u8        = body.load_uint(8)?  as u8;

    if valid_until <= now() { return Err(WalletError::Expired); }

    let state = load_state()?;
    if msg_seqno != state.seqno        { return Err(WalletError::WrongSeqno); }
    if subwallet_id != state.subwallet_id { return Err(WalletError::WrongSubwalletId); }
    if !check_signature(ctx.body_slice_hash(), signature, state.public_key) {
        return Err(WalletError::BadSignature);
    }

    accept_message();

    let op = ExternalOp::try_from(op_u8).ok_or(WalletError::UnknownOp)?;
    let mut new_plugins = state.plugins;
    match op {
        ExternalOp::SimpleSend => {
            while body.remaining_refs() > 0 {
                let mode = body.load_uint(8)? as u8;
                let raw  = body.load_ref()?;
                send_raw(raw, mode)?;
            }
        }
        ExternalOp::InstallPlugin => {
            let wc   = body.load_int(8)? as i8;
            let hash = body.load_uint(256)?;
            new_plugins.insert((wc, hash), ());
        }
        ExternalOp::RemovePlugin => {
            let wc   = body.load_int(8)? as i8;
            let hash = body.load_uint(256)?;
            new_plugins.remove(&(wc, hash));
        }
    }

    save_state(WalletState {
        seqno: state.seqno + 1,
        plugins: new_plugins,
        ..state
    })
}

// -------- getters --------

get fn seqno() -> Result<u32, ParseError> effect(read) {
    Ok(load_state()?.seqno)
}
get fn get_subwallet_id() -> Result<u32, ParseError> effect(read) {
    Ok(load_state()?.subwallet_id)
}
get fn get_public_key() -> Result<u256, ParseError> effect(read) {
    Ok(load_state()?.public_key)
}
get fn is_plugin_installed(wc: i8, addr_hash: u256)
  -> Result<bool, ParseError> effect(read) {
    Ok(load_state()?.plugins.contains(&(wc, addr_hash)))
}
```

### 5.3 Migration notes (C2)

- **Typed internal dispatch.** 0.4.6 handles the plugin payout request inline inside `recv_internal`, checking `op == 0x706c7567` and parsing the body manually. 0.5.0 declares `pub message PluginPayout(op = 0x706c7567) { tos_amount: Coins }` and uses `entry internal fn on_plugin_payout(ctx: InternalContext<PluginPayout>)`. Under Canonical Decision 6, an inbound internal message whose first 32 bits do not match the declared opcode is silently dropped by the wrapper without invoking the user body — identical to the 0.4.6 "do nothing if op mismatches" branch, but without the manual check.
- **No bounce handler needed.** Wallet-v4 does not process bounced messages (it checks `flags & 1` and returns early). 0.5.0 simply omits `entry bounce`; the generated wrapper drops them.
- **Multiple `entry` per contract.** A contract may define at most one `entry internal` for a given message type. To handle multiple internal opcodes, wrap them in a sum enum (`enum WalletMsg { PluginPayout(PluginPayout), SubscriptionPayout(...) }`) or use multiple distinct `message` declarations with the same underlying `InternalContext<RawSlice>` fallback if needed. This contract handles only one internal message shape so a single `entry internal` suffices.
- **Op enum with explicit discriminants.** `ExternalOp : u8 { SimpleSend = 0, InstallPlugin = 1, RemovePlugin = 2 }` pins the wire format (8-bit tag big-endian, values 0/1/2). The `try_from(u8) -> Option<Self>` is a stdlib-provided helper on any `: uN` enum.
- **Dict operations.** 0.4.6 spells dict operations as `plugins~dict_set_builder(264, key, ...)` and `dict_delete?(plugins, 264, key)`. 0.5.0 exposes a typed `Dict<K, V>` with `.insert(k, v)`, `.remove(&k)`, `.contains(&k)`, `.get(&k)`. The 264-bit width is implicit from `PluginKey = (i8, u256)`.
- **Effect set split.** `on_plugin_payout` is `effect(read, send)`; it doesn't write persistent state. `recv_external` is `effect(read, write, send)`. The 0.4.6 `impure` qualifier on both gives no distinction.
- **Legacy exit-code parity.** Every `throw_unless(N, ...)` in 0.4.6 maps to a `WalletError` variant with the same `= N` discriminant. Exit-code observability is preserved.
- **Struct update for state.** `WalletState { seqno: state.seqno + 1, plugins: new_plugins, ..state }` expresses "bump seqno, swap plugins, keep the rest". The canonical lowering (Canonical Decision 1) is a tuple copy with two fields rewritten.

## 6. C3 — Highload Wallet v2

### 6.1 0.4.6 reference

See `crypto/smartcont/highload-wallet-v2-code.fc`. Key shape:

- Persistent state: `(subwallet_id: u32, last_cleaned: u64, public_key: u256, old_queries: Dict<u64, ()>)`.
- Anti-replay via `query_id` dedup dict, not seqno.
- External body carries a dict of (index → (mode, ^Cell)) pairs; contract iterates and forwards.
- After dispatch: insert new query_id into `old_queries`, then trim expired queries via `udict_delete_get_min`.

### 6.2 0.5.0 canonical rewrite

```func
#![edition = "0.5.0"]

use std::dict::Dict;
use std::message::send_raw;
use std::chain::{accept_message, global_id, now};
use std::crypto::check_signature;

pub type QueryId = u64;

pub struct WalletState {
    subwallet_id: u32,
    last_cleaned: u64,
    public_key:   u256,
    old_queries:  Dict<QueryId, ()>,
}

pub enum WalletError : u16 {
    DuplicateQueryId = 32,
    WrongSubwalletId = 34,
    BadSignature     = 35,
    Expired          = 35,
    WrongGlobalId    = 36,
}

pub fn load_state() -> Result<WalletState, ParseError> effect(read) { ... }
pub fn save_state(s: WalletState) -> Result<(), CellError>  effect(write) { ... }

// No internal logic; non-bounced internals are silently accepted and bounces dropped.
entry internal fn recv_internal(
    _ctx: InternalContext<RawSlice>,
) -> Result<(), WalletError> pure { Ok(()) }

entry external fn recv_external(
    ctx: ExternalContext,
) -> Result<(), WalletError> effect(read, write, send) {
    let mut body = ctx.body_slice;
    let signature = body.load_bits(512)?;
    let msg_global_id = body.load_int(32)?;
    if msg_global_id != global_id() {
        return Err(WalletError::WrongGlobalId);
    }
    let subwallet_id = body.load_uint(32)? as u32;
    let query_id     = body.load_uint(64)? as QueryId;

    // query_id encodes "expire_at_unix_time << 32 | nonce"
    let bound = (now() as u64) << 32;
    if query_id < bound {
        return Err(WalletError::Expired);
    }

    let mut state = load_state()?;
    if state.old_queries.contains(&query_id) {
        return Err(WalletError::DuplicateQueryId);
    }
    if subwallet_id != state.subwallet_id {
        return Err(WalletError::WrongSubwalletId);
    }
    if !check_signature(ctx.body_slice_hash(), signature, state.public_key) {
        return Err(WalletError::BadSignature);
    }

    let actions: Dict<i16, (u8, RawCell)> = body.load_dict()?;
    body.end_parse()?;
    accept_message();

    // iterate actions in index order
    for (_, (mode, raw)) in actions.iter_sorted() {
        send_raw(raw, mode)?;
    }

    // insert the new query_id, then trim queries older than (now - 64s) from the bottom
    state.old_queries.insert(query_id, ());
    let trim_bound = bound - (64u64 << 32);
    while let Some((min_id, _)) = state.old_queries.pop_min() {
        if min_id >= trim_bound {
            // restore and stop
            state.old_queries.insert(min_id, ());
            break;
        }
        state.last_cleaned = min_id;
    }

    save_state(state)
}

pub enum QueryStatus { Processed, Unprocessed, Forgotten }

get fn processed(query_id: QueryId)
  -> Result<QueryStatus, ParseError> effect(read) {
    let state = load_state()?;
    if state.old_queries.contains(&query_id) {
        return Ok(QueryStatus::Processed);
    }
    Ok(if query_id <= state.last_cleaned {
        QueryStatus::Forgotten
    } else {
        QueryStatus::Unprocessed
    })
}

get fn get_public_key() -> Result<u256, ParseError> effect(read) {
    Ok(load_state()?.public_key)
}
```

### 6.3 Migration notes (C3)

- **`do...until` → `while let`.** Highload-v2's 0.4.6 dict cleanup uses `do ... until (~ f)` against `udict_delete_get_min`. 0.5.0 replaces this with `while let Some((min_id, _)) = state.old_queries.pop_min()` plus an explicit `break`. The spec's iterator protocol (Canonical Decision 7 does not add new forms; `while let` is the natural idiom.) A key subtlety: `pop_min` mutates the dict and returns `Option`; the canonical `mut self + Result` rule (`doc/func_v0.5.0.tex` §9.5) does not apply here because `pop_min` returns `Option`, not `Result` — the cursor is always advanced on `Some`, never on `None`.
- **Three-state getter.** 0.4.6 returns an integer with three meanings (`true`, `false`, -1). 0.5.0 returns a typed `QueryStatus` enum. At the getter wire boundary, the enum is serialised with a `⌈log₂ 3⌉ = 2`-bit tag per Canonical Decision 2. Callers written in 0.4.6 client code must update. For back-compat, contracts can expose a sibling getter `get fn processed_legacy(q: u64) -> i2` that maps `QueryStatus → i2`.
- **Dict iteration.** 0.4.6 uses `idict_get_next?(16, i)` in a `do...until` loop. 0.5.0 uses `for (_, (mode, raw)) in actions.iter_sorted()`. The iterator trait for `Dict<K, V>` is stdlib-provided; `iter_sorted()` returns pairs in ascending key order. Per Canonical Decision 7, this desugars to `while let Some(...) = __it.next()`.
- **State-in-transit rule preserved.** The body is fully parsed (and `end_parse` called) before `accept_message`, matching 0.4.6. If the dict decode fails, no gas is spent beyond the decode itself, and the wallet remains under the 10 000-gas quota.
- **`mut state` update.** In 0.4.6 the `old_queries` dict is mutated in place via `old_queries~udict_set_builder(...)`. In 0.5.0 we use `let mut state = load_state()?;` followed by `state.old_queries.insert(query_id, ())`. The compiler scalarises the struct locally (lowering §4.4), so there is no tuple-rebuild overhead.
- **No migration of the query_id encoding.** `query_id = valid_until << 32 | nonce` is a protocol convention, not a language one. The 0.5.0 rewrite keeps it; a corpus entry aimed at replacing the encoding would be a protocol revision, not a language migration.

## 7. C4 — Jetton Wallet (Synthetic, from TEP-74)

This entry is not present in `crypto/smartcont/`. It is synthesised from TEP-74 (TOS-TEP-74 as adapted in `doc/tos-tep-token-standards.md`) because no corpus is complete without a Jetton wallet: it is the dominant DeFi primitive on TOS and it exercises the `MasterWorker` pattern and typed `send`.

### 7.1 0.5.0 canonical source

```func
#![edition = "0.5.0"]

use std::address::Address;
use std::message::{send, SendOptions, SendMode, BounceMode, BodyLayout};

pub struct JettonWalletState {
    balance: Coins,
    owner: Address,
    jetton_master: Address,
    jetton_wallet_code: Cell<JettonWalletCode>,
}

pub enum JettonError : u16 {
    InsufficientBalance       = 706,  // arbitrary; part of corpus ABI
    NotOwner                  = 705,
    UnknownMaster             = 707,
    NotAJettonWallet          = 708,
    InsufficientForwardFee    = 709,
    BadJettonPayload          = 710,
}

pub message JettonTransfer(op = 0x0f8a7ea5) {
    query_id:             u64,
    amount:               Coins,
    destination:          Address,
    response_destination: Option<Address>,
    custom_payload:       Option<Cell<RawCell>>,
    forward_tos_amount:   Coins,
    forward_payload:      EitherRefOrInline<RawCell>,
}

pub message JettonInternalTransfer(op = 0x178d4519) {
    query_id:             u64,
    amount:               Coins,
    from:                 Address,
    response_destination: Option<Address>,
    forward_tos_amount:   Coins,
    forward_payload:      EitherRefOrInline<RawCell>,
}

pub message JettonBurn(op = 0x595f07bc) {
    query_id:             u64,
    amount:               Coins,
    response_destination: Option<Address>,
    custom_payload:       Option<Cell<RawCell>>,
}

pub enum JettonMsg {
    Transfer(JettonTransfer),
    InternalTransfer(JettonInternalTransfer),
    Burn(JettonBurn),
}

entry internal fn recv_internal(
    ctx: InternalContext<JettonMsg>,
) -> Result<(), JettonError> effect(read, write, send) {
    let mut state = load_state()?;
    match ctx.body {
        JettonMsg::Transfer(req) =>
            on_transfer(mut state, ctx.sender, ctx.value, req)?,
        JettonMsg::InternalTransfer(req) =>
            on_internal_transfer(mut state, ctx.sender, ctx.value, req)?,
        JettonMsg::Burn(req) =>
            on_burn(mut state, ctx.sender, ctx.value, req)?,
    }
    save_state(state)
}

// Helpers take `mut state` by value-thread; no `&mut self` syntax exists.
// See main spec §Mutable Arguments and Lightweight Safety Checks.
fn on_transfer(
    mut state: WalletState,
    sender: Address,
    msg_value: Coins,
    req: JettonTransfer,
) -> Result<(), JettonError> effect(read, write, send) {
    if sender != state.owner { return Err(JettonError::NotOwner); }
    if state.balance < req.amount { return Err(JettonError::InsufficientBalance); }
    state.balance -= req.amount;

    let dest_wallet = derive_jetton_wallet_address(
        state.jetton_master,
        state.jetton_wallet_code,
        req.destination,
    )?;

    send(
        dest_wallet,
        JettonInternalTransfer {
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
    )?;
    Ok(())
}

fn on_internal_transfer(mut state: WalletState, ...) -> Result<(), JettonError> effect(read, write, send) { ... }
fn on_burn(mut state: WalletState, ...)             -> Result<(), JettonError> effect(read, write, send) { ... }

// Bounce handler: the sibling wallet refused the transfer. Refund balance.
entry bounce fn on_bounce(
    ctx: BounceContext<JettonInternalTransfer>,
) -> Result<(), JettonError> effect(read, write) {
    let mut state = load_state()?;
    state.balance += ctx.body.amount;   // refund
    save_state(state)
}

get fn get_wallet_data()
  -> Result<(Coins, Address, Address, Cell<JettonWalletCode>), ParseError>
  effect(read) {
    let s = load_state()?;
    Ok((s.balance, s.owner, s.jetton_master, s.jetton_wallet_code))
}
```

### 7.2 Migration notes (C4)

- **`MasterWorker` pattern as a protocol, not a language feature.** The derivation of sibling wallet address via `hash(jetton_wallet_code, (jetton_master, destination))` happens in stdlib helper `derive_jetton_wallet_address`, not in any compiler magic. Canonical Decision 8 (coherence) applies: the derivation helper lives in the stdlib crate that declares `JettonWallet`.
- **`BounceMode::Body256` pays off.** The bounce handler `on_bounce` re-decodes the original `JettonInternalTransfer` from the bounced body — only the first 256 bits plus `0xFFFFFFFF` header are preserved per TON convention, so `query_id (64) + amount (≤124) + from (≈267)` may not fit and the codec generator must emit a compile-time check. If it doesn't fit, the author must either reduce bounced-body width or use a ref-stored fallback.
- **`BodyLayout::Auto` exercises Canonical Decision 4.** `JettonInternalTransfer` has variable width via `forward_payload: EitherRefOrInline<RawCell>`. The compiler applies the deterministic fit predicate and produces inline or ref on each `send` call. Two compilers must produce identical bytes.
- **Enum dispatch with typed variants.** `match ctx.body` over `JettonMsg` compiles per Canonical Decision 2: a `⌈log₂ 3⌉ = 2`-bit tag followed by payload. But JettonMsg's variants each wrap a `message M(op = X)` with its own 32-bit opcode — so the wire tag is the opcode (32 bits), not a derived 2-bit tag. This is the message-as-discriminant rule in Canonical Decision 2.
- **`effect(read, write, send)` on `recv_internal`.** Jetton transfers inherently read state, write state, and send follow-on messages. The effect set is maximal.
- **Helpers use `mut state: WalletState`, not `&mut self`.** Per Canonical Decision 8 the language has no borrowed receivers. Helper functions that mutate shared state accept `mut state: WalletState` by value-thread, exactly like the existing `mut s: Slice` pattern on free functions. The lowering returns the updated `state` on `Ok` and rolls back on `Err`. This pattern is specified in the main spec §Mutable Arguments and Lightweight Safety Checks; it was previously flagged as open issue §11.1 but is now considered resolved.

## 8. C5 — Multisig (Sketch)

A full rewrite of `crypto/smartcont/multisig-code.fc` (318 lines) would dominate this document. The sketch below records the key patterns; the full rewrite is targeted for corpus v2.

Patterns exercised:

- `Dict<PublicKey, SignerMeta>` for signer set
- proposal queue as `Dict<QueryId, Proposal>` with expiry
- threshold rotation via `enum MultisigOp` with `UpdateSigners` variant
- quorum check that counts set bits in a `u256` signature mask
- `effect(write, send)` on the approval path; `effect(read)` on getters
- bounce handler that unrolls a partially-committed multi-send

Canonical Decision interactions specific to multisig:

- Canonical Decision 2: `enum MultisigOp` has 5–6 variants; tag width = `⌈log₂ 6⌉ = 3` bits plus padding if `: u8` is declared.
- Canonical Decision 6: getter `get fn get_pending_proposals()` returning `Vec<Proposal>` — see §11.2 below for the open issue on how to wire-serialise Vec at getter boundaries.

## 9. Deferred — Elector

`crypto/smartcont/elector-code.fc` is 1187 lines and contains the most sophisticated state machine in the reference corpus (stake bookkeeping, election cycle, participant slashing, recoverable balances). It exercises every Canonical Decision and then some. A 0.5.0 rewrite is tractable in principle but not in a single corpus-document pass. It is scheduled for corpus v2, after:

1. a reference 0.5.0 compiler exists and can machine-validate the earlier entries;
2. the stdlib `Dict<K, V>` API stabilises;
3. the `BounceContext<T>` partial-body semantics are specified (currently `BounceContext<RawSlice>` is the only fully-specified form).

## 10. Cross-Contract Migration Patterns

Patterns that recur across the corpus and are worth extracting as reusable idioms.

### 10.1 "Load state once, mutate locally, save at end"

All four rewrites follow the template:

```func
let mut state = load_state()?;
// ... mutate state ...
save_state(state)
```

The 0.4.6 pattern of `save_data(new_field1, new_field2, ..., old_field_k)` with field-reshuffling is replaced uniformly.

### 10.2 "Legacy exit code → enum discriminant = N"

The migration-preserving rule:

```func
pub enum ContractError : u16 {
    LegacyCode1 = 33,
    LegacyCode2 = 34,
    ...
}
```

Every `throw_unless(N, cond)` becomes `if !cond { return Err(ContractError::LegacyCodeN) }`. Byte-compatibility is preserved by Canonical Decision 5.

### 10.3 "Entry omission is entry silencing"

An omitted `entry internal`/`entry external`/`entry bounce` causes the generated wrapper to drop the matching inbound message silently. This replaces the 0.4.6 idiom:

```func
() recv_internal(slice in_msg) impure { }   // no-op
```

The 0.5.0 equivalent is to simply not write the entry (or to write `entry internal fn recv_internal(_ctx: InternalContext<RawSlice>) -> Result<(), E> pure { Ok(()) }` when you want to be explicit).

### 10.4 "Lazy-decode external; eager-decode internal"

Per Canonical Decision 9:

- `entry external`: always lazy. Parse inside the body after `accept_message` or signature check.
- `entry internal`: eager by default. Typed `ctx: InternalContext<T>` causes the wrapper to decode before calling the body and silently drop on mismatch.
- `entry external(eager)`: only when the author accepts the gas risk.

### 10.5 "Explicit effect set replaces single `impure`"

Migration map:

| 0.4.6 signature | 0.5.0 signature |
|-----------------|-----------------|
| `() fn() impure` (pure computation) | `fn() -> () pure` |
| `() fn() impure` (reads state) | `fn() -> _ effect(read)` |
| `() fn() impure` (writes state) | `fn() -> _ effect(write)` |
| `() fn() impure` (sends) | `fn() -> _ effect(send)` |
| `() fn() impure` (does everything) | `fn() -> _ effect(read, write, send)` |
| (any) with `asm` body | `fn() -> _ unsafe` |

## 11. Issues Surfaced by the Corpus (Resolved)

Writing this corpus surfaced five open issues that earlier drafts of the main specification did not resolve. **All five are now resolved in `doc/func_v0.5.0.tex` v3**; this section is retained as a historical record and for cross-referencing.

### 11.1 Helper functions that mutate state — resolved

C4's helpers originally used `&mut WalletState`, a borrow syntax the spec forbids. **Resolution (main-spec §Mutable Arguments and Lightweight Safety Checks):** helpers accept `mut state: State` by value-thread, identical to the existing `mut s: Slice` pattern. On `Ok` the caller-side binding is updated; on `Err` it is rolled back. No new syntax needed.

### 11.2 Vec / list in getter return positions — resolved

**Resolution (main-spec §`Vec<T>`):** `Vec<T>` is a first-class built-in with fixed dual representation — stack form is a TVM tuple (chained in 255-element segments for longer), wire form is `uint16 length + items + optional tail ref`. Getter returns expose the stack-tuple form directly.

### 11.3 `EitherRefOrInline<T>` wire form — resolved

**Resolution (main-spec §`EitherRefOrInline<T>`):** added as a first-class built-in. Wire form = `1-bit discriminant + (inline T | ^T)`; the compiler applies the same deterministic fit predicate as Canonical Decision 4, specialised to the field cursor. All conforming compilers produce identical bytes.

### 11.4 Bounce-body width check — resolved

**Resolution (main-spec §Entry Decoding Semantics, "Bounced body width rule"):** every `BounceContext<T>` with `T != RawSlice` must statically satisfy `max_encoded_bits(T) ≤ 256` AND encode with zero refs. Violation is a compile-time error `BounceBodyTooWide`. Authors narrow `T` or fall back to `BounceContext<RawSlice>` and parse manually.

### 11.5 `std::` module layout — resolved

**Resolution (main-spec Appendix A: Standard Library Module Map):** the canonical module tree (`std::prelude`, `std::cell`, `std::address`, `std::coins`, `std::bytes`, `std::vec`, `std::dict`, `std::crypto`, `std::chain`, `std::message`, `std::iter`, `std::result`, `std::option`, `std::intrinsics`) is frozen as part of the edition-0.5.0 ABI. `use std::prelude::*;` is applied implicitly. The full item-level reference lives in a sibling document `doc/func_v0.5.0-stdlib-ref.md` (to be written alongside the reference compiler).

---

With these resolved, corpus v1 no longer depends on any open spec question. Future residual risks that the corpus may surface during actual rewrite-and-compile rounds (when the reference compiler lands) will be tracked here as they appear.

## 12. How to Add to the Corpus

The corpus is versioned. Version bumps (v1 → v2) add new entries; existing entries are frozen at the version in which they were introduced.

To propose a new entry:

1. **Rationale.** Justify why the entry exercises a feature combination not yet covered. "Because it's a common contract" is not sufficient; the test is coverage of Canonical Decisions and unusual lowering shapes.
2. **0.4.6 reference.** Link to the existing contract under `crypto/smartcont/`, or synthesise from an accepted TEP/ecosystem standard.
3. **0.5.0 rewrite.** Must compile under the current 0.5.0 spec without relying on unspecified behaviour. Any unspecified behaviour encountered is itself a spec open issue.
4. **Migration notes.** Per-rewrite commentary at the same level of detail as §4.3 / §5.3 / §6.3 above.
5. **Expected bytecode fixture.** Once a reference compiler exists, the expected `*.boc` is checked in under `crypto/smartcont/v050/Cn/`.
6. **Pull request.** RFC-style review per the stdlib governance process (see `doc/tos-func-stdlib-design.md` §14).

---

**End of corpus document v1.** Next: corpus v2 after reference compiler lands, adding C6 (elector), C7 (full multisig), C8 (payment channel), and C9 (DNS).
