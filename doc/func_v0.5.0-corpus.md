# FunC 0.5.0 Canonical Corpus

Version: v2 (Draft)
Status: Companion reference to `doc/func_v0.5.0.tex` (spec v4) and `doc/func_v0.5.0-lowering.tex`.
Non-normative for language semantics; normative for conformance testing.

## 1. Purpose

This document defines a fixed set of reference smart contracts — the **canonical corpus** — that a FunC 0.5.0 compiler must compile correctly to claim specification conformance.

Three roles:

1. **Living test of the specification.** The Canonical Decisions in the main spec are tight paper rules. Rewriting real-world contracts under those rules is the only way to expose hidden conflicts, insufficient ergonomics, and lowering pitfalls.
2. **Cross-compiler conformance baseline.** Future 0.5.0 compilers must produce byte-identical TVM output for the corpus. Any divergence is either a spec bug or an implementation bug.
3. **Authoring template.** Each corpus entry ships as a three-part artefact: the 0.4.6 original, the 0.5.0 canonical rewrite, and a prose migration note. That is simultaneously a tutorial for contract authors migrating existing code and a library of reusable patterns.

Corpus v2 is the first corpus to target the **simplified v4 surface** — `contract { }` block + `require!` + typed-message entries + `asm` escape hatch + no `?` operator.

## 2. Corpus Membership

| ID | Contract | Source (0.4.6) | Exercises |
|----|----------|----------------|-----------|
| C1 | Simple wallet (wallet3) | `crypto/smartcont/wallet3-code.fc` | baseline migration; `contract { }` block; `Signed<Payload>`; trailing `Slice` field; named error codes; `get fn` |
| C2 | Plugin wallet (wallet-v4) | `crypto/smartcont/wallet-v4-code.fc` | two entries (`external fn` + `internal fn`); `enum` opcode dispatch; `Dict<K, V>`; conditional `send`; op-byte subcommand within external body |
| C3 | Highload wallet (highload-wallet-v2) | `crypto/smartcont/highload-wallet-v2-code.fc` | dict iteration (`for`); `while let` + dict `pop_min`; three-state getter (`enum`); query-id dedup pattern |
| C4 | Jetton wallet (synthetic, TEP-74) | (TEP-74 canonical) | master/worker pattern; `enum` of messages; `match` dispatch; `BounceContext<T>` with width check; `BodyLayout::Auto`; helper functions with `mut state` |
| C5 | Multisig (sketch) | `crypto/smartcont/multisig-code.fc` | proposal queue; signer dict; threshold rotation; outlined only |
| — | Elector (deferred) | `crypto/smartcont/elector-code.fc` | scheduled for corpus v3 after the reference compiler lands |

## 3. Conformance Rules

A FunC 0.5.0 compiler **is corpus-conformant** iff, for every entry, it produces:

- the same TVM code cell hash as the reference compiler for the provided 0.5.0 source;
- the same exported getter method-id set (main-spec Canonical Decision 6);
- the same ABI manifest (opcode bindings, error-code map, entry effect sets) as declared in the per-entry `expected-abi.json` sidecar.

The corpus artefacts live at `crypto/smartcont/v050/Cn/`:

```
v046-original.fc     v050-canonical.fc     expected-bytecode.boc
expected-abi.json    fixtures/             README.md
```

## 4. C1 — Simple Wallet (wallet3)

### 4.1 0.4.6 reference (45 lines)

```func
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

### 4.2 0.5.0 canonical rewrite (30 lines)

```func
#![edition = "0.5.0"]

contract Wallet {
    state { seqno: u32, subwallet_id: u32, pubkey: u256 }

    error WrongGlobal    = 36,
          Expired        = 35,
          WrongSeqno     = 33,
          WrongSubwallet = 34,
          BadSignature   = 35;

    message Payload {
        global_id:    i32,
        subwallet_id: u32,
        valid_until:  u32,
        seqno:        u32,
        actions:      Slice,        // trailing = remaining bits/refs
    }

    external fn recv(msg: Signed<Payload>) {
        let p = msg.body;
        require!(p.global_id    == global_id(),        WrongGlobal);
        require!(p.valid_until  >  now(),              Expired);
        require!(p.seqno        == state.seqno,        WrongSeqno);
        require!(p.subwallet_id == state.subwallet_id, WrongSubwallet);
        require!(msg.check(state.pubkey),              BadSignature);
        accept_message();

        let mut actions = p.actions;
        while actions.refs() > 0 {
            send_raw(actions.load_ref(), actions.load_uint(8) as u8);
        }
        state.seqno += 1;
    }

    get fn seqno()  -> u32  { state.seqno }
    get fn pubkey() -> u256 { state.pubkey }
}
```

### 4.3 Migration notes (C1)

- **Shorter than the 0.4.6 original (30 vs 45 lines).** The `contract { }` block eliminates `load_data` / `save_data` helpers, the manual `set_data(begin_cell()...)` construction, and the `in_msg_body` plumbing. `state`, `error`, `message`, and `external fn` appear as one coherent unit.
- **Signature handling delegated to `Signed<T>`.** The wrapper hashes the body (post-signature), and `msg.check(pubkey)` does the `check_signature` call. Author writes one line instead of three.
- **Trailing `Slice` captures the action list.** `actions: Slice` as the last field of `Payload` binds to the remaining bits and refs. Authors iterate it with the ordinary `while actions.refs() > 0` pattern.
- **Named error codes, ABI preserved.** `throw_unless(33, ...)` becomes `require!(cond, WrongSeqno)`. Because the error variant has explicit `= 33`, the thrown exit code is exactly 33; existing indexers observing exit code 33 keep working.
- **Getter method-ids unchanged.** `get fn seqno()` compiles to `crc16("seqno") | 0x10000`, identical to 0.4.6's `int seqno() method_id`.
- **`internal fn` omitted.** wallet3 does nothing on internal messages and has no bounce handling. In 0.5.0 you simply don't write those entries — the wrapper drops them silently, matching the 0.4.6 no-op `recv_internal`.
- **No `impure`, no `?`, no `Result`.** Every failure is an abort; every success is a plain return.

## 5. C2 — Plugin Wallet (wallet-v4)

### 5.1 0.4.6 reference (121 lines)

Full source at `crypto/smartcont/wallet-v4-code.fc`. Shape:

- Persistent state: `(seqno, subwallet_id, public_key, plugins: Dict<PluginKey, ()>)`.
- `recv_internal` responds to op `0x706c7567` (= "plug") by paying out the plugin's configured amount.
- `recv_external` dispatches on a `u8` sub-op: `0` = simple send, `1` = install plugin, `2` = remove plugin.

### 5.2 0.5.0 canonical rewrite (~60 lines)

```func
#![edition = "0.5.0"]

contract WalletV4 {
    state {
        seqno:        u32,
        subwallet_id: u32,
        pubkey:       u256,
        plugins:      Dict<(i8, u256), ()>,
    }

    error WrongGlobal    = 36,
          Expired        = 35,
          WrongSeqno     = 33,
          WrongSubwallet = 34,
          BadSignature   = 35,
          UnknownSubOp   = 40;

    // --- internal: plugin payout request ---

    message PluginPayout(op = 0x706c7567) {
        tos_amount: Coins,
    }

    internal fn on_plugin_payout(msg: PluginPayout) {
        let (wc, hash) = parse_std_addr(ctx.sender);
        if !state.plugins.contains(&(wc, hash)) { return; }     // unknown plugin
        raw_reserve(msg.tos_amount, 2);
        send_raw(
            Builder::new()
                .store_uint(0x18, 6)
                .store_address(ctx.sender)
                .store_coins(Coins::zero())
                .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
                .end_cell(),
            128,
        );
    }

    // --- external: signed command ---

    enum SubOp : u8 {
        SimpleSend    = 0,
        InstallPlugin = 1,
        RemovePlugin  = 2,
    }

    message ExternalPayload {
        global_id:    i32,
        subwallet_id: u32,
        valid_until:  u32,
        seqno:        u32,
        sub_op:       SubOp,
        tail:         Slice,
    }

    external fn recv(msg: Signed<ExternalPayload>) {
        let p = msg.body;
        require!(p.global_id    == global_id(),        WrongGlobal);
        require!(p.valid_until  >  now(),              Expired);
        require!(p.seqno        == state.seqno,        WrongSeqno);
        require!(p.subwallet_id == state.subwallet_id, WrongSubwallet);
        require!(msg.check(state.pubkey),              BadSignature);
        accept_message();

        let mut tail = p.tail;
        match p.sub_op {
            SubOp::SimpleSend => {
                while tail.refs() > 0 {
                    send_raw(tail.load_ref(), tail.load_uint(8) as u8);
                }
            }
            SubOp::InstallPlugin => {
                let wc   = tail.load_int(8) as i8;
                let hash = tail.load_uint(256);
                state.plugins.insert((wc, hash), ());
            }
            SubOp::RemovePlugin => {
                let wc   = tail.load_int(8) as i8;
                let hash = tail.load_uint(256);
                state.plugins.remove(&(wc, hash));
            }
        }
        state.seqno += 1;
    }

    // --- getters ---

    get fn seqno()            -> u32   { state.seqno }
    get fn get_subwallet_id() -> u32   { state.subwallet_id }
    get fn get_public_key()   -> u256  { state.pubkey }
    get fn is_plugin_installed(wc: i8, addr_hash: u256) -> bool {
        state.plugins.contains(&(wc, addr_hash))
    }
}
```

### 5.3 Migration notes (C2)

- **Two entries in one contract.** `internal fn on_plugin_payout(msg: PluginPayout)` receives only messages whose first 32 bits equal `0x706c7567`; all other internals are silently dropped. `external fn recv(msg: Signed<ExternalPayload>)` handles signed commands. No manual `flags & 1` bounced-bit check; unhandled bounces fall through to the default silent-drop wrapper.
- **`SubOp : u8` with explicit discriminants** gives 8-bit wire width at the cost of zero source-level ceremony. The compiler decodes it before the user body.
- **`Dict<(i8, u256), ()>`** replaces 0.4.6's manual 264-bit packed key dict. The tuple key is laid out MSB-first per field order, reproducing the same wire form.
- **State-struct update.** `state.plugins.insert(...)` mutates in place; `state.seqno += 1` updates a single field. Save happens implicitly at wrapper return.
- **All `throw_unless(N, ...)` map to `require!` with the same numeric exit code.** ABI preserved.

## 6. C3 — Highload Wallet v2

### 6.1 0.4.6 reference (91 lines)

Full source at `crypto/smartcont/highload-wallet-v2-code.fc`. Shape:

- Persistent state: `(subwallet_id, last_cleaned, public_key, old_queries: Dict<u64, ()>)`.
- Anti-replay via query-id deduplication, not seqno.
- External body carries a `Dict<i16, (u8, ^Cell)>` of indexed (mode, ref) action pairs.
- After dispatch: insert new query-id, trim expired queries from the bottom.

### 6.2 0.5.0 canonical rewrite (~55 lines)

```func
#![edition = "0.5.0"]

contract Highload {
    state {
        subwallet_id: u32,
        last_cleaned: u64,
        pubkey:       u256,
        old_queries:  Dict<u64, ()>,
    }

    error DuplicateQuery = 32,
          WrongSubwallet = 34,
          BadSignature   = 35,
          Expired        = 35,
          WrongGlobal    = 36;

    message Payload {
        global_id:    i32,
        subwallet_id: u32,
        query_id:     u64,
        actions:      Dict<i16, (u8, RawCell)>,
    }

    external fn recv(msg: Signed<Payload>) {
        let p = msg.body;
        require!(p.global_id == global_id(), WrongGlobal);

        // query_id encodes (expire_at << 32 | nonce)
        let bound = (now() as u64) << 32;
        require!(p.query_id >= bound,                 Expired);
        require!(p.subwallet_id == state.subwallet_id, WrongSubwallet);
        require!(!state.old_queries.contains(&p.query_id), DuplicateQuery);
        require!(msg.check(state.pubkey),              BadSignature);
        accept_message();

        for (_, (mode, raw)) in p.actions.iter_sorted() {
            send_raw(raw, mode);
        }

        state.old_queries.insert(p.query_id, ());
        let trim = bound - (64u64 << 32);
        while let Some((min_id, _)) = state.old_queries.pop_min() {
            if min_id >= trim {
                state.old_queries.insert(min_id, ());
                break;
            }
            state.last_cleaned = min_id;
        }
    }

    enum Status { Processed, Unprocessed, Forgotten }

    get fn processed(query_id: u64) -> Status {
        if state.old_queries.contains(&query_id) { return Status::Processed; }
        if query_id <= state.last_cleaned        { return Status::Forgotten; }
        Status::Unprocessed
    }

    get fn get_public_key() -> u256 { state.pubkey }
}
```

### 6.3 Migration notes (C3)

- **`do ... until` → `while let`.** `udict_delete_get_min` in a `do...until` loop becomes `while let Some((min_id, _)) = state.old_queries.pop_min() { ... }` plus an explicit `break` for the stop condition.
- **Typed three-state getter.** The 0.4.6 getter returns `-1 / 0 / 1` with implicit meanings. The 0.5.0 `Status` enum forces the wire form to a `⌈log₂ 3⌉ = 2`-bit tag (Canonical Decision 2). Callers need to update to the enum shape; legacy callers can use a sibling getter that maps to `i2` for back-compat if the operator truly needs it.
- **Dict iteration via `for`.** `iter_sorted()` yields ascending-key pairs; the loop desugars via the stdlib `IntoIter` trait per Canonical Decision 7.
- **Typed body with a `Dict` field** exercises the derived codec over a generic `Dict<K, V>`; the wire shape is `u16 length + dict` inlined into the current cell. The `Signed<Payload>` wrapper keeps the signature verification delegated.
- **No `recv_internal`.** Highload wallets explicitly ignore internal messages; omitting the `internal fn` gets the same no-op wrapper behaviour.

## 7. C4 — Jetton Wallet (Synthetic, from TEP-74)

No 0.4.6 reference exists in the repo; this entry is synthesised from TEP-74 / TOS-TEP-74. The master-worker pattern, typed messages, and `BounceContext<T>` with width check all live here.

### 7.1 0.5.0 canonical rewrite

```func
#![edition = "0.5.0"]

contract JettonWallet {
    state {
        balance:            Coins,
        owner:              Address,
        master:             Address,
        wallet_code:        Cell<JettonWalletCode>,
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
        // Non-entry helpers do not see `ctx` or `state` implicitly
        // (main spec §Entrypoints), so the entry body forwards them.
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
        // The sibling wallet refused our transfer. Refund the balance.
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
    require!(sender == state.owner,       NotOwner);
    require!(state.balance >= req.amount, InsufficientBalance);
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
) { /* similar validation and state update */ }

fn on_burn(
    mut state: JettonWalletState, sender: Address, req: Burn,
) { /* ... */ }
```

### 7.2 Migration notes (C4)

- **Master-worker derivation is stdlib.** `derive_jetton_wallet_address(master, code, owner)` lives in `std::message` and encapsulates the `StateInit` hashing that reconstructs a sibling wallet address. Authors never open-code this.
- **`match msg` dispatches three opcodes in one wrapper.** The compiler peeks 32 bits, matches against the three message-level opcodes, and dispatches to the matching arm. Unknown op $\to$ silent drop.
- **`BounceContext<InternalTransfer>` enforces the 256-bit rule.** `InternalTransfer`'s fixed header (`u64 + Coins + Address + Address? + Coins`) is checked at compile time against the 256-bit budget; if it exceeded the budget the compile error `BounceBodyTooWide` would fire and the author would fall back to `BounceContext<Slice>`.
- **Helpers use `mut state: JettonWalletState`.** No `&mut self`. The lowering passes state by value and returns the updated state; the caller's `state` binding is rebound. On abort the whole transaction unwinds, so no rollback logic per helper.
- **`BodyLayout::Auto`** decides whether the 5-field `InternalTransfer` fits inline in the outgoing message cell per the canonical fit predicate (Canonical Decision 4).

## 8. C5 — Multisig (Sketch)

A full rewrite of `crypto/smartcont/multisig-code.fc` (318 lines) lives in corpus v3. Sketch:

- `state { threshold: u8, signers: Dict<u256, SignerMeta>, pending: Dict<u64, Proposal> }`
- `enum MultisigMsg { Propose(Propose), Approve(Approve), Cancel(Cancel), Execute(Execute) }`
- `external fn recv(msg: Signed<Approve>)` for signer approval messages
- `internal fn recv(msg: MultisigMsg)` for on-chain triggers
- `emit ApprovalCast { proposal_id, signer }` on every successful approval

Canonical Decision interactions specific to multisig:

- Canonical Decision 2: `enum MultisigMsg` has 4 variants, tag width = 2 bits if padded via `: u8` the full byte is serialised.
- Canonical Decision 6: getter `get_pending_proposals()` returning `Vec<Proposal>` exercises the stack-tuple form.

## 9. Deferred — Elector

`crypto/smartcont/elector-code.fc` (1187 lines) is scheduled for corpus v3, after the reference compiler exists and the stdlib `Dict<K, V>` stabilises.

## 10. Cross-Contract Migration Patterns

Patterns that recur across the corpus.

### 10.1 `throw_unless(N, cond)` → `require!(cond, NameN)`

Declare the error in the `contract` block's `error` shorthand with `= N`; use `require!(cond, NameN)`. ABI preserved byte-for-byte.

### 10.2 Entry parameter is a message type, not a Slice

```
// 0.4.6
() recv_external(slice in_msg) impure { var cs = in_msg; /* parse */ }

// 0.5.0
external fn recv(msg: Signed<Payload>) { /* p = msg.body */ }
```

The wrapper decodes. The author doesn't write field-by-field loads.

### 10.3 Fixed-header-plus-tail via trailing `Slice` field

```
message Payload {
    // typed fields...
    actions: Slice,   // last field = remainder
}
```

Structured parse for the header; author iterates the tail manually.

### 10.4 Multi-opcode internal via enum + match

```
enum WalletMsg {
    A(MessageA),
    B(MessageB),
}
internal fn recv(msg: WalletMsg) { match msg { ... } }
```

One entry, compiler-peeks-opcode, dispatches.

### 10.5 Mutating helpers via `mut state`

```
fn helper(mut state: WalletState, ...) { state.seqno += 1; ... }
internal fn recv(msg: ...) { helper(mut state, ...); /* state committed */ }
```

No `&mut self` borrow; value-thread. Abort unwinds the whole transaction, so no rollback logic needed.

### 10.6 Bounce handling via `BounceContext<T>`

If `T` fits in 256 bits and zero refs, `bounce fn on_bounce(ctx: BounceContext<T>)` decodes automatically. Otherwise fall back to `BounceContext<Slice>`.

### 10.7 Signature-wallet pattern via `Signed<T>`

```
external fn recv(msg: Signed<Payload>) {
    require!(msg.check(state.pubkey), BadSignature);
    accept_message();
    // ... use msg.body ...
}
```

## 11. Open Items Beyond v1

The corpus is deliberately small at v2. Future additions (v3):

- full multisig rewrite (C5 expansion);
- elector;
- a payment-channel reference;
- a DNS-resolver reference;
- at least one contract that uses an `asm { """...""" }` block for a performance-critical inner loop, to validate the escape-hatch lowering end-to-end.

## 12. How to Add to the Corpus

To propose a new entry:

1. **Rationale.** Justify the feature combination it exercises that earlier entries do not cover.
2. **0.4.6 reference.** Existing contract or accepted TEP.
3. **0.5.0 rewrite** in the v4 surface, without relying on unspecified behaviour.
4. **Migration notes** at the same level of detail as §4.3 / §5.3 above.
5. **Expected-bytecode fixture** once the reference compiler lands.
6. **PR for RFC review** per stdlib governance (see `doc/tos-func-stdlib-design.md` §14).

---

**End of corpus document v2.** Next: corpus v3 after reference compiler lands.
