# Token bridge settlement protocol (design, for review)

Status: **design only, version 2.** Nothing in this document is implemented.
It specifies the change to `jetton-bridge.fc`, `jetton-minter.fc`,
`jetton-wallet.fc`, `settlement.fc`, the deployment scripts and the EVM lock
event that makes every mint and burn a durable, authenticated, idempotent
operation at every participant, recoverable by permissionless funded
retransmission.

Base: `fix/security-findings` at `6f86b5cf1`. Line references are to that
commit unless a file is outside the bridge directory.

Section 16 lists what changed from version 1 (`63afca486`) and why.

## 1. Why the current protocol cannot close

The current protocol (`settlement.fc`, `SECURITY.md` "Completion of mints and
burns") reports each outcome once and treats a bounce as a failure:

- A failed credit bounces to the minter, whose bounce handler reads
  ConfigParam 79 (`jetton-minter.fc:141`). With the parameter missing the
  handler throws, a bounce cannot bounce, and the only record of the outcome
  is gone. The mint stays `MINT_IN_FLIGHT` at the bridge, and `retry_mint`
  admits only `MINT_FAILED` (`jetton-bridge.fc:355`).
- Reports to the bridge are sent with mode `64 + 2`
  (`jetton-minter.fc:125`). An unfundable report is skipped, and nothing can
  send it again.
- The minter refunds a burn notification that bounces
  (`jetton-minter.fc:165`), so the bounce alone authorizes the refund. A
  missing ConfigParam leaves the burn `BURN_AWAITING_BRIDGE`, which
  `retry_refund` does not admit (`:334`).
- Each operation is budgeted once, at its first leg, at that moment's prices.

These gaps share one cause: a leg's outcome exists only in a message. The
design gives each participant a durable record of every operation and of the
result it produced. Anyone can have that record sent again, and the receiver
deduplicates it.

## 2. Terms, atomicity, and what "exactly once" covers

- **Leg**: one transaction at one participant, caused by one message.
- **Request**: a message asking the receiver to apply a settlement effect.
- **Result**: a message reporting an effect already applied and recorded.
- **Final**: a record that no later message can change.
- **Lost**: a message that produced no settlement effect at its receiver.
  Either its transaction threw, ran out of gas or failed in its action phase,
  or a test removed it from the queue. With every protocol send in mode 0
  (no `+2`), a protocol message cannot be silently skipped.
- **Advance**: the permissionless retransmission of section 8.
- **Life** (incarnation): one existence of an account between its first
  transaction and its deletion. Section 10 defines it.

**Settlement effects versus native fees.** A settlement effect is a change
to jetton balances, supply, reservations, protocol records, swap
consumption, `LOG_BURN` or a refund. The exactly-once properties apply to
settlement effects only. Native-currency movements are different:

- Gas, forwarding and storage fees are paid every time a transaction runs,
  including a transaction that refuses.
- A refusing leg that received a non-bounceable message keeps that
  message's value.
- An entry message from a user or advancer bounces back minus fees when it
  is refused.

Duplicates therefore cost the payer native currency and never repeat a
settlement effect.

**Atomicity of one leg.** If the action phase fails, the compute phase's
storage update is not committed (the existing premise at `settlement.fc:46`).
Every protocol send uses mode 0 or mode 1 with a value fixed in the compute
phase, never `+2`. A leg therefore commits its record and all its protocol
messages together, or commits nothing:

- An action-phase failure rolls the leg back. The causes are insufficient
  funds for an outgoing message, a message over the size limit, and an
  account state over the cell limit.
- The predecessor's durable record is untouched. It can still reproduce the
  request, so the same or another participant can advance it.

Records that are optional (the logs other than `LOG_BURN`) remain mode 2.

**No reliance on delivery order.** Every receiver deduplicates by identity,
and no correctness argument uses arrival order. Order decides only which of
two valid outcomes a cancellation race produces (section 7.4).

## 3. Operation identity

### 3.1 Channels and lives

A **channel** is the tuple

```
(kind, sender address, sender life, receiver address, receiver life)
```

Addresses are full standard addresses: workchain and hash. The bridge is on
the masterchain (`-1`). Minters and wallets are on the basechain (`0`), and
the contracts enforce this (`force_chain`, `WORKCHAIN`). A participant's
**life** is its `born_lt`: the logical time of the first transaction that
ran its code since its account was created (section 10.4). Every protocol
message carries the sender's life and the life it expects the receiver to
have. A receiver whose own life differs refuses the message with no effect.
A sender whose life differs from the one the receiver recorded is handled by
section 10.4 and never mixed with the recorded one.

| Channel | Requests | Numbered by | Deduplicated at |
|---|---|---|---|
| S bridge <- EVM | swap votes | **EVM lock nonce `n`**, dense per EVM bridge (section 4) | bridge: `swap_watermark` + `swaps_above` |
| C1 bridge -> minter | `prepare(s)`, `commit(s)` | `s`, per minter, at the bridge | minter: `mint_watermark` + `mints` |
| C2 minter -> wallet | `credit(s)` (mint credits) | the same `s` | wallet: `credit_floor` + `credits_above` (section 5.3) |
| C3 wallet -> minter | `burn_request(b)` | `b`, per wallet life, at the wallet | minter: per holder life `burn_watermark` + `burns` |
| C4 minter -> bridge | `burn_notice(m)` | `m`, per minter, at the minter | bridge: per minter `burn_watermark` + `burns_above` + `cancelled` |
| R wallet <- minter | `refund(b)` | the burn's own `b` | wallet: its own `burns[b]` record |

**Allocatable numbers** on every channel are `0 .. 2^64 - 2`. The value
`2^64 - 1` is the exhausted sentinel, so a watermark of type `uint64` can
always pass the last allocated number. A sender checks exhaustion **before**
assigning a number, and it does so at the point where refusing still has no
effect: the vote for `s`, the wallet's `burn` for `b`, the minter's burn
acceptance for `m` (section 7.3), and the EVM for `n`.

### 3.2 Canonical descriptors

Every request carries its **descriptor cell**, not a hash. The receiver
computes the operation hash with `cell_hash` over the descriptor it
received, and compares it with the hash in its record when one exists.
Descriptors are serialized exactly as below (bit widths fixed, coins as
`VarUInteger 16`, addresses as `addr_std` without anycast). A request whose
descriptor does not parse exactly (`end_parse`) is refused.

```
mint_descriptor#4d494e54
    n:uint64 s:uint64 amount:(VarUInteger 16)
    ^[ bridge:MsgAddressInt evm_bridge:uint160 evm_chain_id:uint32 ]
    ^[ minter:MsgAddressInt recipient_owner:MsgAddressInt ] = MintDescriptor;

burn_descriptor#4255524e
    b:uint64 amount:(VarUInteger 16) destination:uint160 token_address:uint160
    ^[ minter:MsgAddressInt owner:MsgAddressInt wallet_life:uint64 ] = BurnDescriptor;
```

The root cells hold at most 32 + 64 + 64 + 124 = 284 and 32 + 64 + 124 +
160 + 160 = 540 bits. Each reference cell holds at most 267 + 160 + 32 = 459
and 267 + 267 + 64 = 598 bits. All fit in one cell each. The descriptor
binds the originating contract (the bridge for a mint, the wallet's owner,
minter and life for a burn), the operation kind (the tag), the recipient and
the amount.

### 3.3 Order of checks in every handler

1. Parse and authenticate: the sender address, the sender life, and the
   expected receiver life (section 4).
2. Only then look up the number:
   - **Below the watermark:** send the **already-final number response**.
     This is the recorded final result for that number on that channel. It
     never echoes a field from the request as if authenticated, and it
     applies nothing.
   - **Present:** recompute the hash from the descriptor and compare it. A
     mismatch is refused with `error::operation_mismatch` and has no
     effect. A match re-sends the result, or continues the pending work.
   - **New:** check funding, then apply the effect and create the record in
     the same leg.
3. Results carry the number, the outcome where there are two, and both
   lives. A result is matched to the receiver's own record by number and
   authenticated channel. It only finishes that record. A result for an
   absent or already final record has no effect.

### 3.4 Watermarks and acknowledged compaction

On every numbered channel the receiver keeps a watermark `W` and a
dictionary of entries at or above `W`. An effect is applied only for a
number that is neither below `W` nor present, and doing so creates the entry
in the same leg. `W` advances over contiguous final entries, at most
`FOLD_LIMIT` (proposed: 8) per leg, and never decreases. Sender numbers are
never reused within a channel, and a channel includes both lives. So no
request's effect is applied twice, at any delay, as long as the receiver's
life persists (section 10).

Two channels have two possible final outcomes: C1 (COUNTED or REFUSED) and
C4 (RECORDED or CANCELLED). Below `W` the receiver keeps the less common
outcome as an **exception** entry. Exceptions are not permanent. Each one is
dropped once the receiver learns that the sender has finished with that
number. The sender **piggybacks its own finished watermark** on every
request it sends on the channel:

- C1: the bridge's `finished_mint_watermark`. It covers every `s` whose
  outcome the bridge has applied.
- C4: the minter's `finished_notice_watermark`. It covers every `m` whose
  result the minter has applied.
- C3: the wallet's `finished_burn_floor`. It covers every `b` whose outcome
  or refund the wallet has applied.

A sender that has applied the outcome for a number never asks about it
again: its advance refuses, and its record is final. A stale copy of an
earlier request may still arrive, but whatever answer it gets is ignored,
because the sender's record is already final. So an exception below the
piggybacked watermark is never needed again. No participant keeps a
permanent per-operation record.

## 4. Pinned participants and the ConfigParam boundary

ConfigParam 79 is read **only when new business starts**:

- a swap vote and `pay_swap` (oracle address, `state_flags`, mint fee);
- the wallet's `burn` (`state_flags`, burn fee);
- the paths outside settlement: jetton transfers between wallets, wallet
  address discovery, and get-methods that report configuration.

No completion, status, result, cancellation, open or advance handler reads
it.

| Participant | Authenticates | From (no ConfigParam) |
|---|---|---|
| bridge | its minters | `calculate_minter_address(token_data)` from stored minter and wallet code and `my_address()`, plus the minter life recorded at `prepared` |
| minter | its bridge | `bridge:MsgAddressInt` in the minter's **initial data** (the address is pinned in the StateInit), plus the bridge life recorded at the first `prepare` |
| minter | its wallets | `calculate_user_jetton_wallet_address` from stored wallet code, plus the holder's recorded wallet life |
| wallet | its minter | `jetton_master_address` (initial data), plus the minter life recorded at `open` |

**Hidden reads.** Today every path in the wallet and the minter calls
`get_jetton_bridge_config()` (`config.fc:237`) before dispatching:
`jetton-wallet.fc:264` and `jetton-minter.fc:224`, plus `on_bounce` at
`jetton-minter.fc:141`. The implementation dispatches every settlement
opcode before any call that can reach that helper. Two checks hold it there:

- **Dynamic:** every settlement path, including duplicates, final-result
  re-sends and advances, runs in tests with ConfigParam 79 absent and with it
  changed (T-M7, T-B7).
- **Static:** `scripts/verify-token-bridge.py` requires that no settlement
  handler function reaches `get_jetton_bridge_config`. It inspects the call
  graph of the named handlers in the source, and its mutation is to insert
  such a call.

**Moved out of ConfigParam 79.** These become code constants in
`settlement.fc`: `WALLET_RESERVE`, `MINTER_RESERVE`, `BRIDGE_RESERVE`, the
per-step gas declarations, `FOLD_LIMIT`, `STORAGE_QUOTE_HORIZON` and the
admission limits of section 6. The values are provisional (ruling Q7) and
are fixed by measurement: aged dictionaries, storage debt and top-up.

**Suspension.** Flags are checked only at entry:

- `STATE_SWAPS_SUSPENDED` stops votes.
- `STATE_BURN_SUSPENDED` stops the wallet's `burn`.

Advances, results, open and owner cancellation are accepted while suspended.
This is a behaviour change: today `retry_mint` is refused while swaps are
suspended (`jetton-bridge.fc:347`).

**A replaced bridge (ruling Q3).** A bridge replaced through ConfigParam 79
does not inherit tokens, because a minter's address includes its bridge.
Wallets of the old token family keep routing burns to their pinned minter,
and that minter routes them to its pinned old bridge. A replaced ConfigParam
cannot redirect them, because authentication never reads it. The old
family's `burn` entry still reads the current ConfigParam 79, but only for
admission policy (suspension flag and fee). Operators must therefore:

- keep the old bridge funded and observed by oracles while any old-family
  supply exists, and
- either keep the old family's admission policy in the current parameter,
  or set burn suspension knowing that it applies to both families.

A burn of either family is always authenticated against its own pinned
bridge.

## 5. Durable records

The layouts are TL-B. Dictionaries are grouped into extra reference cells so
that no cell has more than four references; that packing is an
implementation detail. Every contract keeps entry counters for its growing
dictionaries, for admission control (section 6).

### 5.1 Bridge (masterchain)

```
storage#_ born_lt:uint64 collector_address:MsgAddress
          jetton_minter_code:^Cell jetton_wallet_code:^Cell
          ^[ swap_watermark:uint64 swaps_above:(HashmapE 64 SwapState) swaps_count:uint32
             channels:(HashmapE 256 ^TokenChannel) channels_count:uint32 ] = BridgeStorage;
swap_paid#0  payer_fee:Coins = SwapState;
swap_preparing#1 minter:uint256 s:uint64 = SwapState;
swap_consumed#2 minter:uint256 s:uint64 = SwapState;
token_channel#_ token_data:^Cell minter_life:uint64 next_mint_seq:uint64
    finished_mint_watermark:uint64
    pending_mints:(HashmapE 64 PendingMint) pending_count:uint32
    burn_watermark:uint64 burns_above:(HashmapE 64 BurnOutcome)
    cancelled:(HashmapE 64 uint256) burns_count:uint32
    minter_finished_notice_watermark:uint64
    liabilities:(HashmapE 64 PendingMint) = TokenChannel;
pending_mint#_ n:uint64 descriptor_hash:uint256 descriptor:^MintDescriptor
    status:uint1 = PendingMint;                ;; 0 PREPARING, 1 COMMITTED
burn_outcome#_ outcome:uint1 descriptor_hash:uint256 = BurnOutcome;  ;; 0 RECORDED, 1 CANCELLED
```

| Record | Transition | Caused by | Effect in the same leg |
|---|---|---|---|
| swap `n` | unseen -> PAID | `pay_swap(n)` with the exact fee; refused if `n < swap_watermark`, already present, or `n >= swap_watermark + PAY_WINDOW` | records the fee |
| swap `n` | PAID -> PREPARING(s) | the swap vote | `pending_mints[s]` = PREPARING; `next_mint_seq += 1`; `prepare(s)` sent |
| swap `n` | PREPARING -> CONSUMED (irrevocable) | `prepared(s)` from the minter | `pending_mints[s]` = COMMITTED; `commit(s)` sent |
| swap `n` | PREPARING -> PAID | `refused(s)` from the minter | `pending_mints[s]` deleted; `s` is final as REFUSED |
| swap `n` | CONSUMED, folded | `swap_watermark` folds over CONSUMED | - |
| `pending_mints[s]` | COMMITTED -> deleted (final) | `mint_completed(s)` | `finished_mint_watermark` folds |
| burn `m` | unseen -> RECORDED | `burn_notice(m, cancel=0)` | `LOG_BURN` and `burn_result(m, RECORDED)` |
| burn `m` | unseen -> CANCELLED | `burn_notice(m, cancel=1)` | `cancelled[m]`; `burn_result(m, CANCELLED)` |
| `cancelled[m]` | dropped | a `burn_notice` carrying `minter_finished_notice_watermark > m` | - |

A REFUSED `s` leaves the swap PAID and re-votable under a new `s`. A
refusal is the minter's durable decision (section 7.1), so the old `s` can
never be committed.

### 5.2 Minter (basechain)

```
storage#_ total_supply:int128 in_flight:Coins mint_reserve:Coins burn_reserve:Coins
          content:^Cell jetton_wallet_code:^Cell
          ^[ bridge:MsgAddressInt bridge_life:uint64 born_lt:uint64
             mint_watermark:uint64 mints:(HashmapE 64 MintRecord) refused:(HashmapE 64 Unit)
             bridge_finished_mint_watermark:uint64
             next_notice_seq:uint64 finished_notice_watermark:uint64
             notices:(HashmapE 64 NoticeRef)
             holders:(HashmapE 256 ^Holder) holders_count:uint32 ] = MinterStorage;
mint_record#_ descriptor_hash:uint256 owner:uint256 amount:Coins
    status:uint2 = MintRecord;    ;; 0 RESERVED, 1 CREDITING, 2 COUNTED
notice_ref#_ owner:uint256 wallet_life:uint64 b:uint64 = NoticeRef;
holder#_ wallet_life:uint64 open:uint2      ;; 0 NEW, 1 OPENING, 2 OPEN
    awaiting_open:(HashmapE 64 Unit)       ;; s values whose credit waits for open
    burn_watermark:uint64 burns:(HashmapE 64 BurnRecord)
    wallet_finished_floor:uint64
    exceptions:(HashmapE 64 Unit)          ;; b below burn_watermark that ended refunded
    old_lives:(HashmapE 64 ^Liabilities) = Holder;
burn_record#_ descriptor_hash:uint256 amount:Coins m:uint64
    status:uint3 cancel_requested:uint1 = BurnRecord;
    ;; 0 AWAITING_BRIDGE, 1 RECORDED, 2 REFUNDING, 3 REFUNDED, 4 REJECTED_REFUNDING
```

Supply accounting:

- `total_supply` is signed. It counts credits that wallets have confirmed,
  minus burns the minter has accepted. It can briefly fall below zero when a
  burn of tokens whose credit has landed is accepted before that credit's
  confirmation. `get_jetton_data` reports `max(total_supply, 0)`, and a new
  getter reports the signed value.
- Capacity in use is `total_supply + in_flight + mint_reserve + burn_reserve`,
  which never exceeds `MAX_SUPPLY`.

| Record | Transition | Caused by | Effect in the same leg |
|---|---|---|---|
| `mints[s]` | unseen -> RESERVED | `prepare(s)`, capacity available (section 6) | `mint_reserve += a`; holder created if absent (NEW -> OPENING, `open` sent); `prepared(s, born_lt)` sent |
| `mints[s]` | unseen -> REFUSED (final) | `prepare(s)`, capacity unavailable | `refused[s]`; `refused(s)` sent |
| `mints[s]` | RESERVED -> CREDITING | `commit(s)` | `mint_reserve -= a`, `in_flight += a`; `credit(s)` sent if the holder is OPEN, else `s` goes into `awaiting_open` |
| `mints[s]` | CREDITING -> COUNTED (final) | `credit_recorded(s)` from the holder's current wallet life | `in_flight -= a`, `total_supply += a`; `mint_completed(s)` sent |
| holder | OPENING -> OPEN | `opened(wallet_life)` | wallet life recorded; up to `FOLD_LIMIT` awaiting credits sent |
| `burns[b]` | unseen -> AWAITING_BRIDGE | `burn_request(b)`, `m` available | `total_supply -= a`, `burn_reserve += a`; `notices[m]`; `burn_notice(m)` sent |
| `burns[b]` | unseen -> REJECTED_REFUNDING | `burn_request(b)` with notice numbers exhausted, or holder capacity exhausted (section 6) | `total_supply -= a`, `in_flight += a`; `refund(b)` sent; **no notice can ever exist for `b`** |
| `burns[b]` | AWAITING_BRIDGE -> RECORDED (final) | `burn_result(m, RECORDED)` | `burn_reserve -= a`; `burn_outcome(b)` sent |
| `burns[b]` | AWAITING_BRIDGE -> REFUNDING | `burn_result(m, CANCELLED)` | `burn_reserve -= a`, `in_flight += a` (capacity unchanged); `refund(b)` sent |
| `burns[b]` | REFUNDING or REJECTED_REFUNDING -> REFUNDED (final) | `refund_recorded(b)` | `in_flight -= a`, `total_supply += a`; `exceptions[b]` if folded |
| `exceptions[b]` | dropped | a `burn_request` carrying `finished_burn_floor > b` | - |

### 5.3 Wallet (basechain)

```
storage#_ balance:Coins owner_address:MsgAddressInt jetton_master_address:MsgAddressInt
          jetton_wallet_code:^Cell
          ^[ born_lt:uint64 minter_life:uint64
             credit_floor:uint64 credits_above:(HashmapE 64 uint256)
             next_burn_seq:uint64 finished_burn_floor:uint64
             burns:(HashmapE 64 PendingBurn) ] = WalletStorage;
pending_burn#_ descriptor:^BurnDescriptor cancel_requested:uint1 = PendingBurn;
```

Credit deduplication needs no counter at the minter. Every `credit(s)`
carries the minter's `mint_watermark`. Every `s` below it is final at the
minter, either COUNTED, which requires this wallet life's
`credit_recorded(s)`, or REFUSED, which is never credited. The wallet sets
`credit_floor := max(credit_floor, mint_watermark)` and drops
`credits_above` entries below it. A `credit(s)` with `s < credit_floor`, or
with `s` in `credits_above`, re-sends `credit_recorded(s)` and credits
nothing. Otherwise the wallet credits and records `s`. Wallet storage is
bounded by its uncounted credits.

| Record | Transition | Caused by | Effect in the same leg |
|---|---|---|---|
| `born_lt` | 0 -> `cur_lt()` | the first transaction running wallet code in this life | - |
| `minter_life` | 0 -> L | `open(L)` from the minter | `opened(born_lt)` sent |
| credit `s` | unseen -> credited (final) | `credit(s)` | `balance += a`; `credit_recorded(s)` sent |
| `burns[b]` | -> PENDING | owner `burn` (requires `minter_life != 0`; see `open_request` in section 7.2) | `balance -= a`; `next_burn_seq += 1`; `burn_request(b)` sent |
| `burns[b]` | `cancel_requested` 0 -> 1 | owner `cancel_burn(b)` | `burn_request(b, cancel=1)` sent |
| `burns[b]` | PENDING -> deleted | `burn_outcome(b)` | `finished_burn_floor` folds |
| `burns[b]` | PENDING -> deleted | `refund(b)` | `balance += a`; `refund_recorded(b)` sent; floor folds |
| refund `b`, `burns[b]` absent | - | `refund(b)` | re-sends `refund_recorded(b)`; credits nothing |

A refund is deduplicated by the wallet's own `burns[b]`. Burn numbers are
never reused in a wallet life. A refund is the only way to delete
`burns[b]` other than a RECORDED outcome, and the bridge decides between the
two exactly once. So a refund for an absent `b` can only be a refund already
credited.

The wallet's owner-facing `burn` and `transfer` keep their message layouts.
Transfers between wallets keep the unchanged TEP-74 path. An
`internal_transfer` whose sender is the minter is refused, so the two credit
paths cannot be confused.

## 6. Capacity and admission

No consumed swap and no accepted burn may need a number, supply capacity or
storage capacity that might not exist later. Every such resource is taken
**at admission**, before any effect that cannot be undone. A completion
**never** needs a new resource:

- **Supply.** Admitting `prepare(s)` requires
  `total_supply + in_flight + mint_reserve + burn_reserve + a <= MAX_SUPPLY`.
  It reserves `a` in `mint_reserve`, and `commit` moves it to `in_flight`.
  Accepting a burn moves `a` from `total_supply` into `burn_reserve`.
  RECORDED releases it. CANCELLED moves it to `in_flight` for the refund
  without changing the capacity in use. A mint can therefore use capacity a
  burn frees only after the bridge has **recorded** that burn, and a refund
  always fits.
- **Numbers.** `s` is taken by the vote, which refuses before consuming
  anything if `s` is exhausted. The credit uses the same `s`, and the refund
  uses the burn's own `b`, so neither needs a new number. `b` is taken by
  the wallet's `burn`, which refuses before the debit if `b` is exhausted.
  `m` is taken when the minter accepts a burn. If `m` is exhausted, the
  minter **rejects** that burn locally (REJECTED_REFUNDING). That is safe
  because no notice was ever sent for `b`, so `LOG_BURN` is impossible for
  it. The refund needs no new number.
- **Storage.** Each contract keeps entry counters and refuses new
  **admissions** above `ADMISSION_LIMIT`. The limit is chosen so that
  completing every admitted operation stays under the account cell limit:
  `max_acc_state_cells` on the basechain, and `max_mc_acc_state_cells` on
  the masterchain (`crypto/block/transaction.cpp:3970-3975`). Completions
  only shrink state, or grow it by at most a per-operation bound that
  admission has already counted.

  A burn from a holder with no holder entry at a minter whose holder count
  is at its limit is **rejected locally** (REJECTED_REFUNDING). The
  rejection is undone by the refund: `total_supply -= a`, `in_flight += a`,
  then `+a` on the count, so it leaves no permanent record. A later
  duplicate request would be rejected again, and the wallet credits the
  refund only once (section 5.3). A mint to a new holder at that limit is
  refused at `prepare`, so the swap is not consumed.

The account cell limit is a ConfigParam 43 value. The code defaults are
65 536 cells per basechain account and **2 048 per masterchain account**
(`crypto/block/mc-config.h:429-430`). The fixture holds 65 536 for both.
This is why no design here keeps a permanent per-operation record on the
bridge (section 4, Q1).

**What a refusal at admission means for users.** A `prepare` refused for
supply or storage leaves the swap PAID and re-votable. The locked ERC-20
stays locked on the EVM side until capacity exists. No consumed swap ever
waits for a future burn or a future number.

## 7. Message flows

### 7.1 Mint

| Id | Message | From -> to | Carries |
|---|---|---|---|
| G1 | swap vote | multisig -> bridge | unchanged fields plus `n` (section 11) |
| P1 | `prepare` | bridge -> minter (minter StateInit) | `s`, mint descriptor, bridge life, `finished_mint_watermark` |
| P2 | `prepared` / `refused` | minter -> bridge | `s`, minter life |
| O1 | `open` | minter -> wallet (wallet StateInit) | minter life |
| O2 | `opened` | wallet -> minter | wallet life |
| M1 | `commit` | bridge -> minter | `s`, descriptor, lives, `finished_mint_watermark` |
| M2 | `credit` | minter -> wallet | `s`, descriptor, lives, `mint_watermark` |
| M3 | `credit_recorded` | wallet -> minter | `s`, owner, lives |
| M4 | `mint_completed` | minter -> bridge | `s`, `^token_data`, lives |

1. **G1 at the bridge** (new business). The oracle quorum, flags and fee
   checks are as today. The swap must be PAID and `s` must be available. The
   swap becomes PREPARING(s), and P1 is sent with the swap's recorded fee.
   Nothing irrevocable has happened yet.
2. **P1 at the minter.** The sender must be the pinned bridge address. On
   first contact the minter records the bridge life, and after that it
   requires a match.
   - Below `mint_watermark`: an already-final number response, `prepared`
     or `refused` according to the exception set.
   - Present: hash compare. RESERVED, CREDITING or COUNTED answer
     `prepared`; REFUSED answers `refused`.
   - New: if capacity is unavailable, record REFUSED and send `refused`.
     Otherwise reserve, create the holder if needed (sending O1), and send
     `prepared`. Either decision is durable and final for this `s`.
3. **P2 at the bridge.** `prepared` makes the swap CONSUMED and sends M1.
   `refused` restores PAID. Neither can happen twice: a second P2 for an
   `s` that is already COMMITTED or already deleted has no effect.
4. **O1 at the wallet.** The wallet records the minter life if unset, then
   sends O2. With the same life recorded it sends O2 again. With a
   different life recorded, it refuses (section 10).
5. **O2 at the minter.** The holder becomes OPEN with that wallet life.
   With a different life already recorded, see section 10.4. The minter
   sends M2 for every awaiting `s`, up to `FOLD_LIMIT`. The rest go out by
   advance.
6. **M1 at the minter.** RESERVED becomes CREDITING. M2 is sent if the
   holder is OPEN, otherwise the credit waits for open. A duplicate commit
   for CREDITING re-sends M2. For COUNTED it re-sends M4.
7. **M2, M3 and M4.** These follow the transitions in section 5. M4 at the
   bridge deletes `pending_mints[s]`.

The swap is consumed only after the minter durably reserved supply and
created the holder record. Every later leg needs no new resource, and every
leg can be advanced. A reservation is never cancelled: `prepared` always
leads to commit. So a late or duplicated message can never authorize a
second mint, and a refusal can never follow a reservation for the same `s`.

### 7.2 Opening a wallet without a mint

A wallet that holds tokens only by transfer has `minter_life = 0` and
cannot `burn` yet. Anyone can send it `open_request`, funded, and the wallet
then sends `open_request(born_lt)` to the minter. The minter creates or
updates the holder and sends O1. This is the only extra step for holders
who never received a mint.

### 7.3 Burn

| Id | Message | From -> to | Carries |
|---|---|---|---|
| B0 | `burn` | owner -> wallet | unchanged |
| B1 | `burn_request` | wallet -> minter | burn descriptor, `cancel`, lives, `finished_burn_floor` |
| B2 | `burn_notice` | minter -> bridge | `m`, burn descriptor, `cancel`, `^token_data`, lives, `finished_notice_watermark` |
| B3 | `burn_result` | bridge -> minter | `m`, outcome, lives |
| B4 | `burn_outcome` | minter -> wallet | `b`, lives |
| R1 | `refund` | minter -> wallet | `b`, amount, lives |
| R2 | `refund_recorded` | wallet -> minter | `b`, owner, lives |
| X0 | `cancel_burn` | owner -> wallet | `b` |
| L | `LOG_BURN` | bridge -> external | **unchanged format** (`settlement.fc:130`) |

1. **B0 at the wallet** (new business). The checks of `burn_tokens` stay.
   New requirements: the wallet is opened, `b` is available, and the fee
   covers the burn path at current prices (section 9). The wallet then
   debits, records PENDING, and sends B1.
2. **B1 at the minter.** The sender must be the derived wallet. The wallet
   life is checked against the holder (section 10.4).
   - Below the holder's `burn_watermark`: an already-final number response.
     That is B4 (RECORDED), or nothing if `b` is in `exceptions` (a refunded
     burn has no wallet record left to answer).
   - Present: hash compare.
     - AWAITING_BRIDGE: set `cancel_requested` if `cancel=1`, then re-send
       B2 with the stored flag.
     - RECORDED: re-send B4.
     - REFUNDING or REJECTED_REFUNDING: re-send R1.
     - REFUNDED: nothing.
   - New: take `m`, or reject locally (section 6). Otherwise apply the
     supply move to `burn_reserve`, record AWAITING_BRIDGE and
     `notices[m]`, and send B2.
3. **B2 at the bridge.** The sender must be the minter derived from
   `token_data`, with its recorded life.
   - Below `burn_watermark`, or present: send B3 again with the recorded
     outcome (an already-final number response). **No `LOG_BURN`.**
   - New, `cancel=0`: record RECORDED, send `LOG_BURN` in mode 0, paid from
     B2's value, and send B3(RECORDED).
   - New, `cancel=1`: record CANCELLED in `cancelled[m]` and send
     B3(CANCELLED).
   - Either way, one leg commits the decision and its messages together.
4. **B3 at the minter.** The sender must be the pinned bridge.
   `notices[m]` must be present and the burn AWAITING_BRIDGE, else no
   effect. Transitions as in section 5.2.
5. **B4, R1 and R2** follow sections 5.2 and 5.3.

### 7.4 Cancellation (RECORDED versus CANCELLED)

- Only the **owner** can cancel, through `cancel_burn(b)` while `burns[b]`
  is pending. Cancellation is accepted while burns are suspended and reads
  no ConfigParam.
- The decision is made **only at the bridge, once per `m`**. The first B2
  for `m` to execute decides. The decision is immutable. Every later B2 for
  `m` receives the same outcome, and a cancelled `m` never logs.
- A refund is authorized only by B3(CANCELLED) from the pinned bridge, or by
  the minter's own local rejection of a `b` for which no notice can exist. A
  bounce, a missing result, a timeout or the owner's request alone never
  credits anything.
- If the minter has not seen `b` when the cancellation arrives (B1 was
  lost), it takes the ordinary new-burn path with `cancel=1`. The bridge
  still decides.
- In normal operation B2 with `cancel=0` executes first, and the
  cancellation then receives RECORDED. A cancellation wins only against a
  notice that has not executed, which is exactly the stuck case. Both
  outcomes are safe.

### 7.5 Bounces

All protocol messages are sent **non-bounceable**. A refusing leg keeps the
value, and the sender's record stays advanceable. No protocol state depends
on a bounce. A bounced message reaching a protocol handler is accepted and
ignored: only an owner's or an advancer's own message can bounce. The
wallet's bounce-restore for transfers between wallets is unchanged. **Its
bounce-restore for `burn_notification` is removed.**

## 8. Permissionless funded retransmission (`advance`)

Each contract accepts `advance(kind, id)` from **any sender**. The message
carries the kind, the identifier and its value, and nothing else. Every
message the contract sends in response is rebuilt from its stored record and
addressed to a pinned or derived address. **No input of the caller reaches
the destination, amount, recipient, outcome or life.**

| Contract | Kind, id | Unfinished record | Final, or below the watermark | No record |
|---|---|---|---|---|
| bridge | MINT `(minter, s)` | PREPARING: re-send P1; COMMITTED: re-send M1 | refuse | refuse |
| bridge | BURN_RESULT `(minter, m)` | n/a | re-send B3 (an already-final number response) | refuse |
| minter | MINT `s` | RESERVED: re-send P2; CREDITING: re-send M2, or O1 if the holder is not OPEN | COUNTED: re-send M4; below `W`: re-send M4 or `refused` | refuse |
| minter | OPEN `owner` | OPENING: re-send O1 | OPEN: re-send O1 (idempotent) | refuse |
| minter | BURN `(owner, b)` | AWAITING: re-send B2; REFUNDING/REJECTED: re-send R1 | RECORDED or below `W`: re-send B4 | refuse |
| wallet | BURN `b` | re-send B1 with `cancel_requested` | refuse | refuse |
| wallet | REPORT `s` | n/a | `s` in `credits_above`: re-send M3 | refuse below `credit_floor` (already counted) |
| wallet | OPEN | re-send `open_request` | - | - |

- **Quotes.** Each contract has `get_advance_cost(kind, id)`. It returns a
  minimum at the quoted state and prices for the path that advance would
  take: a first execution, a duplicate, or a final-result re-send. Section 9
  says what it includes.
- **Payment.** Funding is non-refundable (ruling Q5). An advance that is
  underfunded or inapplicable throws, and the caller's bounceable message
  returns minus fees. Value left over after the last leg stays with the
  participant that ends the path.
- **What an advance cannot do.** It cannot create an operation, change one,
  skip a check (the receiving leg runs the ordinary handler), or repeat a
  settlement effect.
- **Cascading.** An advance at the earliest unfinished participant drives
  the remaining path.

## 9. Fees, storage and gas per leg

Every leg prices itself **when it executes**, with `GETGASFEE` and
`GETFORWARDFEE` and declared gas per step. Before any settlement effect it
requires

```
available = min(msg_value, balance_after_storage_phase - RESERVE)
available >= own_step + forwarding + remaining_need(path)
```

For a non-bounceable message the credit phase runs before the storage phase
(`validator/impl/collator.cpp:3561-3569`). The incoming value therefore
first pays storage debt and restores the reserve, and only the remainder
funds the leg. A leg never spends the contract's pre-existing balance on a
protocol step. If funding is short, the leg throws: no settlement effect,
and its value stays at the receiver.

Quotes (`get_advance_cost`) add three things to the path need:

- the current shortfall below `RESERVE`;
- `GETSTORAGEFEE` on the contract's own size over `STORAGE_QUOTE_HORIZON`
  (proposed: one day), a margin for storage accrued since its last
  transaction;
- on paths that deploy or open a wallet, the StateInit forwarding and the
  wallet's reserve.

A quote is a minimum, not an exact cost (ruling Q5).

Proposed declarations, to be replaced by measured maxima on dictionaries
aged to their admission limits: `WALLET_STEP_GAS = 25 000`,
`MINTER_STEP_GAS = 60 000`, `BRIDGE_STEP_GAS = 40 000`. The figures below
use the fixture `tosctl/src/executor/real_boc/default_config.boc`:

- **Gas:** basechain 1 000 tomi per unit with a flat 100 units for 100 000;
  masterchain 10 000 with a flat 100 for 1 000 000.
- **Forwarding:** basechain lump 1 000 000, then 1 000 per bit and 100 000
  per cell; masterchain lump 10 000 000, then 10 000 per bit and 1 000 000
  per cell.
- **Message sizes:** a small message is priced as one 1 023-bit cell. The
  messages carrying a StateInit are estimates until compiled code is
  measured.

Figures in TOS, path need = own cost + need of the next leg:

| Leg | Own cost | Path need |
|---|---|---|
| M4 at bridge | gas 0.400 | 0.400 |
| M3 at minter | 0.060 + M4 fwd 0.021 | 0.481 |
| M2 at wallet | 0.025 + M3 fwd 0.002 | 0.508 |
| M1 at minter | 0.060 + M2 fwd 0.002 | 0.570 |
| P2 `prepared` at bridge | 0.400 + M1 fwd 0.021 | 0.992 |
| P1 at minter, holder exists | 0.060 + P2 fwd 0.021 | 1.073 |
| P1 at minter, new holder (adds O1 with StateInit 0.011, wallet 0.025 + reserve 0.050, O2 0.002, minter 0.060) | + 0.148 | 1.220 |
| G1 at bridge (P1 with minter StateInit, about 0.25) | 0.400 + 0.250 | **about 1.87** (mint fee floor) |
| B3 RECORDED, then B4 | 0.060 + 0.002, wallet 0.025 | 0.087 |
| B3 CANCELLED, then R1, R2 | 0.060 + 0.002, wallet 0.025 + top-up 0.050, R2 0.002, minter 0.060 | 0.199 |
| B2 at bridge | 0.400 + max(LOG_BURN 0.021 + B3 0.021 + 0.087, B3 0.021 + 0.199) | 0.620 |
| B1 at minter | 0.060 + B2 fwd 0.025 | 0.705 |
| B0 at wallet | 0.025 + B1 fwd 0.002 | **about 0.73** (burn fee floor) |
| Re-send from a final record (for example B3 again, M4 again) | that leg's own cost plus the receiver's no-effect leg | quoted per path |

The contracts' balances pay only for their own storage and for optional
records. Storage maintenance is in section 10.

## 10. Account lifecycle

### 10.1 Facts for this chain

All references are to this repository.

1. **Who pays storage.** Storage fees accrue from `last_paid` at the prices
   in ConfigParam 18. **Special accounts pay none.** A special account is a
   masterchain account listed in ConfigParam 31, or the configuration
   contract (`crypto/block/transaction.cpp:937-939`;
   `crypto/block/mc-config.cpp:2068-2071`; `validator/impl/collator.cpp:2792`).
2. **Debt.** The storage phase collects from the balance. When the balance
   is short it zeroes the balance and records the rest as `due_payment`
   (`transaction.cpp:1246-1294`).
3. **Freezing.** An **active** account is frozen when its total due exceeds
   `freeze_due_limit`. An active account is never deleted directly
   (`transaction.cpp:1281-1286`).
4. **Deletion.** A **frozen or uninitialized** account is deleted when its
   total due exceeds `delete_due_limit` and it holds no extra currencies
   (`transaction.cpp:1263-1275`). Deletion therefore takes at least two
   transactions on that account: one that freezes it, and a later one that
   deletes it.
5. **What freezing keeps.** It replaces code and data with the hash of the
   complete StateInit (code, data, libraries) at that moment
   (`transaction.cpp:4205-4236`). If that hash equals the account's original
   address (the state never changed), the account becomes uninitialized
   instead (`:4227-4231`).
6. **Unfreezing restores everything.** A message whose StateInit hashes to
   the stored frozen hash re-activates the account with exactly that code
   and data (`transaction.cpp:2339-2341`). Whoever presents that StateInit
   restores the full protocol history. The data is the account's state
   after its last transaction before freezing, which any archive of the
   chain can reconstruct. The message must also pay the debt.
7. **Order of phases.** For a non-bounceable message, the credit phase runs
   before the storage phase, so the message's value pays debt first. For a
   bounceable message, the storage phase runs first
   (`validator/impl/collator.cpp:3552-3569`). The collator always collects
   (`force_collect = true`), so the do-not-collect branch for frozen
   accounts (`transaction.cpp:1253-1256`) does not apply to collated blocks.
8. **What triggers it.** Freezing and deletion happen only in a transaction
   of that account. An ordinary account runs no transaction unless a message
   arrives, but **anyone** can send one. A bounceable message with a tiny
   value runs the storage phase first and can complete a deletion once the
   debt exceeds the limit.
9. **What deletion loses.** A deleted account becomes non-existent
   (`transaction.cpp:4720`). A message carrying the account's *initial*
   StateInit redeploys it, because the address is that StateInit's hash
   (`check_in_msg_state_hash`, `transaction.cpp:2358`). The result is a
   **fresh account with zeroed protocol history**. All three contracts here
   have public, derivable initial states.
10. **A frozen participant does nothing.** A message to a frozen account
    whose StateInit does not match is not executed (`transaction.cpp:2338-2341`,
    `:2370`).
    A non-bounceable protocol message's value pays the debt. No settlement
    effect occurs, and the sender's record stays advanceable. A
    StateInit-carrying credit or open sent to a frozen wallet carries the
    *initial* StateInit, which does not match the frozen hash, so it cannot
    recreate the wallet.
11. **The limits are configuration.** `freeze_due_limit` and
    `delete_due_limit` are fields of ConfigParams 20 (masterchain) and 21
    (basechain) (`crypto/block/block.tlb:734-746`). The fixture holds
    0.1 TOS and 1 TOS on both. The live values must be read from each
    network.
12. **The sandbox does not enforce the cell limit.** The Rust sandbox
    executor has `max_acc_state_cells` in its configuration type
    (`tosctl/src/block/src/config_params.rs:3396-3419`). No enforcement was
    found under `tosctl/src`, while the native engine enforces it
    (`transaction.cpp:3970-3975`). Limit tests must rely on the native
    replay, with a positive control that the limit fires.

### 10.2 What deletion does to this protocol

- **Wallet.** Without lives, a recreated wallet would accept old credits and
  refunds again. A credit that landed, whose tokens were transferred away
  before deletion, would be paid twice.
- **Minter.** It loses supply accounting, every watermark and its sender
  counters. A recreated minter would reuse `m` against the bridge.
- **Bridge.** It loses burn outcomes and swap states. A recreated bridge
  could log an `m` again, and EVM unlock would treat that as a new release.

Larger reserves only delay this. They do not establish replay protection.

### 10.3 Options

**(i) Lives (incarnations).** This is the mechanism in sections 3 to 7:

- Every participant sets `born_lt := cur_lt()` in the first transaction
  that runs its code. Unfreezing restores the same `born_lt`, because it is
  in the data. Redeployment after deletion produces a new one.
- Every message carries both lives, and every pinned relationship records
  the peer's life at first contact. Credits are sent only to wallets that
  have confirmed their life (`open`/`opened`).

*Guarantees.* Deletion can never cause a repeated settlement effect:

- Old-life traffic is refused by the new life.
- A recreated wallet is detected unambiguously, because the minter has
  recorded its previous life.
- A first credit cannot be confused with a recreation, because no credit is
  sent before `opened`.
- A recreated minter is refused by wallets and by the bridge, whose
  recorded lives differ.
- A recreated bridge is refused by minters.

*What it does not guarantee.* Unfinished operations of a deleted life
cannot be completed. Whether a credit or refund to the deleted wallet
landed is unknowable on chain once its state is gone. The minter therefore
moves those records to `old_lives` as **frozen liabilities**: recorded,
reported by a getter, never re-sent and never silently dropped. Deleting a
minter or bridge strands its whole token family, safely.

*Cost.* Two 64-bit lives in every message and record, one `open`/`opened`
round trip per new holder (about 0.15 TOS at the fixture), and per-holder
life tracking at the minter.

**(ii) Keep-alive and restore.** Make deletion operationally unreachable,
and restore frozen participants from their frozen state:

- Every participant is monitored, and its reserve is topped up. Anyone can
  fund one with a plain non-bounceable message.
- A frozen participant is restored by sending its exact last state as a
  StateInit (fact 6), reconstructed from an archive node. Two windows bound
  this: a participant is frozen only once its debt exceeds
  `freeze_due_limit`, and it can be deleted only after its debt exceeds
  `delete_due_limit` (facts 3 and 4).

*Guarantees.* Full recovery, including old operations, as long as the
obligation is met. *Without (i)*, a lapse is a safety failure. *Cost.* A
monitoring service over every participant. Wallets are unbounded in number.
Archive access is also required.

**(iii) Special account for the bridge.** List the bridge in ConfigParam 31.
It then pays no storage and is never frozen or deleted (facts 1 and 3). This
is a governance change that touches only the masterchain bridge. Minters and
wallets are basechain accounts and cannot be special. The masterchain cell
limit still applies.

**(iv) Reserve sizing alone.** Choose reserves so that the time to freeze
exceeds a horizon at a price ceiling. This only delays the failure. It is
listed for completeness and is not sufficient.

### 10.4 Recommendation

> **Recommendation:** combine (i), (iii) and (ii) restricted to minters, and
> have the owner state the liveness boundary explicitly.
>
> - (i) makes deletion of any participant **fail safe**. No repeated effect
>   can occur, and unfinished operations of a deleted life become visible
>   frozen liabilities.
> - (iii) removes deletion of the bridge, which holds the burn decisions the
>   EVM side relies on.
> - (ii), applied to minters (one per token, a set small enough to monitor),
>   keeps token families alive and restores a frozen minter from its frozen
>   state.
> - Wallets are protected by (i) and by their reserve. Monitoring every
>   wallet is not assumed.
> - The closing condition already exempts "permanent participant
>   unavailability". The owner should record that a **deleted** participant
>   is such unavailability. No contract can recover settlement history that
>   the chain itself has destroyed. Under this design, that destruction
>   cannot cause a repeated effect.

This choice is the owner's. If (i) is not adopted, sections 3 to 7 keep the
`born_lt` fields as zero, and deletion becomes a safety assumption that must
be stated.

## 11. Compatibility

- **EVM side (ruling on Q1, required by section 6).**
  - `Bridge.sol` adds a dense `uint64 lockNonce` per bridge, emitted in
    `Lock`. Nonces run from 0 to `2^64 - 2`, and `lock` refuses at the
    sentinel.
  - The oracle swap vote carries `n`.
  - A swap's identity becomes `(evm_chain_id, evm_bridge, n)`. It replaces
    `cell_hash(ext_chain_hash, internal_index)` (`jetton-bridge.fc:71`),
    and `pay_swap` quotes `n`.
  - The oracle vote format, `test_protocol_model.py` and the oracle
    specification change with it.
  - This is the compactable source nonce that ruling Q1 permits. Option (a),
    permanent records, cannot scale under the masterchain cell limit
    (section 6).
- **`LOG_BURN` and unlock.** The format is unchanged. EVM `unlock`
  identifies a release by
  `(receiver, token, amount, tx.address_hash, tx.tx_hash, tx.lt)`
  (`evm/contracts/TosUtils.sol`, `Bridge.sol:114`). It stays unique because
  `LOG_BURN` is emitted once per `m`, permanently: the record is never
  re-decided, and the bridge's life never restarts silently (section 10).
  Oracles must accept that the logging transaction may come from an
  advanced retransmission. They must also keep observing a retired bridge
  while its family has supply. An operation id in the log would help
  observation, but it does not replace bridge deduplication (ruling Q10).
- **Wallet and minter addresses** change, because their code and initial
  data change, and the minter's initial data include its bridge (Q3). The
  owner-facing `transfer` and `burn` layouts are unchanged. Credits arrive
  on a new opcode. A wallet must be opened before its first `burn`.
- **Bridge storage** changes. `new-bridge.fif` builds the new layout, and
  `a_bridge_deployed_by_its_script_completes_a_mint` keeps holding the
  script and the contract to one layout. The ConfigParam 79 format
  (`build-config79.fif`) does not change. Its reserve and gas fields stop
  affecting settlement.
- **Removed opcodes (ruling Q9).** `mint` (21), `mint_credited` (22),
  `mint_completed` (23), `mint_failed` (24), `retry_mint` (25),
  `burn_recorded` (26) and `retry_refund` (27) are removed. Each is refused
  as `unknown_op` before any settlement effect, and each has a test. The
  statuses `MINT_FAILED` and `BURN_REFUND_FAILED`, the logs `LOG_MINT_FAILED`
  and `LOG_BURN_REFUND_FAILED`, the getters `get_pending_mint` and
  `get_next_mint_id`, and the JS tests and verifier pins that use them are
  retired. New opcodes are numbered from 40 upward, so no message in the old
  layout parses as one in the new layout.
- **Tooling updated with the implementation:** `scripts/verify-token-bridge.py`,
  `crosschain/token-bridge/tvm/tests/*.js`, `NOTICE.md` (items 13-18
  superseded), and `SECURITY.md` (completion, "What remains", incident
  procedure).
- **Deployed instances (ruling Q4).**
  - No deployment is recorded in memo.
  - The only users of `new-bridge.fif` and `build-config79.fif` are the
    build, the verifier and the tests.
  - The README says no ConfigParam slot is populated, and `SECURITY.md`
    forbids activation.
  - Empty current slots do not prove absence. Before the implementation
    merges, each operated network needs an inventory: the history of
    ConfigParams 79 and 81-83 since genesis, a search for accounts whose
    code hash matches any built bridge, minter or wallet, and the balances
    and pending records of any match.
  - This inventory needs network access and is not done here. Any instance
    found is immutable and incompatible. It is retired under the current
    incident procedure, not migrated.

## 12. Failure analysis per message

Columns: lost; duplicated; delayed past completion or cancellation;
reordered; bounced; gas rise before it.

- In every row, a **gas rise** means the leg throws with no settlement
  effect, keeps the value, and the predecessor is advanced at the new price.
- Every row's **bounced** case is: protocol messages are not bounceable,
  and a forged bounce has no effect.

| Msg | Lost | Duplicated | Delayed past completion | Reordered |
|---|---|---|---|---|
| G1 | swap stays PAID; oracles re-vote | swap not PAID: refused, payment untouched | same | independent per `n` |
| P1 | swap PREPARING; advance MINT at the bridge | answered from the record | already-final number response | independent per `s` |
| P2 | bridge PREPARING; advance re-sends P1, minter re-answers | no effect | no effect | n/a (one per `s`) |
| O1/O2 | holder OPENING; advance OPEN | idempotent | idempotent | n/a |
| M1 | minter RESERVED; advance MINT at the bridge | CREDITING: re-send M2; COUNTED: M4 | M4, no effect | independent |
| M2 | minter CREDITING; advance at the minter or the bridge | wallet re-sends M3, no credit | `s < credit_floor`: no credit | `credits_above` holds it |
| M3 | credit landed, uncounted; advance REPORT at the wallet, or MINT | no effect | no effect | independent |
| M4 | `pending_mints[s]` stays; advance at the bridge reaches COUNTED, which re-sends M4 | no effect | no effect | independent |
| B1 | `burns[b]` PENDING; advance BURN at the wallet | answered from the record | already-final number response | independent |
| B2 | minter AWAITING; advance at the minter or the wallet | B3 again, **no second log** | same; a cancelled `m` never logs | independent |
| B3 | minter AWAITING; advance at the minter (re-send B2) or BURN_RESULT at the bridge | no effect | no effect | independent |
| B4 | wallet PENDING; advance at the wallet, and the minter re-sends B4 | no effect | no effect | independent |
| R1 | minter REFUNDING; advance BURN at the minter | wallet: `burns[b]` absent, re-sends R2, no credit | same | n/a |
| R2 | minter REFUNDING; advance re-sends R1, wallet re-reports | no effect | no effect | n/a |
| X0 | owner resends | flag already set | after RECORDED: RECORDED; after refund: refused | first B2 to execute decides |
| A* | caller resends | each runs as its leg | refused or answered from the final record | n/a |
| L | part of a final transaction; oracles read it from the chain | impossible: one RECORDED per `m` | n/a | n/a |

## 13. Liveness boundaries that remain

Safety holds while each participant's life persists, and under section 10
option (i) deletion cannot break it either. "Safety" here means no repeated
credit, count, supply transition or `LOG_BURN`, and never both `LOG_BURN`
and a refund for one burn. Without option (i), deletion is a stated safety
assumption.

Completion needs execution to resume and current-price funding to be
supplied. It is not guaranteed under:

1. **Permanent execution failure**: a code defect, or a step over the gas
   limit. Aged-dictionary measurements and `FOLD_LIMIT` bound the second.
2. **Permanent participant unavailability**: a participant frozen and never
   restored, or deleted. A deleted life's unfinished operations become
   frozen liabilities (section 10.3).
3. **Absent funding.** An unfunded operation stays unfinished and holds its
   watermark. Admission limits bound the growth this causes.
4. **Admission refusals.** A refused `prepare` leaves its swap unconsumed,
   and the ERC-20 stays locked until capacity exists. A local burn rejection
   refunds. Neither leaves a consumed swap or an accepted burn waiting.
5. **Off-chain.** Oracle signing and the EVM release.

## 14. Test matrix

All tests run in `tosctl/src/node-control/contracts/tests/token_bridge_sandbox.rs`
with real action and bounce phases. With `TOKEN_BRIDGE_TRACE_DIR` set, every
transaction is replayed through the native engine by
`scripts/replay-token-bridge-trace.py` (`.github/workflows/contract-sandboxes.yml:220-225`),
with identical exit codes, action results, bounces, outgoing messages,
values, fees, balances and data. The fixture configuration has no
ConfigParam 79 (it holds 8, 12, 18, 20, 21, 24, 25, 31 and 43), so a
recording made without 79 replays without it.

**Properties:**

| Id | Property |
|---|---|
| P1 | Every consumed swap remains recoverable to exactly one wallet credit and an authenticated bridge completion. This design consumes a swap only after a reservation, and it has no mint cancellation after consumption. |
| P2 | Duplicate, delayed and reordered mint requests and results cannot repeat a wallet credit, supply accounting or fee consumption, and lost results remain re-reportable. |
| P3 | Every accepted burn debit remains recoverable to exactly one bridge-recorded release obligation or exactly one wallet refund. |
| P4 | `LOG_BURN` and refund are mutually exclusive, and losing any acknowledgement cannot leave an operation without a funded reconciliation path. |

**Harness additions:**

- queue control: drop a queued message by predicate, duplicate it, hold it
  and deliver it later, forge a bounced copy, and forge any authenticated
  sender;
- environment control: remove or replace ConfigParam 79, set masterchain and
  basechain gas prices independently, and set storage prices and advance
  time;
- lifecycle control: freeze, delete and recreate an account through the
  native rules, and restore it from its frozen state;
- quote helpers: `get_advance_cost`;
- an **independent model** (item 10 below).

**Ledger check**, after every delivered transaction:

- **(I1)** `Σ wallet balances + D + T = total_supply + L`.
  - `D` is the burns debited at wallets and not yet accepted or rejected by
    the minter.
  - `T` is the jetton amounts in wallet-to-wallet `internal_transfer`
    messages in flight: debited at the sender, not yet credited or bounced
    back.
  - `L` is the credits and refunds landed at wallets and not yet counted.
  - Separately,
    `total_supply + in_flight + mint_reserve + burn_reserve <= MAX_SUPPLY`.
- **(I2)** `LOG_BURN` count per `m` is 1 if the bridge recorded `m` as
  RECORDED, else 0.
- **(I3)** Refund credits per burn are **at most 1**, and only for CANCELLED
  or locally rejected burns. The count is exactly 1 once that burn's refund
  path has completed. Right after the cancellation, 0 is valid.
- **(I4)** Never both I2 and I3 for one burn.
- **(I5)** Each swap's payment is consumed at most once. Consumed swaps
  equal the bridge's CONSUMED swaps.
- **(I6)** Wallet credits per `(minter life, s)` are at most 1, and supply
  counts per `s` are at most 1.
- **(I7)** Transaction-level funded execution. In every protocol leg, the
  contract's balance after the transaction is at least its balance before,
  minus the storage fee collected in that transaction. The leg draws on the
  contract's pre-existing balance for nothing but storage. The exception is
  G1, which spends the swap's recorded payment and nothing more. Storage
  maintenance is tested separately (T-L).
- **(I8)** Atomic send. Every durable transition in section 5 that names a
  message has that message among the same transaction's outgoing messages.

**The independent model** records every settlement effect as it happens:
credits per `(life, s)`, refunds per `b`, supply transitions, `LOG_BURN`
emissions per `m`, and payment consumption per `n`. It records them outside
the contracts' dictionaries, from the transaction outputs and balance
deltas. Compaction inside a contract cannot erase the model's evidence of a
duplicate, and I1-I6 are checked against the model.

| Id | Scenario | Controls | Asserts, beyond the ledger | Property |
|---|---|---|---|---|
| T-M1 | mint, one pass, new holder | none | open handshake; one credit; supply = amount; all records final and folded | P1, P2 |
| T-M2 | lose each of P1, P2, O1, O2, M1, M2, M3, M4 in turn | drop it; advance at the bridge, and at every other contract that has an advance for it | final state equals T-M1; quote is a minimum: the quote succeeds, and one unit less is refused with no effect | P1, P2 |
| T-M3 | gas rise before each mint leg | raise the receiving chain's price; deliver (throws, no effect); advance at the risen price | as T-M1 | P1, P2 |
| T-M4 | duplicate and old messages | each mint message twice in flight; re-deliver held copies after completion | no second credit, count or payment consumption | P2 |
| T-M5 | reorder | two mints to one holder, delivered out of order on C1 and C2 | `credits_above` and the watermarks behave | P2 |
| T-M6 | identity reuse | forged P1, M1 and M2 from the authenticated sender with an existing number and altered descriptor; a duplicate vote for a CONSUMED or PREPARING swap | `operation_mismatch` or refused; nothing applied | P1, P2 |
| T-M7 | ConfigParam 79 absent or changed | remove or change 79 before each leg after G1, including advances, duplicates and final re-sends; all suspension flags set | completes; no exit 666 anywhere | P1 |
| T-M8 | bounces | forged bounces of every mint message; all bounces suppressed through T-M2 and T-M3 | no state change from any bounce; outcomes identical | P1, P2 |
| T-M9 | advance hygiene | stranger advances: unfinished, final, absent, underfunded, while suspended | no field from the caller reaches an output; refusals bounce | P1, P2 |
| T-M10 | refused prepare | supply full; holder limit reached | swap stays PAID and re-votable; `s` REFUSED forever; a forged commit for that `s` is refused | P1 |
| T-B1 | burn, one pass | none | one `LOG_BURN`; `burn_reserve` released; records final | P3, P4 |
| T-B2 | lose each of B1, B2, B3, B4, R1, R2 in turn | drop it; advance at each contract | as T-B1, or one refund; log count unchanged | P3, P4 |
| T-B3 | gas rise before each burn leg | as T-M3 | as T-B1 | P3, P4 |
| T-B4 | ConfigParam 79 absent or changed | as T-M7, after B0; burn suspension set after B0 | completes; new burns refused; advance and cancel accepted | P3, P4 |
| T-B5 | cancellation | B2 lost then cancel; cancel after RECORDED; B1 lost then cancel; both B2 flags queued in both orders; non-owner cancel | one of {log, refund}, never both | P3, P4 |
| T-B6 | duplicate and old messages after completion or cancellation | re-deliver every held burn message | no second log, refund, debit or supply transition | P3, P4 |
| T-B7 | bounces cannot refund | forged bounced B2 and B1; bounces suppressed | no refund; no balance restore | P4 |
| T-B8 | identity reuse | forged B1 and B2 with an existing number and altered descriptor | `operation_mismatch`; no log | P3, P4 |
| **T-X1** | **refund-capacity race** | accept a burn; attempt mints up to `MAX_SUPPLY` (refused while the burn is unresolved); cancel; complete the refund. Repeat with B3 lost and with R1 and R2 reordered | refund always fits; only a RECORDED burn frees capacity | P3, P4 |
| **T-X2** | **admission exhaustion** | supply full; `s`, `m` and `b` each at `2^64 - 2` then exhausted; `n` at the sentinel; holder and swap admission limits | every refusal happens before an irrevocable effect; `m` exhaustion rejects locally and refunds; no consumed swap or accepted burn waits | P1, P3 |
| **T-X3** | **compaction boundaries on every channel** | gaps; finalization out of order; more than `FOLD_LIMIT` contiguous; late originals; altered descriptors below `W` (already-final number response, nothing applied); exceptions dropped only after the piggybacked watermark passes; final-result re-sends | the model sees no duplicate effect | P2, P3, P4 |
| **T-X4** | **deletion and recreation** | for the wallet, the minter and the bridge, each independently: freeze then restore from the frozen state (history intact, operations complete); freeze, delete, recreate, before and after each acknowledgement, with duplicates already queued | no repeated effect; old-life traffic refused; unfinished old-life records listed as liabilities | all (section 10) |
| **T-X5** | **burn and transfer interleaving** | transfer a landed credit before its M3; burn it from the receiving wallet; then reconcile; cancel where permitted | I1 holds with `T`; signed supply behaves | P2, P3 |
| **T-X6** | **fee failure on duplicate paths** | price rise before: M4 re-sent from a COUNTED record, R2 re-reported, B3 re-sent for a recorded burn, already-final number responses | throw with no effect; quote at the new price succeeds | P2, P4 |
| **T-X7** | **true action failures** | outgoing value above the balance; a message over the size limit; an account state at the cell limit (native replay, with a positive control that the limit fires) | the whole leg rolls back; the named predecessor's record remains; an advance recovers | all |
| **T-X8** | **authentication substitutions** | wrong bridge, minter, wallet, holder, channel and life on every message | refused; never finishes another operation | all |
| **T-X9** | **payment replay** | `pay_swap(n)` after CONSUMED; for a PAID or PREPARING `n`; outside `PAY_WINDOW` | refused and bounced; no new payment record; no mint fee consumed | P2 |
| **T-X10** | **independent model** | every test runs with the model | the model, not the contract dictionaries, is the reference for I1-I6 | all |
| T-G | gas and cells | every dictionary aged to its admission limit; every leg and every advance path including folding | measured gas within declarations; cells within the limit (native) | budget soundness |
| T-L | storage maintenance | time advanced at fixture storage prices; reserve shortfall; debt; top-up by a plain message; quote includes deficit and horizon | legs fund storage from the incoming value first; no protocol leg touches the reserve | I7 |
| T-S | deployment and removed opcodes | `new-bridge.fif` deploys a working bridge; every removed opcode 21-27 is refused before any effect | | compatibility |

**Mutation controls.** Each must turn its named test red **for the named
reason**. Each run records the failing assertion and is restored to green.

- The wallet ignores `credit_floor` and `credits_above`: T-M4, a model
  duplicate credit.
- The minter counts M3 for a COUNTED `s`: T-M4, a model duplicate count.
- The bridge ignores `burn_watermark` and `burns_above`: T-B6, a second
  `LOG_BURN`.
- The bridge honours a second B2's flag: T-B5, log and refund.
- A bounce triggers a refund: T-B7.
- Any settlement handler reads ConfigParam 79: T-M7 and T-B4, exit 666.
- The hash comparison is removed: T-M6 and T-B8.
- `burn_reserve` is not counted at mint admission: T-X1, the refund exceeds
  `MAX_SUPPLY`.
- Exceptions are dropped without the piggybacked watermark: T-X3, a wrong
  final answer reaching a pending sender.
- The life check is removed: T-X4, a repeated credit after recreation.
- `advance` takes a field from the body: T-M9.
- **Atomic send:** add `+2` to one protocol send, then make that send fail
  in its action phase. The control is red only if **I8** (atomic send)
  fails in that transaction. End-state assertions are not counted, because
  an advance may still recover the operation. This control tests the
  atomic-send rule, not settlement safety.

Tests that assert removed behaviour are rewritten, each stating the changed
outcome:

- the refund-on-bounce and `retry_*` tests (`token_bridge_sandbox.rs:833`,
  `:882`, `:1035`, `:1057`, `:1091`);
- `:1484`, which asserts that a mint stays in flight forever.

## 15. Rulings applied and decisions still open

| Ruling | Applied as |
|---|---|
| Q1: option (c) refused | Section 11. A dense EVM lock nonce. Permanent records were permitted but cannot scale under the masterchain cell limit (section 6). **Owner confirmation needed** for the `Bridge.sol` and oracle vote change. |
| Q2: keep cancellation | Section 7.4, with refund capacity reserved (section 6). |
| Q3: accept the pinned bridge | Section 4: old-family admission and routing after replacement. |
| Q4: inventory | Section 11: history and code-hash inventory, a prerequisite before merge. |
| Q5: retain excess | Section 8: funding is non-refundable, and a quote is a minimum. |
| Q6: deletion | Section 10: facts, options and a recommendation. **Owner decision.** |
| Q7: constants are provisional | Section 4 and T-G/T-L. Values are set by measurement. |
| Q8: already-final number response | Section 3.3. |
| Q9: removed opcodes | Section 11 and T-S. |
| Q10: `LOG_BURN` unchanged | Section 11. Holds because emission is once per `m` permanently, and the bridge's life never restarts silently (section 10). |

Open decisions:

- **D1** (Q6): choose the lifecycle option of section 10.4.
- **D2** (Q1): approve the EVM lock nonce and the oracle vote change.
- **D3:** confirm that requiring `open_request` before the first burn, for
  wallets that only ever received transfers, is acceptable (section 7.2).
- **D4:** confirm the admission limits once measured against the live cell
  limits of each network. A masterchain limit of 2 048 cells would bound the
  bridge to a few hundred concurrently unresolved operations.

## 16. Changes from version 1

| Review item | Change |
|---|---|
| A: refund capacity | `burn_reserve` is counted at mint admission, released by RECORDED and moved to `in_flight` by CANCELLED. The refund uses the burn's own `b`, so it needs no new number (sections 5.2, 6). |
| B: admission | A `prepare`/`prepared` reservation precedes consumption, and the minter's durable REFUSED keeps the swap re-votable. Numbers and storage are taken at admission, and `m` exhaustion rejects locally. No consumed swap or accepted burn waits for a future burn or number (sections 6, 7.1). |
| C: account deletion | Section 10: facts from this chain's source, four options, and a marked recommendation. Lives (`born_lt`) are integrated in the design. |
| D: identity | Channel namespace with lives; canonical descriptors with references; full addresses; authentication before any response; hashes recomputed from descriptors; numbers `0 .. 2^64 - 2` with a sentinel checked before assignment (section 3). |
| E: funding and invariants | Quotes for every path, including storage deficit, horizon and deployment; available value net of storage; rollback to an advanceable predecessor; a static and dynamic ConfigParam 79 audit; settlement effects separated from native fees; I1 with transfers, I3 "at most one", I7 at transaction level, I8 atomic send (sections 2, 4, 9, 14). |
| New since version 1 | Per-account cell limits (`max_mc_acc_state_cells` defaults to 2 048) make permanent per-operation records on the bridge unscalable. Exceptions are now compacted by piggybacked sender watermarks, and swaps by an EVM nonce. Wallet credits are deduplicated with a minter-supplied floor instead of a per-holder counter. |
