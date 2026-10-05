# Token bridge settlement protocol (design, for review)

Status: **design only, version 3.** Nothing in this document is implemented.
It specifies changes to `jetton-bridge.fc`, `jetton-minter.fc`,
`jetton-wallet.fc`, `settlement.fc`, the deployment scripts, the EVM
`Bridge.sol` lock path and the oracle vote format. Together they make every
mint and burn a durable, authenticated, idempotent operation at every
participant, recoverable by permissionless funded retransmission.

Base: `fix/security-findings` at `6f86b5cf1`. Line references are to that
commit. Section 17 lists the changes from versions 1 (`63afca486`) and 2
(`2390e3028`).

**Owner rulings recorded here (2026-10-05):**

- **Lifecycle, option (Y).** Lives (incarnations), ConfigParam 31 for the
  bridge, and monitoring and restore for minters. Liabilities left without a
  resolution because the chain deleted a participant's history are accepted
  as an explicit, owner-approved scope change (section 10). Lives must still
  guarantee that no settlement effect repeats after any deletion, including
  when both endpoints are recreated.
- **EVM lock counter and oracle vote format change: approved**, subject to
  the namespace, gap and exhaustion rules of section 11.

## 1. Why the current protocol cannot close

The current protocol (`settlement.fc`, `SECURITY.md` "Completion of mints and
burns") reports each outcome once and treats a bounce as a failure:

- A failed credit bounces to the minter. The minter's bounce handler reads
  ConfigParam 79 (`jetton-minter.fc:141`). With the parameter missing the
  handler throws, and a bounce cannot bounce, so the mint stays
  `MINT_IN_FLIGHT` for good. `retry_mint` admits only `MINT_FAILED`
  (`jetton-bridge.fc:355`).
- Reports to the bridge are sent with mode `64 + 2`
  (`jetton-minter.fc:125`). An unfundable report is skipped, and nothing can
  send it again.
- A bounced burn notification is refunded on the bounce alone
  (`jetton-minter.fc:165`). If ConfigParam 79 is missing, the burn stays
  `BURN_AWAITING_BRIDGE`, which `retry_refund` does not admit (`:334`).
- Each operation is budgeted once, at its first leg, at the prices of that
  moment.

These gaps share one cause: a leg's outcome exists only in a message. The
design gives every participant a durable record of every operation and of
the result it produced. Anyone can have that record sent again, and the
receiver deduplicates it.

## 2. Terms, atomicity, and what "exactly once" covers

- **Leg**: one transaction at one participant, caused by one message.
- **Request**: a message that asks the receiver to apply a settlement effect.
- **Result**: a message that reports an effect the sender has already
  applied and recorded.
- **Final**: a record that no later message can change.
- **Lost**: a message that produced no settlement effect at its receiver,
  because its transaction threw, ran out of gas, failed in its action phase,
  or was removed from the queue by a test. Every protocol send uses mode 0,
  or mode 1 with a value fixed in the compute phase, and never `+2`, so a
  protocol message is never silently skipped.
- **Life**: one existence of an account. See section 10.4.

**Settlement effects versus native fees.** A settlement effect is a change
to jetton balances or holds, supply or reservations, protocol records, swap
consumption, `LOG_BURN`, `LOG_SWAP_CANCELLED` or a refund. The exactly-once
properties apply to settlement effects only. Native currency behaves
differently:

- gas, forwarding and storage fees are paid every time, including by a
  transaction that refuses;
- a refusing leg keeps the value of a non-bounceable message;
- a refused entry message from an owner or advancer bounces back minus fees.

**Atomicity of one leg.** If the action phase fails, the compute phase's
storage update is not committed (`settlement.fc:46`). A leg therefore
commits its record and all its protocol messages together, or commits
nothing. A rolled-back leg leaves its predecessor's durable record intact,
so that request can be advanced again. Optional logs, which are every log
except `LOG_BURN` and `LOG_SWAP_CANCELLED`, are sent in mode 2.

**No reliance on delivery order.** Every receiver deduplicates by identity,
and no correctness argument uses arrival order. Order decides only which of
two valid outcomes wins a cancellation race (sections 7.4 and 11).

## 3. Identity, windows and acknowledgements

### 3.1 Channels

A **channel** is the tuple
`(kind, sender address, sender life, receiver address, receiver life)`.

- Addresses are full standard addresses: workchain plus hash.
- The bridge is on the masterchain. Minters and wallets are on the basechain,
  which `force_chain` and `WORKCHAIN` enforce.
- Every request carries a number that its sender allocates densely on that
  channel.

| Channel | Requests | Numbered by | Receiver state |
|---|---|---|---|
| S EVM -> bridge | `pay_swap`, swap vote, `cancel_lock` | EVM lock nonce `n` (section 11) | bridge: `swap_watermark`, `swaps_above` |
| C1 bridge -> minter | `prepare(s)`, `commit(s)` | `s`, per minter, at the bridge | minter: `mint_watermark`, `mints` |
| C2 minter -> wallet | `credit(s)` | the same `s` | wallet: `credit_floor`, `credits_above` |
| C3 wallet -> minter | `burn_admit(b)` | `b`, per wallet life, at the wallet | minter: per holder `burn_watermark`, `burns` |
| C4 minter -> bridge | `burn_notice(m)` | `m`, per minter, at the minter | bridge: per channel `burn_watermark`, `burns_above` |
| R minter -> wallet | `refund(b)`, `admit_refused(b)` | the burn's own `b` | wallet: its own `burns[b]` |

**Allocatable numbers** are `0 .. 2^64 - 2`. The value `2^64 - 1` is the
exhausted sentinel. A sender checks exhaustion **before** it allocates, at a
point where refusing still has no settlement effect.

### 3.2 Canonical descriptors

A request carries its **descriptor cell**, never a bare hash. The receiver
parses the descriptor exactly (`end_parse`) and computes `cell_hash` itself.

- Bit widths are fixed.
- Coins are encoded as `VarUInteger 16`.
- Addresses are encoded as `addr_std` without anycast.

```
mint_descriptor#4d494e54
    n:uint64 s:uint64 amount:(VarUInteger 16)
    ^[ bridge:MsgAddressInt evm_bridge:uint160 evm_chain_id:uint32 ]
    ^[ minter:MsgAddressInt recipient_owner:MsgAddressInt ] = MintDescriptor;

burn_descriptor#4255524e
    b:uint64 amount:(VarUInteger 16) destination:uint160 token_address:uint160
    ^[ minter:MsgAddressInt owner:MsgAddressInt wallet_life:uint64 ] = BurnDescriptor;
```

Each cell fits within 1 023 bits:

| Cell | Bits |
|---|---|
| mint root | at most 284 |
| mint reference 1 (`bridge`, `evm_bridge`, `evm_chain_id`) | at most 459 |
| mint reference 2 (`minter`, `recipient_owner`) | at most 534 |
| burn root | at most 540 |
| burn reference | at most 598 |

The descriptor binds four things: the originating contract, the kind (the
tag), the recipient and the amount.

### 3.3 Order of checks in every handler

1. **Authenticate first.** Check the sender address and the sender's life,
   and check that the expected receiver life equals the receiver's own life
   (section 10.4). Nothing is answered before this step passes.
2. **Then look the number up.**
   - **Below the watermark, with an exception entry for it:** re-send that
     entry's recorded result.
   - **Below the watermark, with no entry:** send the channel's **default
     answer** and apply nothing.
     - The default is COUNTED on C1, RECORDED on C4, and RECORDED on C3.
     - On C3, a refused or refunded burn whose exception was compacted
       answers nothing.
     - The default may be wrong for an operation whose exception was
       discarded. That is safe for one reason only: an exception is discarded
       after the authenticated sender reported that it has finished that
       number (section 3.4), so the sender's record ignores the answer.
     - The default is never called that operation's recorded result.
   - **Present:** recompute the hash from the descriptor and compare. On a
     mismatch, refuse with `error::operation_mismatch` and apply nothing. On
     a match, re-send the result or continue the pending work.
   - **New:** check the window (section 3.4) and funding, then apply the
     effect and create the record in the same leg.
3. **Results** carry the number, the outcome (where there are two), both
   lives, and the receiver's acknowledged floor (section 3.4). A result only
   finishes the matching record. A result for an absent or already-final
   record has no effect.

### 3.4 Sliding windows with acknowledged floors

Every channel is a sliding window. Its state lives on both sides:

- **Sender.** It keeps its next number and its *finished floor*
  `F_s`: every number below `F_s` has had its result applied at the sender.
  It also keeps the receiver's *acknowledged compaction floor* `A`.
- **Receiver.** It keeps its applied watermark `W` and the entries at or
  above `W`. It keeps *exception* entries below `W`: results other than the
  channel default, such as REFUSED on C1, CANCELLED on C4, and REFUSED or
  REFUNDED on C3. It also keeps its *compaction floor* `C`: the highest
  `F_s` the sender has reported.

The rules:

1. The receiver discards every entry and exception below `C`.
2. The sender allocates a new number only if `next < A + WINDOW`.
3. Every result, and every sync reply, carries the receiver's current `C`.
   The sender sets `A := max(A, C)`.
4. Every request carries the sender's current `F_s`.

**Storage bound.** The receiver's live entries lie in
`[C, A_at_sender + WINDOW)`. Because `A <= C`, that range is within
`[C, C + WINDOW)`. **The receiver holds at most `WINDOW` entries per
channel, whatever the state of synchronization.**

**Independent synchronization.** `sync(channel)` is a permissionless funded
operation at the sender.

- It sends the sender's `F_s` to the receiver. The receiver compacts and
  replies with its `C`.
- It needs no new business and creates no settlement effect.
- It is accepted while every admission limit is full, and it reads no
  ConfigParam.
- A window that stays full because no new business carries the floor is
  emptied by one funded `sync`.
- A receiver may also start a `sync_request` towards its sender. The
  sender answers with a `sync`.

**Exactly once.** Sender numbers are never reused on a channel, and a
channel includes both lives. An effect is applied only for a number that is
neither below `W` nor present. `W` never decreases. An entry below `C` is
discarded only after the sender reported that it finished that number.
Together these mean no request's effect is applied twice, at any delay.

## 4. Pinned participants and the ConfigParam boundary

**When ConfigParam 79 is read.** Only when new business starts:

- the swap vote and `pay_swap`: oracle address, `state_flags`, mint fee;
- the wallet's `burn`: `state_flags`, burn fee;
- `cancel_lock`: oracle address;
- paths outside settlement: jetton transfers between wallets, wallet-address
  discovery, and get-methods that report configuration.

No result, completion, sync, open, advance or cancellation handler reads it.

| Participant | Authenticates | From (no ConfigParam) |
|---|---|---|
| bridge | its minters | `calculate_minter_address(token_data)`, using the stored codes and `my_address()`; plus the minter life recorded for that channel |
| minter | its bridge | `bridge:MsgAddressInt` in the minter's initial data (pinned in its StateInit); plus the recorded bridge life |
| minter | its wallets | `calculate_user_jetton_wallet_address`; plus the holder's recorded wallet life |
| wallet | its minter | `jetton_master_address` (initial data); plus the recorded minter life |

**Hidden reads of ConfigParam 79.** Today every path in the wallet and the
minter calls `get_jetton_bridge_config()` (`config.fc:237`) before
dispatching:

- the wallet at `jetton-wallet.fc:264`;
- the minter at `jetton-minter.fc:224`;
- the minter's bounce handler at `jetton-minter.fc:141`.

The implementation dispatches every settlement opcode before any call that
can reach that helper. Two checks hold this:

- **Dynamic.** Every settlement path, including duplicates, default answers,
  syncs and advances, runs in tests with ConfigParam 79 absent and with it
  changed (T-M7, T-B4).
- **Static.** `scripts/verify-token-bridge.py` refuses the build if any
  named settlement handler reaches `get_jetton_bridge_config` in the call
  graph. Its mutation control inserts such a call.

**Constants instead of ConfigParam 79.** The following live in
`settlement.fc` as code constants:

- the reserves;
- the declared gas for each step;
- `FOLD_LIMIT`;
- the per-channel `WINDOW` sizes;
- the admission limits;
- `STORAGE_QUOTE_HORIZON`.

Their values are provisional (Q7) and are set by measurement.

**Suspension.**

- `STATE_SWAPS_SUSPENDED` stops swap votes and payments.
- `STATE_BURN_SUSPENDED` stops the wallet's `burn`.
- Advances, results, syncs, opens and owner cancellations are accepted while
  suspended.
- Behaviour change: today `retry_mint` is refused while swaps are suspended
  (`jetton-bridge.fc:347`).

**A replaced bridge (ruling Q3).** A minter's address includes its bridge,
so a bridge replaced through ConfigParam 79 does not inherit any tokens.

- Wallets of the old family keep routing to their pinned minter, and that
  minter routes to its pinned old bridge.
- The old family's `burn` reads the current ConfigParam 79, but only for its
  admission policy: suspension and fee.
- Operators keep the old bridge funded and observed by oracles while the old
  family has supply.
- A burn of either family is authenticated against its own pinned bridge.

## 5. Durable records

The layouts below are TL-B. Dictionaries are grouped into extra reference
cells so that no cell has more than four references.

### 5.1 Bridge (masterchain)

```
storage#_ born_lt:uint64 evm_chain_id:uint32 evm_bridge:uint160   ;; immutable namespace
          collector_address:MsgAddress jetton_minter_code:^Cell jetton_wallet_code:^Cell
          ^[ swap_watermark:uint64 swaps_above:(HashmapE 64 SwapState)
             channels:(HashmapE 256 ^TokenChannel) channels_count:uint32 ] = BridgeStorage;
swap_paid#0 payer:MsgAddressInt fee:Coins = SwapState;
swap_preparing#1 minter:uint256 s:uint64 payer:MsgAddressInt fee:Coins = SwapState;
swap_consumed#2 = SwapState;
swap_cancelled#3 = SwapState;
token_channel#_ token_data:^Cell state:uint1 minter_life:uint64   ;; state 1 = terminal
    next_mint_seq:uint64 finished_mint_floor:uint64 minter_mint_ack:uint64
    pending_mints:(HashmapE 64 PendingMint)
    burn_watermark:uint64 burn_compaction_floor:uint64
    burns_above:(HashmapE 64 BurnOutcome) = TokenChannel;
pending_mint#_ n:uint64 descriptor_hash:uint256 descriptor:^MintDescriptor
    status:uint1 = PendingMint;   ;; 0 PREPARING, 1 COMMITTED
burn_outcome#_ outcome:uint1 descriptor_hash:uint256 = BurnOutcome;   ;; 0 RECORDED, 1 CANCELLED
```

The bridge carries no permanent per-operation record. Its swap entries are
bounded by `SWAP_WINDOW`, the pending mints of each channel by `MINT_WINDOW`
(rule 2 of section 3.4), and the burn outcomes of each channel by
`BURN_WINDOW` (section 3.4). The number of channels is bounded by
`CHANNEL_LIMIT`.

### 5.2 Minter (basechain)

```
storage#_ total_supply:int128 in_flight:Coins mint_reserve:Coins burn_reserve:Coins
          stranded:Coins content:^Cell jetton_wallet_code:^Cell
          ^[ bridge:MsgAddressInt bridge_life:uint64 born_lt:uint64 state:uint1
             mint_watermark:uint64 mint_compaction_floor:uint64
             mints:(HashmapE 64 MintRecord)
             next_notice_seq:uint64 finished_notice_floor:uint64 bridge_burn_ack:uint64
             notices:(HashmapE 64 NoticeRef)
             holders:(HashmapE 256 ^Holder) holders_count:uint32 ] = MinterStorage;
mint_record#_ descriptor_hash:uint256 owner:uint256 amount:Coins status:uint3 = MintRecord;
    ;; 0 AWAITING_OPEN, 1 RESERVED, 2 CREDITING, 3 COUNTED, 4 REFUSED
notice_ref#_ owner:uint256 b:uint64 = NoticeRef;
holder#_ wallet_life:uint64 open:uint2 open_attempt:uint32   ;; 0 NEW, 1 OPENING, 2 OPEN
    outstanding_credits:uint16
    burn_watermark:uint64 burn_compaction_floor:uint64
    burns:(HashmapE 64 BurnRecord)
    old_life:(Maybe ^OldLife) = Holder;
burn_record#_ descriptor_hash:uint256 amount:Coins m:uint64 status:uint3
    cancel_requested:uint1 = BurnRecord;
    ;; 0 AWAITING_BRIDGE, 1 RECORDED, 2 REFUNDING, 3 REFUNDED, 4 ADMIT_REFUSED
old_life#_ wallet_life:uint64 burns:(HashmapE 64 BurnRecord) = OldLife;
```

**Supply accounting.** Capacity in use is
`total_supply + in_flight + mint_reserve + burn_reserve + stranded`. It
never exceeds `MAX_SUPPLY`. `total_supply` is signed: a burn of a landed
credit whose confirmation is still in flight briefly takes it below zero.
`get_jetton_data` reports `max(total_supply, 0)`.

### 5.3 Wallet (basechain)

```
storage#_ balance:Coins owner_address:MsgAddressInt jetton_master_address:MsgAddressInt
          jetton_wallet_code:^Cell
          ^[ born_lt:uint64 minter_life:uint64 open_attempt:uint32
             credit_floor:uint64 credits_above:(HashmapE 64 uint256)
             next_burn_seq:uint64 finished_burn_floor:uint64 minter_burn_ack:uint64
             burns:(HashmapE 64 PendingBurn) ] = WalletStorage;
pending_burn#_ descriptor:^BurnDescriptor status:uint1 cancel_requested:uint1 = PendingBurn;
    ;; status 0 HELD (awaiting admission), 1 ADMITTED
```

The tokens of a burn are **held** in `burns[b]` from the owner's `burn`
onwards: they are removed from `balance` and cannot be transferred.
The burn reaches one of three ends:

- RECORDED: they are destroyed;
- ADMIT_REFUSED: they are released back to `balance`;
- CANCELLED: they are refunded to `balance`.

The wallet deletes `burns[b]` in the same leg as the release, the refund or
the RECORDED outcome. Burn numbers are never reused within a wallet life,
so every return of held tokens is deduplicated by `burns[b]` itself.

## 6. Capacity and accounting

A completion **never** needs a resource that admission did not reserve.
Every resource is reserved by the participant that owns it, before any
irreversible settlement effect:

- the bridge's storage through its own windows and its channel limit;
- the minter's storage through its holder limit and its windows;
- the wallet's storage through its windows.

A participant never counts another account's capacity. A downstream
participant either has the window space that the sender's acknowledged floor
guarantees (section 3.4), or it refuses before any effect.

### 6.1 Reservation and accounting per transition

| Participant | Transition | Reserves on entry | Releases | Supply effect |
|---|---|---|---|---|
| bridge | `pay_swap(n)` -> PAID | swap slot (`n < swap_watermark + SWAP_WINDOW`) | on CONSUMED or CANCELLED fold | - |
| bridge | vote -> PREPARING(s) | mint-window slot of the channel (`s < minter_mint_ack + MINT_WINDOW`); a channel slot if the channel is new (`CHANNEL_LIMIT`) | slot freed when `s` finishes and is acknowledged | - |
| bridge | REFUSED result -> swap PAID again | none; reuses the PREPARING slot | `s` finished (REFUSED) | - |
| bridge | `cancel_lock(n)` -> CANCELLED | swap slot already held, or a new one within `SWAP_WINDOW` | fold | payment refunded to its payer |
| bridge | `burn_notice(m)` -> RECORDED or CANCELLED | burn-window slot; guaranteed by the minter's `m < bridge_burn_ack + BURN_WINDOW` | compacted when the minter's finished floor passes `m` | - |
| minter | `prepare(s)` -> AWAITING_OPEN or RESERVED | `mints` slot (guaranteed by the bridge window); `mint_reserve += a`; holder slot and its burn window if the holder is new (`HOLDER_LIMIT`); `outstanding_credits += 1` (below `CREDIT_WINDOW`) | - | capacity checked: total + a <= MAX |
| minter | `prepare(s)` -> REFUSED | `mints` slot only, guaranteed by the bridge window, **so a refusal is always storable** | compacted when the bridge's finished floor passes `s` | - |
| minter | `commit(s)` -> CREDITING | none | - | `mint_reserve -= a`, `in_flight += a` |
| minter | `credit_recorded(s)` -> COUNTED | none | `outstanding_credits -= 1` | `in_flight -= a`, `total_supply += a` |
| minter | `burn_admit(b)` -> AWAITING_BRIDGE | holder burn-window slot (opened earlier); notice slot `m < bridge_burn_ack + BURN_WINDOW`; `m` not exhausted | - | `total_supply -= a`, `burn_reserve += a` |
| minter | `burn_admit(b)` -> ADMIT_REFUSED | holder burn-window slot only (reserved by opening), **so a refusal is always storable** | compacted when the wallet's finished floor passes `b` | none (no supply moved) |
| minter | `burn_result` RECORDED | none | notice slot (after acknowledgement) | `burn_reserve -= a` |
| minter | `burn_result` CANCELLED -> REFUNDING | none | notice slot | `burn_reserve -= a`, `in_flight += a` (net zero) |
| minter | `refund_recorded(b)` -> REFUNDED | none | holder burn slot (after acknowledgement) | `in_flight -= a`, `total_supply += a` |
| minter | wallet recreated -> `old_life` | none; the old life's records move into the single `old_life` slot reserved with the holder | the slot frees once every old record is finished (section 10.4) | CREDITING to the old life: `in_flight -= a`, `stranded += a`; REFUNDING to the old life: the same |
| wallet | `open(L)` | none (fixed fields) | - | - |
| wallet | `credit(s)` | `credits_above` slot; bounded by the minter's `CREDIT_WINDOW` per holder | dropped below `credit_floor` | `balance += a` |
| wallet | owner `burn` -> HELD | `burns` slot (`b < minter_burn_ack + HOLDER_BURN_WINDOW`) | deleted on its end, then compacted at the minter | `balance -= a` (held) |
| wallet | `admit_refused(b)` | none | `burns[b]` deleted | `balance += a` (released) |
| wallet | `refund(b)` | none | `burns[b]` deleted | `balance += a` |
| wallet | `burn_outcome(b)` RECORDED | none | `burns[b]` deleted | - |

### 6.2 Admission limits and live cell limits

The size of each window and limit is set so that the participant's
worst-case occupancy fits under the account cell limit. That worst case is
every window full, every exception held, and `old_life` occupied. The
occupancy is **measured** (T-G) on compiled code with worst-case dictionary
shapes. Nothing here asserts a figure in advance.

The cell limit is read from ConfigParam 43 at admission. That reading is new
business, and only ConfigParam 79 is excluded from completions.

- **The limit is configuration.** The defaults are 65 536 cells per account,
  and 2 048 per masterchain account from global version 12
  (`crypto/block/mc-config.h:429-430`; `crypto/block/transaction.cpp:3970`).
  ConfigParam 43 can override both.
- **Both engines enforce it.** Native: `transaction.cpp:3970-3975`. Rust:
  `tosctl/src/executor/src/transaction_executor.rs:1907`, called at `:757`.
  Both select the masterchain limit by global version.
- **Special accounts are exempt.** Both engines exempt them from the size
  limit (`transaction.cpp:2594-2596`; `transaction_executor.rs:755`), from
  storage fees (`transaction.cpp:938`) and from forwarding fees
  (`transaction.cpp:3535`).

**If the live limit falls below a reservation.** A ConfigParam 43 change, or
a global-version change, can lower the limit below what admitted operations
still need.

- Admission stops at once: every admission compares worst-case occupancy
  with the current limit.
- A completion that would grow the state past the new limit fails in its
  action phase. That leg rolls back, and its predecessor's record stays
  advanceable.
- **Remaining dependency:** those completions resume only when the limit
  rises back to at least the reserved worst case. Governance must not lower
  ConfigParam 43 below the measured worst case of a live deployment, or must
  accept that the affected operations pause until it is raised.
- A bridge listed in ConfigParam 31 is exempt and unaffected.

## 7. Message flows

### 7.1 Mint

| Id | Message | From -> to | Carries |
|---|---|---|---|
| G1 | swap vote | multisig -> bridge | `n`, `evm_chain_id`, `evm_bridge`, recipient, amount, token data |
| P1 | `prepare` | bridge -> minter (minter StateInit) | `s`, descriptor, bridge life, expected minter life or 0, `F_s` |
| O1 | `open` | minter -> wallet (wallet StateInit) | minter life, expected wallet life or 0, `open_attempt` |
| O2 | `opened` / `open_refused` | wallet -> minter | wallet life, echoed minter life, echoed `open_attempt` |
| P2 | `prepared` / `refused` | minter -> bridge | `s`, minter life, echoed bridge life, minter `C` |
| M1 | `commit` | bridge -> minter | `s`, descriptor, lives, `F_s` |
| M2 | `credit` | minter -> wallet | `s`, descriptor, lives, `mint_watermark` |
| M3 | `credit_recorded` | wallet -> minter | `s`, owner, lives |
| M4 | `mint_completed` | minter -> bridge | `s`, `^token_data`, lives, minter `C` |

1. **G1 at the bridge.** This is new business. The checks:
   - oracle quorum, flags and fee, as today;
   - `evm_chain_id` and `evm_bridge` equal the pinned namespace;
   - the swap is PAID;
   - the channel is not terminal;
   - `s` is available within the channel's window.

   The swap becomes PREPARING(s) and P1 is sent, funded from the swap's
   recorded fee. Nothing irrevocable has happened.
2. **P1 at the minter.** Authenticate and bootstrap the lives (section
   10.4), then look up `s`.
   - **New, no capacity** (supply, holder limit or `CREDIT_WINDOW`): record
     REFUSED and send `refused`.
   - **New, holder already OPEN:** record RESERVED, `mint_reserve += a`, and
     send `prepared`.
   - **New, holder not OPEN:** record AWAITING_OPEN with the reservation
     made. Start or continue the opening (O1). Reply only after O2.
   - **On O2 `opened`:** every AWAITING_OPEN `s` of that holder becomes
     RESERVED and `prepared` is sent.
   - **On O2 `open_refused`:** they become REFUSED, their reservations are
     released, and `refused` is sent. A wallet bound to another minter life
     sends `open_refused`.
3. **P2 at the bridge.**
   - `prepared` makes the swap CONSUMED (irrevocable) and sends M1.
   - `refused` restores the swap to PAID; the swap can be voted again under
     a new `s`.
   - A second P2 for an `s` that is already resolved has no effect.

   A swap is therefore consumed only after the minter reserved supply, holder
   storage and a credit slot, **and** the recipient wallet confirmed its
   life. Every later leg can be advanced and needs no new resource. A
   reservation is never cancelled: `prepared` always leads to commit.
4. **M1, M2, M3 and M4** follow section 6.1. The wallet deduplicates credits
   with `credit_floor := max(credit_floor, mint_watermark)` and
   `credits_above`. Every `s` below the minter's watermark is either COUNTED
   (from this wallet life's M3) or REFUSED (never credited).

### 7.2 Opening a wallet

Opening reserves the holder's storage at the minter, including its full
burn window. It establishes both lives. A wallet must be opened before its
first `burn` (ruling D3).

Opening is:

- permissionless and funded: `advance(OPEN)` at the wallet sends
  `open_request(wallet life)` to the minter;
- retryable;
- independent of ConfigParam 79.

The minter answers with O1 if it has holder capacity. If it does not, it
answers with `open_refused_capacity`; the wallet stays unopened and its
tokens stay usable for transfers.

### 7.3 Burn: admission before the hold becomes a burn

| Id | Message | From -> to | Carries |
|---|---|---|---|
| B0 | `burn` | owner -> wallet | unchanged layout |
| B1 | `burn_admit` | wallet -> minter | burn descriptor, `cancel`, lives, `F_s` |
| B1r | `admit_refused` | minter -> wallet | `b`, lives, `C` |
| B2 | `burn_notice` | minter -> bridge | `m`, descriptor, `cancel`, `^token_data`, lives, `F_s` |
| B3 | `burn_result` | bridge -> minter | `m`, outcome, lives, `C` |
| B4 | `burn_outcome` | minter -> wallet | `b`, lives, `C` |
| R1 | `refund` | minter -> wallet | `b`, amount, lives, `C` |
| R2 | `refund_recorded` | wallet -> minter | `b`, owner, lives |
| X0 | `cancel_burn` | owner -> wallet | `b` |
| L | `LOG_BURN` | bridge -> external | **unchanged format** |

1. **B0 at the wallet.** This is new business.
   - Today's `burn_tokens` checks still apply.
   - The new checks: the wallet is opened, `b` lies within the window, `b`
     is not exhausted, and the fee covers the path at current prices.
   - The wallet moves the amount into a hold (`burns[b]` = HELD) and sends
     B1.
2. **B1 at the minter.** Authenticate first, then look up `b` in the
   holder's burn window.
   - **New, no notice slot or `m` exhausted:** record **ADMIT_REFUSED**.
     This is a durable terminal decision, stored in the holder slot reserved
     at opening. No supply moves, and B1r is sent. A later copy of B1(`b`)
     finds this record, even if capacity has since become available, and
     receives B1r again. **It can never be admitted.** The record is
     discarded only when the wallet's finished floor passes `b`, and by then
     the wallet's `burns[b]` is gone.
   - **New, slot available:** record AWAITING_BRIDGE, move `a` into
     `burn_reserve`, take `m`, and send B2.
   - **Present:** compare the hash.
     - AWAITING_BRIDGE: set `cancel_requested` if B1 has `cancel=1`, then
       re-send B2.
     - RECORDED: re-send B4.
     - REFUNDING: re-send R1.
     - ADMIT_REFUSED: re-send B1r.
     - REFUNDED: nothing.
   - **Below the watermark:** an exception entry is answered with its
     recorded result; otherwise the default answer is B4.
3. **B1r at the wallet.** If `burns[b]` is HELD, release the hold. If
   `burns[b]` is absent, nothing happens.
4. **B2 at the bridge.** Authenticate first.
   - **Below the watermark or present:** re-send B3 with the recorded
     outcome or the default answer. **No `LOG_BURN`** is sent.
   - **New, `cancel=0`:** record RECORDED, send `LOG_BURN` in mode 0
     (paid from B2), and send B3(RECORDED).
   - **New, `cancel=1`:** record CANCELLED and send B3(CANCELLED).

   In every case, one leg commits the decision and its messages together.
5. **B3, B4, R1 and R2** follow section 6.1. R1 to a wallet whose
   `burns[b]` is absent re-sends R2 and credits nothing.

### 7.4 Cancellation (RECORDED versus CANCELLED)

- **Who can cancel.** Only the owner, through `cancel_burn(b)`, while
  `burns[b]` is pending. Cancellation is accepted while burns are suspended
  and reads no ConfigParam.
- **A held burn not yet admitted** is cancelled the same way: B1 carries
  `cancel=1`, and the decision is still made at the bridge.
- **Where it is decided.** The bridge decides once per `m`: the first B2 for
  `m` to execute decides, and the decision is immutable. Every later B2 for
  `m` receives the same outcome. A cancelled `m` never logs.
- **What authorizes returning tokens.**
  - A refund is authorized only by B3(CANCELLED) from the pinned bridge.
  - Releasing a hold is authorized only by the minter's durable
    ADMIT_REFUSED, and no notice can exist for that `b`.
  - A bounce, a missing result, a timeout or the owner's request alone
    returns nothing.

### 7.5 Bounces

All protocol messages are non-bounceable, and no protocol state depends on
a bounce. A bounced message is accepted and ignored. Only an owner's or an
advancer's own message can bounce. The wallet's bounce restore for
`burn_notification` is removed. The bounce restore for transfers between
wallets is unchanged.

## 8. Permissionless funded retransmission (`advance`, `sync`)

Each contract accepts `advance(kind, id)` and `sync(channel)` from any
sender. The message carries only the kind, the identifier and its value.
Every outgoing message is rebuilt from stored records and addressed to a
pinned or derived address. **No input of the caller reaches the
destination, amount, recipient, outcome or life.**

| Contract | Kind | Unfinished | Final, or below the watermark | No record |
|---|---|---|---|---|
| bridge | MINT `(minter, s)` | PREPARING: P1; COMMITTED: M1 | refuse | refuse |
| bridge | BURN_RESULT `(minter, m)` | n/a | B3 (recorded result or default answer) | refuse |
| minter | MINT `s` | AWAITING_OPEN: O1; RESERVED: P2; CREDITING: M2 | COUNTED or REFUSED: M4 or `refused` | refuse |
| minter | OPEN `owner` | OPENING: O1 (same attempt) | OPEN: O1 (idempotent) | refuse |
| minter | BURN `(owner, b)` | AWAITING: B2; REFUNDING: R1 | RECORDED: B4; ADMIT_REFUSED: B1r | refuse |
| wallet | BURN `b` | B1 with `cancel_requested` | refuse | refuse |
| wallet | REPORT `s` | n/a | `s` in `credits_above`: M3 | refuse |
| wallet | OPEN | `open_request` | - | - |
| any | `sync(channel)` | sends `F_s`; the receiver compacts and replies with `C` | | |

**Funding, quotes and excess.**

- `get_advance_cost(kind, id)` and `get_sync_cost(channel)` return a
  minimum, valid at the quoted state and prices.
- Funding is non-refundable. A refused advance bounces back to the caller,
  minus fees.
- Any excess stays with the participant that ends the path (ruling Q5).

## 9. Fees, storage and gas per leg

Every leg prices itself when it executes, using `GETGASFEE`,
`GETFORWARDFEE` and the declared gas for each step. Before any settlement
effect it requires:

```
available = min(msg_value, balance_after_storage_phase - RESERVE)
available >= own_step + forwarding + remaining_need(path)
```

For a non-bounceable message the credit phase runs before the storage phase
(`validator/impl/collator.cpp:3561-3569`). The incoming value therefore pays
any storage debt and restores the reserve first. A leg never spends the
contract's pre-existing balance on a protocol step.

Each quote also includes:

- the current shortfall below `RESERVE`;
- `GETSTORAGEFEE` on the contract's own size over `STORAGE_QUOTE_HORIZON`;
- the StateInit forwarding and the wallet reserve wherever a path deploys or
  opens a wallet.

**Illustrative path costs.** These use the fixture configuration
(`tosctl/src/executor/real_boc/default_config.boc`) and the proposed
declarations: wallet 25 000 gas, minter 60 000 and bridge 40 000. The
StateInit message sizes are estimates. Figures are in TOS.

| Path | Cost |
|---|---|
| Mint from G1, existing open holder | about 1.72 |
| Mint, new holder: adds the open round trip (O1 with StateInit, wallet step and reserve, O2, minter step) | about 0.15 more |
| Burn from B0 | about 0.73 |
| Re-send from a final record | that leg's own cost plus the receiver's no-effect leg |
| `sync` | sender step plus receiver step plus two small forwards; on a masterchain channel, about 0.45 |

All of these are replaced by measured values in T-G.

## 10. Account lifecycle (ruling: option Y)

### 10.1 Facts for this chain

1. **Storage fees.** Fees accrue from `last_paid` at the ConfigParam 18
   prices. Special accounts pay none (`crypto/block/transaction.cpp:938`).
   An account is special when it is a masterchain account listed in
   ConfigParam 31, or the config contract (`crypto/block/mc-config.cpp:2068-2071`;
   `validator/impl/collator.cpp:2792`). Special accounts are also exempt
   from the account size limit (`transaction.cpp:2594-2596`;
   `tosctl/src/executor/src/transaction_executor.rs:755`) and pay no
   forwarding fees (`transaction.cpp:3535`). These exemptions hold only
   while the account stays listed in ConfigParam 31.
2. **Debt.** The storage phase collects what it can. A shortfall zeroes the
   balance and is recorded as debt (`transaction.cpp:1246-1294`).
3. **Freeze before delete.** An active account is frozen when its debt
   exceeds `freeze_due_limit` (`transaction.cpp:1281-1286`). A frozen or
   uninitialized account is deleted when its debt exceeds
   `delete_due_limit` (`:1263-1275`). These are two different transactions,
   but **no intervention window is guaranteed**. A large enough accumulated
   debt, or a price change, can make the account deletable on the very next
   transaction after it freezes.
4. **What freezing keeps.** The account's code and data are replaced by the
   hash of its full StateInit (`transaction.cpp:4205-4236`). If that hash
   equals the account's original address, the account becomes uninit
   instead (`:4227-4231`).
5. **Unfreezing.** A message whose StateInit hashes to the stored hash
   restores that exact code and data (`transaction.cpp:2338-2341`). The
   message must also pay the debt.
6. **Phase order.** For a non-bounceable message, credit runs before
   storage. For a bounceable message, storage runs first
   (`collator.cpp:3552-3569`). The collator always collects
   (`force_collect = true`).
7. **Who can trigger it.** Freeze and delete happen only inside a
   transaction of that account, and anyone can cause one by sending it a
   message.
8. **What deletion leaves.** A deleted account becomes non-existent
   (`transaction.cpp:4720`). Its public initial StateInit can redeploy it
   with no protocol history (`:2358`).
9. **A frozen participant executes nothing.** A message whose StateInit does
   not match the frozen hash is not executed (`transaction.cpp:2338-2341`,
   `:2370`). A non-bounceable message's value goes to pay the debt.
10. **The limits are configuration.** `freeze_due_limit` and
    `delete_due_limit` come from ConfigParams 20 and 21
    (`crypto/block/block.tlb:734-746`). The fixture holds 0.1 TOS and 1 TOS.
    Live values are read from each network.

### 10.2 What option Y guarantees and accepts

**Guaranteed: no settlement effect is ever repeated after any deletion.**
This covers deletion of any participant, or of several, including both ends
of one relationship. Lives (section 10.4) enforce it.

**Operational controls:**

- **The bridge is listed in ConfigParam 31.** It then pays no storage and is
  exempt from the size limit, so it is not frozen or deleted for debt. This
  holds only while it stays listed.
- **Minters are monitored.** Each minter has a reserve target and an alert
  threshold, and is topped up with plain non-bounceable messages. A frozen
  minter is restored from its frozen state (fact 5), reconstructed from an
  archive. This is an operational obligation of the bridge operator.
  Fact 3 says it may not always be possible in time.
- **Wallets** rely on their reserve, which is topped up by every credit.

**Accepted scope change (owner-approved, 2026-10-05).** When the chain
deletes a participant's history, that participant's unfinished obligations
are not completed. They are stranded:

- **A deleted wallet.**
  - Credits still CREDITING to it move to `stranded`.
  - Refunds still REFUNDING to it move to `stranded`.
  - Its held burns that the bridge has not yet decided are still decided.
    RECORDED completes normally, because the tokens were destroyed with the
    old wallet anyway. CANCELLED becomes stranded.
- **A deleted minter.** Its token family becomes terminal: the bridge and
  every wallet refuse its new life. Swaps it had consumed but not completed,
  and burns it had admitted but not decided, are stranded.
- **A deleted bridge** (only possible after it has left ConfigParam 31). The
  minters refuse its new life. Its unfinished operations are stranded, and
  `LOG_BURN` is never emitted twice.

**How stranding is recorded.** Every stranding emits
`LOG_LIABILITY_STRANDED` with the full descriptor, in mode 0, in the leg
that detects the deletion. Its amount stays counted in `stranded`, so supply
capacity remains conservative. Reconciliation is off-chain. This is an
explicit narrowing of the closing condition, not a reading of "permanent
participant unavailability".

### 10.3 Bounded storage under recreation

A holder carries **one** `old_life` slot, reserved with the holder. When a
newer wallet life is detected:

1. The current life's records move into `old_life`.
2. Records that cannot complete without the old wallet are stranded (logged
   and counted).
3. Records still awaiting the bridge keep running.
4. The new life may open only after `old_life` has emptied. Until then the
   new life's open request gets `open_refused_retry`, and the new wallet can
   still receive transfers.
5. `old_life` empties as soon as the bridge decides those burns. That
   decision is advanceable.

The storage per holder is therefore bounded no matter how many times a
wallet is recreated.

### 10.4 Lives: bootstrap and handshake rules

A participant's **life** is `born_lt`. It is set to `cur_lt()` in the first
transaction that runs the participant's code. Unfreezing restores the same
value, because it is part of the data. Recreation after deletion produces a
strictly larger value, because logical time only increases. Each
relationship records the peer's life once.

- **L1. Messages carry lives.** Every message carries the sender's life and
  the receiver life it expects. Only the bootstrap messages `prepare`,
  `open` and `open_request` may carry 0 as the expected life.
- **L2. Non-bootstrap messages must match.** A non-bootstrap message whose
  expected life differs from the receiver's own life is refused with no
  effect.
- **L3. What a bootstrap message may initialize.** A bootstrap message from
  an authenticated address may initialize the receiver's recorded life for
  that peer only if that record is unset. Once set, it never changes except
  through L5.
  - The minter learns the bridge life from the first P1 from its pinned
    bridge.
  - The wallet learns the minter life from the first O1 from its master.
  - The minter learns the wallet life from O2, or from `open_request`.
  - The bridge learns the minter life from P2.
- **L4. Replies are bound to the attempt.**
  - O2 must echo the minter's life and its current `open_attempt`. It is
    accepted only while the holder is OPENING with that attempt.
  - P2 must echo the bridge's life, and it is bound to its `s`.
  - Any other reply is ignored.
  - `open_attempt` increases only when a new opening starts. A resend
    reuses the same attempt.
- **L5. A peer's life changes.**
  - **An older life than recorded** means old-life traffic. It is ignored:
    no effect and no answer.
  - **A newer life of a wallet** means the wallet was recreated. Apply
    section 10.3 and start a new opening attempt with that life expected.
  - **A newer life of a minter or a bridge** means a hub was recreated. The
    relationship becomes **terminal** and is refused forever.
    - A wallet whose minter is recreated refuses it.
    - A bridge whose minter is recreated marks that channel terminal.
    - A minter whose bridge is recreated refuses that bridge.
- **L6. No retargeting.** An operation binds to a peer life when it is
  created, if that life is already known. Otherwise it binds at the first
  accepted reply of its bootstrap exchange. Only `prepare` and `open` create
  operations before the peer life is known, and neither applies an external
  settlement effect before binding: a reservation is not one. An operation
  is never rebound. A message for a bound operation always carries the bound
  life, so a newer life refuses it under L2.

**Why no effect repeats.** An effect-bearing message is a commit, credit,
admission, notice, result, refund or release. Each one carries the bound
life of its operation and is applied only by that life (L2). A recreated
participant has a newer life. It therefore never applies an older life's
effect, and its peers refuse to bind its new life to old operations (L5 and
L6).

**Each recreation case:**

| Case | Outcome |
|---|---|
| Wallet recreated, minter alive | Old credits are refused by the new wallet (L2). The minter detects the newer life (L5) and strands the old life's credits and refunds. The new life must open again. |
| Minter recreated, bridge alive | The bridge refuses the newer life (terminal channel). Wallets refuse its O1, so its holders stay unopened and its burn admissions are impossible. |
| Bridge recreated, minter alive | Minters refuse the newer bridge life, so `LOG_BURN` cannot repeat. |
| Wallet and minter both recreated | The new minter has no bridge life, because the bridge refuses it, so it admits nothing and prepares nothing. The new wallet may record the new minter's life through O1, but no effect-bearing message can reach it: the new minter has no open bridge channel. |
| Bridge and minter both recreated | The new bridge and new minter may bootstrap a fresh channel. Old wallets refuse the new minter (they hold the older minter life, L5), so the new family can serve only wallets that are new as well. The new wallets sit at the same addresses as the old ones, but the old wallets are alive and refuse the new minter. No old operation is re-applied, because none carries the new lives. |
| All three recreated | A fresh family at the same addresses, with none of the old history. Every old operation is bound to old lives, so no old effect can apply. |

**Old opens and replies after recreation.**

- An O1 left over from before a wallet's recreation carries either the old
  expected life, which the new wallet refuses under L2, or 0. A 0 lets the
  new wallet record the minter life, and it answers with an O2 carrying the
  attempt.
- If that attempt is no longer current, the minter ignores the O2 (L4).
  If it is current, the opening binds to the new life. That is correct,
  because no operation has ever been bound to that holder's OPENING state.
- An O2 left over from an older wallet life is ignored (L5).

## 11. EVM side and namespace

**One immutable namespace.** The TOS bridge serves exactly one
`(evm_chain_id, evm_bridge)`.

- Both values are pinned in the bridge's initial data.
- Every vote, payment and cancellation must name them.
- `MY_CHAIN_ID` (params) must equal the pinned chain id.
- ConfigParam 79's external chain address field must match the pinned bridge
  for new business to proceed.
- A different EVM bridge needs a different TOS bridge.
- The swap watermark therefore represents the full tuple identity.

**Lock nonce.** `Bridge.sol` keeps a dense `uint64 lockNonce`.

- `lock` refuses at `2^64 - 1` (exhaustion is checked before allocation).
- `Lock` emits `n`.
- `lock` stores `locks[n] = (locker, token, amount, status)`, so a refund
  is possible.
- The swap identity is `(evm_chain_id, evm_bridge, n)`, replacing
  `cell_hash(ext_chain_hash, internal_index)` (`jetton-bridge.fc:71`).
- The oracle vote carries `n` and the namespace.

**Gap policy: source-authenticated terminal cancellation.** A lock that is
never paid or voted would otherwise block `swap_watermark`, and with it the
payment window.

- `cancel_lock(n)` is an oracle-quorum vote: the authenticated source of
  lock events.
- The TOS bridge decides it atomically, once per `n`:
  - If `n` is unseen or PAID, it becomes **CANCELLED**, which is terminal.
    Any recorded payment is returned to its payer. `LOG_SWAP_CANCELLED(n)`
    is emitted in mode 0 in the same leg.
  - If `n` is PREPARING or CONSUMED, the cancellation is refused with no
    effect.
- A CANCELLED `n` can never be paid, voted or consumed. A CONSUMED `n` can
  never be cancelled.
- The watermark folds over CONSUMED and CANCELLED, so gaps always make
  progress.

**EVM refund.** `Bridge.refundLock(n, signatures)` pays `locks[n]` back to
its locker.

- It requires an oracle quorum over a digest of `"refund"`, `n`, the
  namespace and the lock fields.
- Oracles sign it only on observing `LOG_SWAP_CANCELLED(n)` on TOS.
- `finishedVotings` and `locks[n].status` make it once-only.
- It is mutually exclusive with consumption, because TOS decided
  CANCELLED, which is terminal.

This uses a TOS-side terminal decision, not an inference of non-receipt or
a timeout. The oracles choose *when* to cancel. Correctness does not depend
on that choice.

**Payment window.**

- `pay_swap(n)` is accepted only for an unseen `n` within
  `[swap_watermark, swap_watermark + SWAP_WINDOW)`.
- A payment after CONSUMED or CANCELLED, a second payment for a PAID or
  PREPARING `n`, or one outside the window is refused and bounced. No record
  is created.

**Exhaustion.** `s`, `m` and `b` are checked by their senders before
allocation (section 3.1). `n` is checked by `lock`.

## 12. Compatibility

- **`LOG_BURN`.** Its format is unchanged. EVM `unlock` identifies a release
  by
  `(receiver, token, amount, tx.address_hash, tx.tx_hash, tx.lt)`
  (`evm/contracts/TosUtils.sol`, `Bridge.sol:114`). That stays unique
  because:
  - `LOG_BURN` is emitted once per `m`;
  - the decision is immutable;
  - a recreated bridge is refused by every minter (section 10.4).

  Oracles must accept a logging transaction that came from an advance, and
  must keep observing retired bridges.
- **New log** `LOG_SWAP_CANCELLED` (section 11). **New optional log**
  `LOG_LIABILITY_STRANDED` (section 10.2), which is required in mode 0 when
  stranding.
- **Addresses.** Wallet and minter addresses change, because their code and
  initial data change, and the minter's initial data include its bridge.
- **Interfaces kept.** The owner-facing `transfer` and `burn` layouts are
  unchanged.
- **Opening.** Wallets must be opened before their first burn.
- **Bridge storage** changes: `new-bridge.fif` builds it, including the
  pinned namespace. The ConfigParam 79 format is unchanged.
- **Removed opcodes** 21 to 27. Each is refused as `unknown_op` before any
  effect, and each has a test.
- **Retired with them:** the old statuses, the old logs, the getters
  `get_pending_mint` and `get_next_mint_id`, and the JS tests and verifier
  pins that use them.
- **New opcodes** are numbered from 40 upward.
- **EVM side.**
  - `lockNonce`, `locks[n]` and `refundLock` are added.
  - The `Lock` event and the vote format change.
  - The changes reach `test_protocol_model.py`, the Hardhat tests, and the
    Tron build and tests.
- **Deployed instances (Q4).**
  - None are recorded in memo or in the deployment tooling.
  - Before merge, each operated network needs an inventory: the history of
    ConfigParams 79 and 81 to 83 since genesis, plus a code-hash search for
    every built bridge, minter and wallet.
  - That inventory needs network access and has not been done.
  - Any instance found would be retired under the incident procedure, not
    migrated.

## 13. Failure analysis per message

Two cases are the same for every message, so they are not repeated in the
table:

- **A gas rise:** the leg throws with no effect and keeps the value, and the
  predecessor is advanced at the new price.
- **A bounce:** no protocol message is sent bounceable, and a forged bounce
  has no effect.

| Msg | Lost | Duplicated | Delayed past completion | Reordered |
|---|---|---|---|---|
| G1 | the swap stays PAID; oracles vote again | refused, payment untouched | same | independent per `n` |
| `cancel_lock` | resend the vote | answered from the decision | same | first decision wins over a vote |
| P1 | PREPARING; advance at the bridge | answered from the record | answered from the record or default | independent |
| O1/O2 | OPENING; advance OPEN | idempotent within an attempt | stale attempt or older life: ignored | n/a |
| P2 | PREPARING; advance re-sends P1 | no effect | no effect | n/a |
| M1 | RESERVED; advance | CREDITING: M2 again; COUNTED: M4 again | M4, no effect | independent |
| M2 | CREDITING; advance | the wallet re-sends M3, no credit | `s < credit_floor`: no credit | `credits_above` |
| M3 | credit landed, uncounted; advance REPORT | no effect | no effect | independent |
| M4 | COMMITTED; advance reaches COUNTED | no effect | no effect | independent |
| B1 | HELD; advance at the wallet | answered from the record | answered from the record or default | independent |
| B1r | HELD; advance re-sends B1, B1r again | released once (`burns[b]`) | same | n/a |
| B2 | AWAITING; advance | B3 again, **no second log** | same | independent |
| B3, B4, R1, R2 | advance at either end | no effect, or a re-sent result | no effect | independent |
| `sync` | resend | idempotent (`max`) | an older floor is ignored | n/a |
| L, `LOG_SWAP_CANCELLED` | part of a final transaction | impossible: one decision per `m` or `n` | n/a | n/a |

## 14. Liveness boundaries

Safety holds after any deletion (section 10.4). "Safety" means no repeated
credit, count, supply transition, release, `LOG_BURN` or
`LOG_SWAP_CANCELLED`, and never both `LOG_BURN` and a refund. Completion
requires that execution resumes and that current-price funding is supplied.
The exceptions are:

1. **Permanent execution failure.** This includes a step over the gas limit
   or a reduced cell limit (section 6.2).
2. **A frozen participant that is not restored.**
3. **A deleted participant.** Its unfinished obligations are stranded under
   the owner-approved scope change (section 10.2).
4. **Absent funding.** A full window then refuses new admissions until a
   funded advance or `sync` drains it.
5. **Admission refusals.** A refused prepare leaves its swap unconsumed and
   cancellable through `cancel_lock`. A refused burn admission releases the
   hold.
6. **Off-chain:** oracle signing and EVM execution.

## 15. Test matrix

All tests run in `tosctl/src/node-control/contracts/tests/token_bridge_sandbox.rs`
with real action and bounce phases. Every transaction is replayed through
the native engine by `scripts/replay-token-bridge-trace.py`
(`.github/workflows/contract-sandboxes.yml:220-225`). The fixture
configuration has no ConfigParam 79. It holds ConfigParams 8, 12, 18, 20,
21, 24, 25, 31 and 43.

**Properties:**

| Id | Property |
|---|---|
| P1 | Every consumed swap is recoverable to exactly one wallet credit and an authenticated bridge completion. A swap is consumed only after the minter reserved for it and the wallet was opened. The only exception is the owner-approved stranding when a participant is deleted. |
| P2 | Duplicate, delayed and reordered mint requests and results cannot repeat a credit, a supply count or a fee consumption. Lost results remain re-reportable. |
| P3 | Every admitted burn is recoverable to exactly one bridge-recorded release obligation or exactly one refund. A refused admission releases its hold exactly once. |
| P4 | `LOG_BURN` and refund are mutually exclusive, and losing any acknowledgement cannot leave an operation without a funded reconciliation path. |

**Harness additions.**

- **Queue control:** drop, duplicate, hold and deliver later, forge a bounce,
  and forge any authenticated sender.
- **Configuration changes:** remove or change ConfigParam 79; change gas
  prices per chain; change storage prices and advance time; change
  ConfigParam 43 and the global version.
- **Lifecycle:** freeze, delete and recreate accounts under the native rules,
  and restore them from frozen state.
- **Quote helpers.**
- **An independent model** that records every settlement effect from
  transaction outputs and balance deltas, outside the contract dictionaries.

**Ledger check** (after every delivered transaction, against the model):

- **(I1) Token conservation.**
  `Σ balances + Σ holds + T = total_supply + L + R_pending`.
  - `T` counts amounts in transfers between wallets that are still in
    flight.
  - `L` counts credits and refunds that have landed but are not yet counted.
  - `R_pending` counts the holds still present at wallets whose burn the
    minter has admitted. Supply was reduced when the burn was admitted, but
    the wallet deletes the hold only when the outcome or refund reaches it.

  Separately, the capacity in use stays within `MAX_SUPPLY`.
- **(I2)** `LOG_BURN` is emitted at most once per `m`, and exactly once
  for a RECORDED `m`.
- **(I3)** Refunds and releases per `b` are at most 1. They are exactly 1
  once that path has completed.
- **(I4)** No burn has both I2 and I3.
- **(I5)** Each payment is consumed at most once. CANCELLED and CONSUMED
  never both hold for one `n`.
- **(I6)** Credits per `(life, s)` are at most 1, and counts per `s` are at
  most 1.
- **(I7) Funded execution.** In every protocol leg, the balance after the
  transaction is at least the balance before, minus the storage fee
  collected. G1 and `cancel_lock` spend only the recorded payment.
- **(I8) Atomic send.** Every durable transition that names a message has
  that message in the same transaction.
- **(I9) Storage bound.** No receiver holds more than `WINDOW` entries per
  channel.

**Tests carried over from version 2.** Their content is unchanged from
version 2, and each now runs against the model.

| Id | Covers |
|---|---|
| T-M1 | mint, one pass, new holder |
| T-M2 | lose each message |
| T-M3 | gas rise before each leg |
| T-M4 | duplicates and old messages |
| T-M5 | reorder |
| T-M6 | identity reuse |
| T-M7 | ConfigParam 79 absent or changed |
| T-M8 | bounces |
| T-M9 | advance hygiene |
| T-M10 | refused prepare |
| T-B1 | burn, one pass |
| T-B2 | lose each message, now including B1r |
| T-B3 | gas rise |
| T-B4 | ConfigParam 79 |
| T-B5 | cancellation races, now including cancelling a HELD burn |
| T-B6 | old messages |
| T-B7 | bounces cannot refund |
| T-B8 | identity reuse |
| T-X1 | refund-capacity race |
| T-X2 | admission exhaustion |
| T-X3 | compaction boundaries |
| T-X5 | burn and transfer interleaving |
| T-X6 | fee failure on duplicate paths |
| T-X7 | true action failures |
| T-X8 | authentication substitutions |
| T-X9 | payment replay |
| T-X10 | the independent model |
| T-G | gas and cells |
| T-L | storage maintenance |
| T-S | deployment and removed opcodes |

**Changed in version 3:**

| Id | Scenario | Asserts | Property |
|---|---|---|---|
| T-X4 | Deletion and recreation of each participant. Freeze and restore keep history intact. Delete and recreate before and after every acknowledgement, with duplicates queued. Covers every row of the table in section 10.4, including both endpoints and all three recreated. | No repeated effect in the model. Old-life traffic is refused. Stranded obligations are logged and counted in `stranded`. Hub recreation leaves the relationship terminal. | all |

**New in version 3, the reviewer's required additions:**

| Id | Scenario | Asserts | Property |
|---|---|---|---|
| T-Y1 | **Rejected burn replayed after capacity frees.** Admission is refused because the notice window is full. Then the window drains and every held copy of B1(`b`) is delivered. | Each copy gets B1r again. `b` is never admitted. No supply moves. Exactly one release. | P3 |
| T-Y2 | **Downstream storage full after upstream preparation.** Fill the wallet's credit window and the holder's burn window after prepare. Fill the bridge's burn window with notices pending. | Completions still succeed within the reserved slots, and nothing needs storage it lacks. New admissions are refused before any effect. | P1, P3 |
| T-Y3 | **A REFUSED result while admission storage is full.** Every minter admission limit is full when `prepare` arrives. | REFUSED is stored in its window slot and `refused` is delivered. The swap stays PAID. | P1 |
| T-Y4 | **Watermark sync with no new business.** Finish operations until every window is full, then send no further business. | A funded `sync` alone compacts and reopens every window. It is accepted while admission is full and with ConfigParam 79 absent. | P2, P4 |
| T-Y5 | **An unpaid early EVM nonce blocks the payment window.** Lock `n0` is never paid, and later locks fill `SWAP_WINDOW`. | Later payments are refused. `cancel_lock(n0)` makes it CANCELLED and emits one `LOG_SWAP_CANCELLED`. The watermark folds and later payments are accepted. A cancel against a PREPARING swap is refused. The EVM `refundLock` executes once, and fails after the swap is consumed. Covered in Hardhat and in the sandbox. | P1, P2 |
| T-Y6 | **Old opening messages after recreation.** Stale O1 and O2 for every attempt, delivered after wallet recreation, after minter recreation, and after both. | Older lives are ignored, stale attempts are ignored, hub recreation is terminal, and no credit reaches a new life for an old operation. | all |
| T-Y7 | **A large storage-price jump** that freezes and then deletes in consecutive transactions, for the wallet and for the minter. The bridge is also run with ConfigParam 31 listing and without it. | Deletion is detected through lives, stranding is logged, and there is no repeated effect. A ConfigParam 31 bridge is exempt. | all |
| T-Y8 | **ConfigParam 43 or global-version changes between admission and completion.** Lower the limit below reserved needs, and switch the masterchain limit on at version 12. | Admission stops. A growing completion rolls back and remains advanceable. It completes after the limit is restored. The special bridge is unaffected. Both engines agree. | all |

**Mutation controls.** Each mutation is listed with the test that must fail
and the failure it must show:

- the wallet ignores its floor and set — T-M4, a duplicate credit;
- the minter counts a COUNTED `s` — T-M4;
- the bridge ignores its watermark — T-B6, a second `LOG_BURN`;
- the bridge honours a second B2 flag — T-B5;
- a bounce triggers a refund — T-B7;
- a settlement handler reads ConfigParam 79 — T-M7 and T-B4;
- the hash comparison is removed — T-M6 and T-B8;
- `burn_reserve` is not counted — T-X1;
- an exception is dropped without the sender's floor — T-X3, a wrong answer
  reaching a pending sender;
- `ADMIT_REFUSED` is not stored, so a duplicate is re-evaluated — T-Y1, an
  admission after a release;
- the sender window ignores `A` — T-Y4 and I9;
- the life check is removed — T-X4 and T-Y6;
- a newer hub life is treated as a recreated wallet — T-Y6, retargeting;
- `cancel_lock` accepts a PREPARING `n` — T-Y5;
- `advance` takes a field from the body — T-M9.

**Atomic send.** Add `+2` to one protocol send, then make that send fail in
its action phase. The control counts as red only when **I8** fails in that
transaction. End-state assertions do not count, because an advance may
still recover the operation.

## 16. Rulings applied and decisions still open

| Item | Status |
|---|---|
| Q1 / D2: EVM counter | Approved by the owner. Namespace, gaps and exhaustion are handled in section 11. This is the chosen architecture. Sharded record contracts, authenticated external history, and bounded operation generations would also have preserved replay history. |
| Q2: cancellation | Kept (section 7.4). |
| Q3: pinned bridge | Section 4. |
| Q4: inventory | A prerequisite before merge, not done here (section 12). |
| Q5: excess | Section 8. |
| Q6 / D1: lifecycle | Owner chose option Y (section 10). |
| Q7: constants | Provisional, set by measurement (T-G, T-L). |
| Q8: already-final answers | Section 3.3, with the default-answer wording. |
| Q9: removed opcodes | Section 12, T-S. |
| Q10: `LOG_BURN` | Unchanged (section 12). |
| D3: opening before burn | Approved. Opening is permissionless, funded, retryable and independent of ConfigParam 79, and it reserves the holder's burn window (section 7.2). |
| D4: limits | Measured worst cases. Admission stops when limits fall, and completions then depend on the limit being restored (section 6.2). |

**Still open:** the window and limit values, which are measured during
implementation, and the network inventory (Q4).

## 17. Changes from versions 1 and 2

**Version 2:**

- refund capacity;
- a prepare step before consumption;
- lives;
- canonical descriptors;
- quotes and storage costs;
- the invariant fixes;
- ten tests;
- the lifecycle facts.

**Version 3, by review item:**

| Item | Change |
|---|---|
| A: local rejection | A burn is admitted before its hold becomes a burn. ADMIT_REFUSED is a durable terminal record, stored in a holder slot reserved at opening. It is discarded only after the wallet's finished floor passes it (sections 6.1, 7.3). |
| B: distributed capacity | Every participant reserves only its own capacity. Downstream space is guaranteed by sliding windows with acknowledged floors. Section 6.1 tabulates every transition, including refusal, recovery and `old_life`. |
| C: compaction | Permissionless funded `sync` runs independently of new business and while admission is full. "Recorded final result" now applies only to stored entries; anything else is a default answer (sections 3.3, 3.4). |
| D: EVM nonce | A single immutable pinned namespace. Gaps close by source-authenticated terminal `cancel_lock` with an EVM `refundLock`. The counter is described as the chosen architecture (section 11). |
| E: incarnation handshake | Rules L1 to L6, the case table for every combination of recreations, and stale opens (section 10.4). |
| Facts | The Rust executor enforces the size limit. Special accounts are exempt in both engines. The masterchain limit depends on the global version and ConfigParam 43. No unmeasured capacity figure remains. |
| D4 | Behaviour when limits fall (section 6.2). |
| Tests | T-Y1 to T-Y8, I9, and the new mutation controls. |
| Owner rulings | Option Y and the EVM change are recorded. Stranded liabilities are an explicit approved scope change. |
