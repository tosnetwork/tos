# Token bridge settlement protocol (design, for review)

Status: **design only.** Nothing in this document is implemented yet. It
specifies the change to `jetton-bridge.fc`, `jetton-minter.fc`,
`jetton-wallet.fc`, `settlement.fc` and the deployment scripts that makes
every mint and burn a durable, authenticated, idempotent operation at every
participant, recoverable by permissionless funded retransmission. The design
is reviewed before any contract code changes.

Base: `fix/security-findings` at `6f86b5cf1`. Line references below are to
that commit.

## 1. Why the current protocol cannot close

The current protocol (`settlement.fc`, `SECURITY.md` "Completion of mints and
burns") reports each outcome back once and relies on bounces for failure:

- A failed credit bounces to the minter, whose bounce handler reads
  ConfigParam 79 (`jetton-minter.fc:141`). With the parameter missing the
  handler throws, a bounce cannot bounce, and the only record of the outcome
  is gone. The mint stays `MINT_IN_FLIGHT` at the bridge, and `retry_mint`
  admits only `MINT_FAILED` (`jetton-bridge.fc:355`).
- Reports to the bridge are sent with mode `64 + 2` (`jetton-minter.fc:125`).
  An unfundable report is skipped and nothing can send it again.
- A burn notification that bounces is refunded by the minter
  (`jetton-minter.fc:165`). The refund is authorized by the bounce alone. The
  same handler also reads ConfigParam 79 first, so a removed parameter leaves
  the burn `BURN_AWAITING_BRIDGE`, which `retry_refund` does not admit
  (`jetton-minter.fc:334`).
- Every step is budgeted once, at the first leg, at that moment's prices. A
  sustained price rise between legs strands the operation in flight, and
  nothing distinguishes a credit that landed from one that did not.

These gaps share one cause. A leg's outcome is held only in a message. When that message is lost, nothing on chain can reproduce it. The
design below gives each participant a durable record of every operation it
has seen and of the result it produced. Any participant can send that record
again, and the receiver deduplicates it.

## 2. Terms

- **Leg**: one transaction at one participant, caused by one message.
- **Request**: a message that asks the receiver to apply an effect (credit a
  balance, count supply, emit `LOG_BURN`).
- **Result**: a message that reports an effect already applied and recorded.
- **Final**: a record that no later message can change.
- **Lost**: a message that produced no effect at its receiver. The model
  covers all of these: a message never sent (a skipped action), a message
  whose transaction ran out of gas, threw, or failed in its action phase, and
  a message a test removes from the delivery queue.
- **Advance**: the permissionless operation that retransmits a request or a
  result from the stored record (section 7).

TVM gives each leg one atomicity guarantee. If the action phase fails, the
compute phase's storage update is not committed. This is the existing
premise at `settlement.fc:46`. Every leg in this design commits its record
and sends its messages in one transaction, with no `+2` (ignore errors) mode
on any protocol message. A leg therefore either applies completely or has no
effect at all.

The design does **not** rely on in-order delivery between a pair of accounts.
Every receiver deduplicates by identity, and a correctness argument never
uses arrival order. Arrival order decides only which of two valid outcomes a
cancellation race produces (section 6.4).

## 3. Operation identity

Every operation has a **sequence number** on each channel it crosses, plus an
**operation hash** that binds its fields. A channel is an ordered
(sender, receiver) pair, and the sender assigns its numbers densely
(0, 1, 2, ...).

| Channel | Sender assigns | Receiver deduplicates by |
|---|---|---|
| C1 bridge -> minter (mint requests) | `s`, per minter, at the bridge | minter: `mint_watermark` + `mints` |
| C2 minter -> wallet (credits: mint and refund) | `k`, per holder, at the minter | wallet: `credit_watermark` + `credits_above` |
| C3 wallet -> minter (burn requests) | `b`, at the wallet | minter: per holder `burn_watermark` + `burns` |
| C4 minter -> bridge (burn notices) | `m`, at the minter | bridge: per minter `burn_watermark` + `burns_above` + `cancelled` |

Operation hashes are 256-bit cell hashes of a tagged descriptor:

```
mint_op  = cell_hash("mint"(32) bridge:uint256 minter:uint256 swap_key:uint256
                     recipient_owner:uint256 amount:Coins)
burn_op  = cell_hash("burn"(32) minter:uint256 owner:uint256 b:uint64
                     amount:Coins destination:uint160 token_address:uint160)
credit_op = cell_hash("credit"(32) minter:uint256 owner:uint256 k:uint64
                      kind:uint1 ref:uint64 amount:Coins)
```

The originating contract (bridge or wallet) and the operation kind appear in
the tag and the first address. The recipient and the amount are explicit
fields. Every request carries its sequence number and its operation hash.
Every receiver stores the hash with its record, so a request that reuses a
sequence number with different fields is detected and refused with a new
error `error::operation_mismatch`. Results carry only the sequence number
(and, for a burn, the outcome). They carry no hash, because a participant
answering from below its watermark no longer holds one. A result is matched
to the receiver's own record by number and authenticated sender, and it does
nothing except finish that record. A result for a record that is absent or
already final has no effect.

**Below a watermark** (section 5.4) a receiver keeps no per-operation hash.
A request whose number is below the watermark is answered with the recorded
final result and **has no effect**, whatever its fields. Applying nothing is
the refusal there, and no field comparison is possible. Open question Q8
asks for a ruling on this.

**Swaps.** A mint originates from a swap vote. The swap key is
`cell_hash(ext_chain_hash, internal_index)`, unchanged from `jetton-bridge.fc:71`.
The bridge records every consumed swap permanently as
`swap_key -> (minter, s, mint_op)`. A second vote for a consumed swap key is
refused with `error::swap_consumed`, whether its fields are identical or
different. The throw rolls back, so it consumes no payment. This makes
"one swap, one mint operation" a contract property instead of an oracle
assumption. Its masterchain storage cost is open question Q1.

## 4. Pinned participants and metadata

ConfigParam 79 is read **only when new business starts**: a swap vote, a
`pay_swap`, the wallet's `burn` entry, and the non-settlement paths (jetton
transfers between wallets, wallet-address discovery, get-methods). No
completion, status, result, cancellation or advance handler reads it. Every
address such a handler needs is in its own storage or derivable from it.

| Participant | Needs to authenticate | Source after this change |
|---|---|---|
| bridge | its minters | `calculate_minter_address(token_data)` from the bridge's own stored minter/wallet code and `my_address()` (already true, `jetton-bridge.fc:78`) |
| minter | its bridge | **new** `bridge:uint256` field in the minter's initial data (masterchain), written by the bridge into the StateInit |
| minter | its wallets | `calculate_user_jetton_wallet_address` from stored wallet code (already true) |
| wallet | its minter | `jetton_master_address` in wallet data (already true) |

Protocol metadata that is currently read from the ConfigParam on completion
paths moves as follows:

- **Bridge address** (minter): pinned in the minter's StateInit. Because the
  minter's address is the hash of its StateInit, each bridge has its own
  minters and wallets. Section 10 and Q3 cover the consequence.
- **Wallet and minter storage reserves**
  (`wallet_min_tos_for_storage`, `minter_min_tos_for_storage`): become code
  constants in `settlement.fc`. Completion budgets must not depend on a
  parameter that can change mid-flight (Q7).
- **Gas and forwarding prices**: already read at execution time with
  `GETGASFEE` and `GETFORWARDFEE` (`settlement.fc:58`). These are network
  prices, not ConfigParam 79, and they are the reason every leg re-prices
  itself (section 8).
- **Suspension flags**: checked only at entry. `STATE_SWAPS_SUSPENDED` stops
  votes, and `STATE_BURN_SUSPENDED` stops the wallet's `burn`. Advance,
  results and owner cancellation are accepted while suspended. **This is a
  behaviour change:** `retry_mint` is refused while swaps are suspended today
  (`jetton-bridge.fc:347`).

## 5. Durable records

Each participant's storage is given in TL-B form. The 4-reference limit of a
cell is met by grouping dictionaries into a second cell where noted. The
exact packing is an implementation detail.

### 5.1 Bridge (masterchain)

```
storage#_ collector_address:MsgAddress jetton_minter_code:^Cell jetton_wallet_code:^Cell
          ^[ paid_swaps:(HashmapE 256 Unit)
             consumed_swaps:(HashmapE 256 ConsumedSwap)
             channels:(HashmapE 256 ^TokenChannel) ] = BridgeStorage;
consumed_swap#_ minter:uint256 s:uint64 mint_op:uint256 = ConsumedSwap;
token_channel#_ token_data:^Cell next_mint_seq:uint64
                pending_mints:(HashmapE 64 PendingMint)
                burn_watermark:uint64
                burns_above:(HashmapE 64 BurnOutcome)
                cancelled:(HashmapE 64 uint256) = TokenChannel;
pending_mint#_ swap_key:uint256 recipient_owner:uint256 amount:Coins mint_op:uint256 = PendingMint;
burn_outcome#_ outcome:uint1 burn_op:uint256 = BurnOutcome;   ;; 0 RECORDED, 1 CANCELLED
```

| Record | States | Transition | Caused by |
|---|---|---|---|
| `paid_swaps[key]` | absent -> paid | `pay_swap` with the exact mint fee (unchanged) | user |
| `paid_swaps[key]` | paid -> absent | consumed by a swap vote | oracle multisig |
| `consumed_swaps[key]` | absent -> present (permanent) | same transaction as the consumption above | oracle multisig |
| `pending_mints[s]` | absent -> PENDING | same transaction; `next_mint_seq += 1` | oracle multisig |
| `pending_mints[s]` | PENDING -> absent (final) | `mint_completed(s)` from the derived minter | minter result |
| burn `m` | unseen -> RECORDED | `burn_notice(m, ..., cancel=0)` from the derived minter, **same transaction** as `LOG_BURN` | minter request |
| burn `m` | unseen -> CANCELLED | `burn_notice(m, ..., cancel=1)` | minter request |
| burn `m` | RECORDED/CANCELLED | never changes; duplicates only re-send `burn_result` | - |
| `burn_watermark` | `W -> W+n` | folding contiguous final entries out of `burns_above` (section 5.4) | any of the above |

A RECORDED or CANCELLED burn is final the moment it is written, so `m` is
entered into `burns_above` and folded immediately when `m == burn_watermark`.
A CANCELLED entry is also written to `cancelled[m]`, which is never compacted
(section 5.4).

### 5.2 Minter (basechain)

```
storage#_ total_supply:Coins in_flight:Coins content:^Cell jetton_wallet_code:^Cell
          ^[ bridge:uint256
             mint_watermark:uint64 mints:(HashmapE 64 MintRecord)
             next_notice_seq:uint64 notices:(HashmapE 64 NoticeRef)
             holders:(HashmapE 256 ^Holder) ] = MinterStorage;
mint_record#_ mint_op:uint256 owner:uint256 amount:Coins k:uint64 status:uint1 = MintRecord;
                                                    ;; 0 CREDITING, 1 COUNTED
notice_ref#_ owner:uint256 b:uint64 = NoticeRef;
holder#_ next_credit_seq:uint64 credits:(HashmapE 64 PendingCredit)
         burn_watermark:uint64 burns:(HashmapE 64 BurnRecord)
         cancelled:(HashmapE 64 Unit) = Holder;
pending_credit#_ kind:uint1 ref:uint64 amount:Coins credit_op:uint256 = PendingCredit;
                                                    ;; kind 0 MINT (ref = s), 1 REFUND (ref = b)
burn_record#_ burn_op:uint256 amount:Coins destination:uint160 m:uint64
              status:uint2 cancel_requested:uint1 = BurnRecord;
              ;; 0 AWAITING_BRIDGE, 1 RECORDED, 2 REFUNDING, 3 REFUNDED
```

| Record | States | Transition | Caused by |
|---|---|---|---|
| `mints[s]` | unseen -> CREDITING | first `mint_request(s)` from the pinned bridge; `in_flight += a`; `credits[k]` created; credit sent | bridge request |
| `mints[s]` | CREDITING -> COUNTED (final) | first `credit_recorded(k)` from the holder's wallet; `in_flight -= a`, `total_supply += a`; `mint_completed(s)` sent | wallet result |
| `holder.credits[k]` | absent -> pending -> absent | created with the credit; deleted when its `credit_recorded(k)` is counted | - |
| `holder.burns[b]` | unseen -> AWAITING_BRIDGE | first `burn_request(b)` from the wallet; `total_supply -= a`; `notices[m]` created; `burn_notice(m)` sent | wallet request |
| `holder.burns[b]` | AWAITING_BRIDGE: `cancel_requested 0 -> 1` | `burn_request(b, cancel=1)`; `burn_notice(m, cancel=1)` sent | wallet request |
| `holder.burns[b]` | AWAITING_BRIDGE -> RECORDED (final) | `burn_result(m, RECORDED)` from the pinned bridge; `burn_outcome(b)` sent to the wallet | bridge result |
| `holder.burns[b]` | AWAITING_BRIDGE -> REFUNDING | `burn_result(m, CANCELLED)`; `cancelled[b]` set; `in_flight += a`; refund credit `k` sent | bridge result |
| `holder.burns[b]` | REFUNDING -> REFUNDED (final) | `credit_recorded(k)` for the refund credit; `in_flight -= a`, `total_supply += a` | wallet result |
| watermarks | fold | `mint_watermark` over COUNTED, `holder.burn_watermark` over RECORDED/REFUNDED | - |

`notices[m]` maps a bridge-channel number back to its holder record. It is
deleted when the result for `m` is applied.

### 5.3 Wallet (basechain)

```
storage#_ balance:Coins owner_address:MsgAddressInt jetton_master_address:MsgAddressInt
          jetton_wallet_code:^Cell
          credit_watermark:uint64 credits_above:(HashmapE 64 uint256)
          next_burn_seq:uint64 burns:(HashmapE 64 PendingBurn) = WalletStorage;
pending_burn#_ amount:Coins destination:uint160 cancel_requested:uint1 = PendingBurn;
```

| Record | States | Transition | Caused by |
|---|---|---|---|
| balance and `burns[b]` | -> debited, PENDING | owner `burn`: `balance -= a`; `burns[b]` created; `next_burn_seq += 1`; `burn_request(b)` sent | owner |
| `burns[b]` | `cancel_requested 0 -> 1` | owner `cancel_burn(b)`; `burn_request(b, cancel=1)` sent | owner |
| `burns[b]` | PENDING -> absent | `burn_outcome(b)` from the minter (RECORDED) | minter result |
| `burns[b]` | PENDING -> absent | a REFUND credit with `ref = b`, in the same transaction as its balance credit | minter request |
| credit `k` | unseen -> credited (final) | first `credit(k)` from the minter: `balance += a`; `k` recorded; `credit_recorded(k)` sent | minter request |

The owner-facing `burn` keeps its message layout (`burn_tokens`,
`jetton-wallet.fc:191`). Transfers between wallets keep the unchanged TEP-74
path. A credit from the minter now arrives as a distinct `op::credit` rather
than as `internal_transfer`. An `internal_transfer` whose sender is the
minter is refused, so the two paths cannot be confused.

### 5.4 Watermark compaction, and why it rejects arbitrarily late duplicates

On every channel the receiver holds a watermark `W` and a dictionary of
entries at or above `W`:

1. A request with number `n < W` is a duplicate. It is answered with the
   recorded final result and applies nothing.
2. A request with `n >= W` that has an entry is a duplicate of a known
   operation. It is checked against the stored hash (mismatch is refused),
   and it then re-sends the result or continues the pending work. It does
   not repeat the effect.
3. A request with `n >= W` and no entry is new. The receiver applies its
   effect and creates the entry in the same transaction.
4. When the entry at `W` is final, `W` advances over contiguous final
   entries and deletes them. Each transaction folds at most `FOLD_LIMIT`
   entries (proposed: 8) so that gas stays bounded. Folding resumes in later
   transactions, and the order of folding does not affect correctness.

**Claim.** No request's effect is applied twice, at any delay. *Argument.*
The sender assigns each number to exactly one operation and never reuses it
(it is a monotonic counter in the sender's storage). The receiver applies an
effect only in case 3, which requires that `n` is neither below `W` nor
present. Applying it creates the entry atomically. The entry is deleted only
when `W` passes `n`, and `W` never decreases. So after the first application,
every later message numbered `n` falls into case 1 or case 2. The argument
uses neither time nor delivery order. **Time-based deletion is not used
anywhere.**

**Outcomes below the watermark.** Cases 1 and 2 must reproduce the right
result. On C1 and C2 there is only one final outcome (counted, credited), so
`W` is enough. On C3 and C4 there are two (RECORDED and cancelled), so the
cancelled numbers are kept permanently: `cancelled[m]` at the bridge and
`holder.cancelled[b]` at the minter. Cancellations are owner-initiated and
expected to be rare. The bridge's set is the only permanent per-cancellation
masterchain growth (Q1).

**What does not compact.** The bridge's `consumed_swaps` grows permanently,
by one entry per swap (Q1). The minter's `holders` grows by one entry per
holder that ever received a credit or burned. The entry is basechain storage
holding two counters, two watermarks and three dictionary roots.
`credits_above`, `burns_above`, `mints` and the pending dictionaries are
bounded by the number of operations that are out of order or unfinished. An
operation left unfinished (unfunded, never advanced) keeps its watermark
from passing, and later finals accumulate above it. The accumulation is
bounded by the number of later operations and drains as soon as the blocking
operation is advanced. This is a liveness cost, not a safety one.

**Persistence assumption.** Replay protection holds while the receiver's
account exists. An account deleted for storage debt and later redeployed by
a StateInit-carrying message starts again from `W = 0`. Section 11 states
this as a boundary and quantifies it.

## 6. Message flows

### 6.1 Messages

All protocol messages, requests and results alike, are sent
**non-bounceable**. A leg that refuses keeps the value it was sent, and the
sender's record stays unfinished and advanceable. No protocol state depends
on a bounce, so suppressing bounces changes nothing. A bounced message that
arrives anyway (only an owner's or an advancer's own message can bounce) is
accepted and ignored by the protocol handlers. The wallet's existing
bounce-restore for transfers between wallets is unchanged. **The wallet's
bounce-restore for `burn_notification` is removed**, because burns no longer
travel bounceable.

| Id | Message | From -> to | Body (after `op`, `query_id`) |
|---|---|---|---|
| G1 | `execute_voting` swap | multisig -> bridge | unchanged |
| M1 | `mint_request` | bridge -> minter (StateInit) | `s, mint_op, swap_key, recipient_owner, amount` |
| M2 | `credit` | minter -> wallet (StateInit) | `k, kind, ref, amount, credit_op` |
| M3 | `credit_recorded` | wallet -> minter | `k, owner` |
| M4 | `mint_completed` | minter -> bridge | `s, ^token_data` |
| B0 | `burn` | owner -> wallet | unchanged |
| B1 | `burn_request` | wallet -> minter | `b, amount, owner, destination, cancel` |
| B2 | `burn_notice` | minter -> bridge | `m, burn_op, amount, owner, destination, cancel, ^token_data` |
| B3 | `burn_result` | bridge -> minter | `m, outcome` |
| B4 | `burn_outcome` | minter -> wallet | `b` (RECORDED only; a cancellation arrives as an M2 refund) |
| X0 | `cancel_burn` | owner -> wallet | `b` |
| A* | `advance` | anyone -> bridge / minter / wallet | `kind, id` (section 7) |
| L | `LOG_BURN` | bridge -> external | **unchanged format** (`settlement.fc:130`) |

Proposed opcodes are 40 to 49 (`mint_request`, `credit`, `credit_recorded`,
`mint_completed`, `burn_request`, `burn_notice`, `burn_result`,
`burn_outcome`, `advance`, `cancel_burn`). Fresh numbers are used so that a
message in the current layout can never be parsed as one in the new layout.
Opcodes 21 to 27 (`mint`, `mint_credited`, `mint_completed`, `mint_failed`,
`retry_mint`, `burn_recorded`, `retry_refund`) are removed and become
`error::unknown_op`. The statuses `MINT_FAILED`, `BURN_REFUND_FAILED` and the
logs `LOG_MINT_FAILED` and `LOG_BURN_REFUND_FAILED` are removed: there is no
failure state anymore, only *unfinished* and *final*.

### 6.2 Mint

1. **G1 at the bridge** (new business: reads ConfigParam 79 for the oracle
   address, `state_flags` and the fee). The existing checks stay. The swap
   key must be paid and not consumed. In one transaction the bridge deletes
   `paid_swaps[key]`, writes `consumed_swaps[key]`, creates
   `pending_mints[s]` and sends M1 carrying the mint fee. If the minter later
   cannot proceed at current prices, the operation stays recorded and
   advanceable (P1: a consumed swap is always recoverable).
2. **M1 at the minter.** The sender must equal the pinned `bridge`.
   - `s < mint_watermark` or `mints[s]` is COUNTED: send M4 again.
   - `mints[s]` is CREDITING (hash checked): send M2 again for its `k`.
   - Otherwise new. If `total_supply + in_flight + a > MAX_SUPPLY`, or the
     value is below the minter's need (section 8), the minter throws and
     records nothing; it is **deferred**, not failed. Otherwise it gets or
     creates the holder, takes `k = next_credit_seq`, writes `credits[k]`
     and `mints[s]` = CREDITING, sets `in_flight += a` and sends M2.
3. **M2 at the wallet.** The sender must equal `jetton_master_address`.
   - `k < credit_watermark` or `k` is in `credits_above` (hash checked): send
     M3 again. The balance is unchanged.
   - Otherwise, if the value is below the wallet's need, throw. Else
     `balance += a`, record `k` (folding), and for a REFUND delete
     `burns[ref]`. Then send M3.
4. **M3 at the minter.** The sender must be the derived wallet of `owner`.
   - `credits[k]` is present: delete it, then
     `in_flight -= a` and `total_supply += a`. For MINT, set `mints[s]` to
     COUNTED, fold, and send M4. For REFUND, set `burns[b]` to REFUNDED and
     fold.
   - `credits[k]` is absent: the credit was already counted. No effect.
5. **M4 at the bridge.** The sender must be the minter derived from the
   carried `token_data`. If `pending_mints[s]` is present in that minter's
   channel, delete it. If absent, no effect.

### 6.3 Burn

1. **B0 at the wallet** (new business: reads ConfigParam 79 for
   `state_flags` and the exact burn fee). The checks of `burn_tokens` stay,
   and a new one requires the fee to cover the whole burn path at current
   prices, or the wallet refuses and keeps the tokens. In one transaction
   the wallet sets `balance -= a`, writes `burns[b]` = PENDING and sends B1.
2. **B1 at the minter.** The sender must be the derived wallet of `owner`.
   - `b < holder.burn_watermark`: if `b` is in `holder.cancelled`, do
     nothing (a refunded burn has no pending wallet record to answer).
     Otherwise send B4.
   - `burns[b]` is present (hash checked). AWAITING_BRIDGE: if `cancel=1`,
     set `cancel_requested`, then send B2 again with the stored
     `cancel_requested` flag. RECORDED: send B4. REFUNDING: send the refund
     M2 again. REFUNDED: nothing.
   - Otherwise new. If `a > total_supply` (a credit landed but is not yet
     counted) or the value is below the need, throw: the burn is
     **deferred**, and the wallet's record keeps it advanceable. Otherwise
     set `total_supply -= a`, take `m = next_notice_seq`, write `burns[b]`
     = AWAITING_BRIDGE and `notices[m]`, and send B2.
3. **B2 at the bridge.** The sender must be the minter derived from the
   carried `token_data`.
   - `m < burn_watermark`, or `m` is in `burns_above` or `cancelled`: send
     B3 again with the recorded outcome. **No `LOG_BURN`.** The burn's hash
     is compared where one is held (`burns_above`, `cancelled`). Below the
     watermark a RECORDED burn holds none (section 5.4).
   - Otherwise new. If the value is below the need, throw. With `cancel=0`,
     record RECORDED, send `LOG_BURN` in mode 0 (paid from the notice) and
     send B3(RECORDED) in mode 0. With `cancel=1`, record CANCELLED, write
     `cancelled[m]` and send B3(CANCELLED). Both are a single transaction:
     the record, the log and the result commit together or not at all.
4. **B3 at the minter.** The sender must be the pinned `bridge`.
   `notices[m]` must be present and the burn AWAITING_BRIDGE, else no
   effect. On RECORDED the burn becomes RECORDED, the minter folds and sends
   B4. On CANCELLED the burn becomes REFUNDING, `cancelled[b]` is set,
   `k = next_credit_seq`, `credits[k]` = REFUND, `in_flight += a`, and M2
   (refund) is sent.
5. **B4 at the wallet.** The sender must be the minter. The wallet deletes
   `burns[b]` if present. There is no reply.
6. **Refund.** Steps 6.2.3 and 6.2.4 with `kind = REFUND`: the wallet credits
   once per `k`, and the minter counts once per `k`.

### 6.4 Cancellation (RECORDED versus CANCELLED)

- Only the **owner** can cancel, through `cancel_burn(b)` to the wallet,
  which requires `burns[b]` to be present. A third party cannot force a
  refund in place of a release. Cancellation is accepted while burns are
  suspended and does not read ConfigParam 79.
- The decision is made **only at the bridge, once per `m`**. The first B2
  for `m` to execute decides RECORDED (`cancel=0`) or CANCELLED (`cancel=1`).
  The decision is final and permanent. Every later B2 for `m`, with either
  flag, receives the same outcome, and **a cancelled `m` can never emit
  `LOG_BURN`**.
- The refund is authorized only by B3(CANCELLED) from the pinned bridge. A
  bounce, a missing result, a timeout or the owner's request alone never
  credits anything.
- If the minter has not yet seen `b` when the cancellation reaches it (the
  first B1 was lost), the minter takes the ordinary new-burn path with
  `cancel=1`: it applies the supply transition and asks the bridge, so the
  bridge still makes the choice.
- In normal operation B2(`cancel=0`) is sent first, so the burn is RECORDED
  and the cancellation receives RECORDED. A cancellation therefore wins only
  for a burn whose notice has not yet executed at the bridge, which is
  exactly the stuck case. Both outcomes are safe. Arrival order picks one.

Q2 asks whether cancellation should be kept at all. With cancellation
removed, every accepted burn ends in exactly one RECORDED, and the refund
path and its tests go away.

## 7. Permissionless funded retransmission (`advance`)

Each contract accepts `advance(kind, id)` from **any sender**. The message
carries only the kind, the identifier and its TON value. Everything the
contract sends is rebuilt from its stored record. The destination is a
pinned or derived address, and the amount, recipient, destination and
outcome are stored fields. **The caller has no input that reaches any of
them.**

| Contract | `advance` kind, id | If the record is unfinished | If the record is final | If there is no record |
|---|---|---|---|---|
| bridge | MINT `(minter, s)` | `pending_mints[s]`: send M1 again | (deleted) refuse | refuse |
| bridge | BURN_RESULT `(minter, m)` | n/a (bridge records are final at once) | send B3 again with the outcome | refuse |
| minter | MINT `s` | CREDITING: send M2 again | COUNTED or below `W`: send M4 again (it carries only `s` and the minter's own token data) | refuse |
| minter | BURN `(owner, b)` | AWAITING: send B2 again; REFUNDING: send the refund M2 again | RECORDED or below `W` (not cancelled): send B4 again | refuse |
| wallet | BURN `b` | `burns[b]`: send B1 again, with `cancel_requested` | (deleted) refuse | refuse |
| wallet | REPORT `k` | n/a | below `W` or in `credits_above`: send M3 again | refuse |

- **Who pays.** The caller pays with the message value. The contract
  requires `value >= advance_cost(kind, id)`, the price of this leg and of
  every remaining leg at current prices (section 8). A get-method
  `get_advance_cost(kind, id)` on each contract returns that figure. An
  underfunded or inapplicable advance throws, and the caller's bounceable
  message returns the value.
- **What it cannot do.** It cannot create an operation (it requires an
  existing record), change one (it reads every field from storage), skip a
  check (the receiving leg runs the same handler as for an original
  request), or repeat an effect (the receiver deduplicates, section 5.4).
  A wasted advance costs only its caller.
- **Cascading.** An advance at the earliest unfinished participant drives
  the whole remaining path. For example, an advance of a mint at the bridge
  produces M1. The minter, if CREDITING, sends M2. The wallet, if it already
  credited, re-sends M3. The minter counts once and sends M4. A recovery
  never needs to know which leg was lost.
- **Excess.** The value left after the last leg stays with the participant
  that ends the path. Returning it to the funder would add a response
  address to every leg (Q5).
- **While suspended** and **without ConfigParam 79**: accepted.

## 8. Fees and gas per leg

Every leg prices itself **when it executes**, with `GETGASFEE` and
`GETFORWARDFEE` and with declared gas per step, as `settlement.fc` does now.
Before applying any effect, the leg requires the incoming value to cover its
own step and every remaining leg of the path it is about to take. If the
value is short, it throws and has no effect. The value stays at the receiver
(non-bounceable), and the sender's record stays unfinished and advanceable.
When prices are stable a funded path completes in one pass. When prices rise
between legs, the first underfunded leg stops the path cleanly, and an
advance funded at the new price resumes it.

Declared gas (proposed, to be replaced by measured maxima on aged contracts
as `every_completion_step_fits_the_gas_it_is_priced_at` does today):
`WALLET_STEP_GAS = 25 000`, `MINTER_STEP_GAS = 60 000`,
`BRIDGE_STEP_GAS = 40 000`. Storage reserves (code constants):
`WALLET_RESERVE = 0.05 TOS`, `MINTER_RESERVE = 0.1 TOS`, the values the
sandbox uses now.

The figures below use the configuration fixture
`tosctl/src/executor/real_boc/default_config.boc`. It prices basechain gas at
1 000 tomi per unit (flat 100 units for 100 000) and masterchain gas at
10 000 (flat 100 units for 1 000 000). Basechain forwarding is a 1 000 000
lump plus 1 000 per bit and 100 000 per cell. Masterchain forwarding is a
10 000 000 lump plus 10 000 per bit and 1 000 000 per cell. A "small"
message is priced as one 1 023-bit cell, as `small_message_fee` does. The
StateInit-carrying messages depend on compiled code size and are estimates
until measured.

| Leg | Chain | Own cost (gas + forwarding of what it sends) | Remaining need it must forward |
|---|---|---|---|
| M4 at bridge | mc | 0.400 | 0 |
| M3 at minter | bc gas, mc forward | 0.060 + 0.0212 | 0.400 -> **need 0.481** |
| M2 at wallet | bc | reserve top-up <= 0.050 + 0.025 + 0.0021 | 0.481 -> **need 0.558** |
| M1 at minter | bc | 0.060 + credit with StateInit approx. 0.0105 | 0.558 -> **need 0.629** |
| G1 / advance MINT at bridge | mc | 0.400 + M1 with minter StateInit approx. 0.25 | 0.629 -> **need approx. 1.28** |
| B3 RECORDED at minter, then B4 | bc | 0.060 + 0.0021, then 0.025 at the wallet | **need 0.087** |
| B3 CANCELLED at minter, then refund | bc | 0.060 + 0.0105 + 0.050 + 0.025 + 0.0021 + 0.060 | **need 0.208** |
| B2 at bridge | mc | 0.400 + max(LOG_BURN 0.0212 + B3 0.0212 + 0.087, B3 0.0212 + 0.208) | **need 0.629** |
| B1 at minter | bc gas, mc forward | 0.060 + B2 approx. 0.025 | **need 0.714** |
| B0 at wallet (burn fee floor) | bc | 0.025 + B1 0.0021 | **need approx. 0.741** |

Figures are in TOS. The sandbox's current `MINT_FEE` and `BURN_FEE` are
2 TOS. The implementation exposes the exact figure at the moment of a call
(`get_advance_cost`, and the existing `get_credit_cost` and `get_burn_cost`
reworked). The tests assert each threshold exactly: the cost succeeds, and
one unit less is refused with no effect.

The contracts' own balances pay only for storage and for optional records:
the logs other than `LOG_BURN`, sent in mode 2. They never pay for a
protocol leg. `LOG_BURN` is paid from B2's value, in mode 0, atomically with
the RECORDED record.

## 9. Failure analysis per message

"Effect" means the state change in section 5. A "gas rise before it" means
prices rise between the send and the execution so that the value no longer
covers the need.

| Msg | Lost | Duplicated | Delayed past completion or cancellation | Reordered | Bounced | Gas rise before it |
|---|---|---|---|---|---|---|
| G1 | No effect; the payment stays in `paid_swaps`; oracles re-vote | `swap_consumed`, no effect, payment untouched | same as duplicated | independent per swap | multisig's concern; no bridge state | bridge runs on the vote's value; M1 carries the fee; later legs re-price |
| M1 | `pending_mints[s]` stays; advance MINT at the bridge | CREDITING: re-sends M2; COUNTED: re-sends M4 | below `W`: re-sends M4; no credit | `s+1` before `s`: both recorded, `W` waits for `s` | not sent bounceable; a forged bounce is ignored | minter throws, no record; advance at the bridge at the new price |
| M2 | `mints[s]` CREDITING / `credits[k]` stays; advance at the minter or the bridge | wallet re-sends M3, balance unchanged | `k < W`: re-sends M3, no credit | `credits_above` holds `k+1`; folds when `k` lands | as M1 | wallet throws, no credit; advance |
| M3 | credit landed, uncounted; `credits[k]` stays; advance REPORT at the wallet or advance at the minter/bridge | `credits[k]` absent: no effect | no effect | each `k` independent | as M1 | minter throws; advance REPORT |
| M4 | `pending_mints[s]` stays; advance MINT at the bridge reaches a COUNTED minter, which re-sends M4 | no effect | no effect | independent | as M1 | bridge throws; advance at the minter |
| B0 | owner's own message; no debit | separate burns, separate `b` (intended) | n/a | n/a | owner's message bounces back on refusal; tokens kept | wallet refuses unless the fee covers the path at current prices |
| B1 | `burns[b]` PENDING stays; advance BURN at the wallet | AWAITING: re-sends B2; final: re-sends B4 or the refund | below `W`: B4, or nothing for a cancelled `b` | `b+1` first: independent records, `W` waits | as M1 | minter throws, no supply change; advance at the wallet |
| B2 | minter AWAITING; advance at the minter or the wallet | re-sends B3 with the recorded outcome; **no second `LOG_BURN`** | same; a notice for a cancelled `m` gets CANCELLED and never logs | `m+1` first: independent; `W` waits | as M1 | bridge throws, nothing recorded, no log; advance |
| B3 | minter AWAITING; advance at the minter (re-sends B2) or advance BURN_RESULT at the bridge | `notices[m]` absent or not AWAITING: no effect | no effect | independent | as M1 | minter throws; advance |
| B4 | wallet `burns[b]` stays; advance at the wallet, and the minter re-sends B4 | no effect | no effect | independent | as M1 | wallet throws; advance |
| X0 | owner's own message; resend it, or advance BURN at the wallet after it executed | sets an already-set flag | after RECORDED: the bridge answers RECORDED; after a refund: `burns[b]` is gone, refused | decided by the first B2 to execute | owner's message only | wallet throws; owner resends |
| A* | no effect; caller resends | each runs as its leg; the receivers deduplicate | refused ("no record") or re-sends a final result | n/a | bounces to its caller on refusal | throws (underfunded); caller resends at `get_advance_cost` |
| L | an external message cannot be lost once the transaction is final; oracles read it from the bridge transaction | impossible: exactly one RECORDED per `m` | n/a | n/a | n/a | atomic with RECORDED: both or neither |

A burn at a minter whose supply does not yet include a landed credit is
deferred, not refused for good (B1, `a > total_supply`). It completes after
that credit's M3 is counted, which is itself recoverable. **This is a
behaviour change:** today the burn notification bounces back to the wallet
(`a_burn_that_overtakes_its_credits_confirmation_is_refused_and_returned`).

## 10. Compatibility

- **Wallet code and addresses.** The wallet's code and its initial data
  layout change (new watermark, burn counter and dictionaries), so every
  wallet address changes. Its owner-facing `transfer` and `burn` layouts do
  not change. Its credit path is a new opcode.
- **Minter code and addresses.** The minter's code and initial data change,
  and the initial data now include the bridge address. Every minter address
  changes, and **each bridge has its own minters**. A bridge replaced through
  ConfigParam 79 does not inherit the old bridge's tokens. The old bridge
  must stay funded and observed by oracles until every operation pinned to
  it is final (Q3).
- **Bridge storage.** The layout changes (section 5.1). `new-bridge.fif` is
  rewritten to build it, and `a_bridge_deployed_by_its_script_completes_a_mint`
  keeps holding the script and the contract to one layout. `get_pending_mint`
  and `get_next_mint_id` are replaced by per-minter getters.
- **ConfigParam 79 format.** Unchanged (`build-config79.fif`). The fields
  `wallet_min_tos_for_storage`, `minter_min_tos_for_storage` and
  `wallet_gas_consumption` stop affecting settlement. They remain only for
  jetton transfers and discovery.
- **`LOG_BURN`.** **The format is unchanged** (the 704-bit body,
  `settlement.fc:130`). EVM `unlock` identifies a release by
  `(receiver, token, amount, tx.address_hash, tx.tx_hash, tx.lt)`
  (`evm/contracts/TosUtils.sol`, `Bridge.sol:114`). That identity is unique
  because the bridge emits `LOG_BURN` exactly once per burn, in exactly one
  transaction. A second emission, even with identical fields, would be a
  second valid unlock, which is why duplicates never log. Two things change
  for oracle operators. The transaction that logs a burn may be an advanced
  retransmission long after the burn. Oracles must also keep watching a
  retired bridge while it has unfinished operations. Adding the burn
  operation id to `LOG_BURN` is not needed for safety (Q10).
- **EVM contracts.** No change.
- **`votes-collector.fc` and `multisig.fc`.** No change.
- **Other tooling that pins the layout**, all updated with the
  implementation: `scripts/verify-token-bridge.py` (source pins at
  `:103-196`), `crosschain/token-bridge/tvm/tests/*.js` (executed by
  `scripts/test-token-bridge-tvm.sh`), `NOTICE.md` (items 13 to 18
  superseded), and `SECURITY.md` ("Completion of mints and burns", "What
  remains", "Incident procedure").
- **Deployed instances.** None found. `~/memo` (all of `codex-security/`)
  records no deployment. The only references to `new-bridge.fif` and
  `build-config79.fif` are the build, the verifier, the sandbox and the JS
  tests. `README.md` states that no ConfigParam slot is populated by this
  directory, and `SECURITY.md` forbids activation before the pre-mainnet
  checklist. **No migration is designed.** Before implementation is merged,
  the owner should confirm that ConfigParams 79, 81, 82 and 83 are empty on
  every operated network. If an instance is found, its code is immutable
  and its storage is incompatible. It would have to be retired under the
  current incident procedure, not migrated.

## 11. Liveness boundaries that remain

The design guarantees safety (no double credit, no double count, no second
`LOG_BURN`, never both `LOG_BURN` and a refund) unconditionally. It
guarantees completion only once execution resumes and current-price funding
is supplied. What it cannot guarantee:

1. **Permanent execution failure.** A leg that can never execute (a code
   defect, or a step above the per-transaction gas limit) blocks its
   operation forever. Aged-dictionary gas measurements (section 12, T-G) and
   `FOLD_LIMIT` bound the second case.
2. **Permanent participant unavailability.** The bridge (masterchain)
   frozen for unpaid storage, or a minter or wallet deleted for storage
   debt. Deletion is also the one **safety** caveat. A wallet deleted and
   then redeployed by a retransmitted credit starts from `credit_watermark
   = 0` and would credit that `k` again. This is reachable only if the
   minter's `credits[k]` is still unfinished at that time. That requires all
   of the following: a credit landed, its M3 was lost, nobody advanced it,
   and the wallet then accumulated storage debt beyond `delete_due_limit`.
   The fixture's basechain storage prices are 1 per bit and 500 per cell per
   2^16 s, and its `delete_due_limit` is 1 TOS. A wallet account of about
   20 cells and 10 000 bits, code included, therefore accrues about 0.01 TOS
   a year, and its 0.05 TOS reserve lasts about 5 years. Deletion then takes
   roughly another century after the balance is gone. A storage price rise
   shortens both. Losing the account would also lose its jetton balance,
   which is the ordinary jetton-wallet risk. Q6 asks whether this is
   accepted as a boundary.
3. **Absent funding.** Nothing advances an operation nobody pays for. An
   unfunded operation stays unfinished and holds its watermark (section
   5.4).
4. **Deferral conditions.** A mint over the supply bound waits for burns. A
   burn exceeding counted supply waits for its credit's count. Both resolve
   through ordinary, recoverable operations.
5. **Off-chain.** Oracles signing the unlock for a recorded `LOG_BURN`, and
   the EVM release, are outside this protocol. The bridge's guarantee is one
   recorded release obligation per burn.

## 12. Test matrix

All tests run in `tosctl/src/node-control/contracts/tests/token_bridge_sandbox.rs`
on real action and bounce phases. With `TOKEN_BRIDGE_TRACE_DIR` set, every
transaction they execute is recorded and replayed through the native engine
by `scripts/replay-token-bridge-trace.py` (job `contract-sandboxes`,
`.github/workflows/contract-sandboxes.yml:220-225`). The replay requires
identical exit codes, action results, bounces, outgoing messages with values
and fees, and final balance and data. The fixture configuration has no
ConfigParam 79 (it holds 8, 12, 18, 20, 21, 24, 25, 31, 43), so a recording
made with 79 removed replays with 79 absent. Every price change is part of
each recorded configuration.

**Closing properties** the tests are mapped to:

| Id | Property |
|---|---|
| P1 | Every consumed swap remains recoverable to exactly one wallet credit and an authenticated bridge completion, or to an authenticated cancellation that permanently prevents that credit. This design has no mint cancellation, so it is always the former. |
| P2 | Duplicate, delayed and reordered mint requests and results cannot repeat a wallet credit, supply accounting or fee consumption, and lost results remain re-reportable. |
| P3 | Every accepted burn debit remains recoverable to exactly one bridge-recorded release obligation or exactly one wallet refund. |
| P4 | `LOG_BURN` and refund are mutually exclusive, and losing any acknowledgement cannot leave an operation without a funded reconciliation path. |

**Harness additions:** drop a queued message by predicate; duplicate one;
hold one and deliver it later; forge a bounced copy of any message; remove
or replace ConfigParam 79; set masterchain and basechain gas prices
independently; `advance` helpers with `get_advance_cost`; and a **ledger
check** run after every delivered transaction.

**Ledger check** (every test, every transaction):

- (I1) `Σ wallet balances + D = total_supply + L`, where `D` is debited
  burns not yet accepted by the minter and `L` is credits landed at wallets
  and not yet counted. `L <= in_flight`.
- (I2) The number of `LOG_BURN` per `m` is 1 if the bridge recorded `m`
  RECORDED, else 0.
- (I3) Refund credits per burn: 1 if CANCELLED, else 0.
- (I4) Never both I2 and I3 for one burn.
- (I5) Paid swaps consumed per swap key is at most 1.
- (I6) Wallet credits per `k` is at most 1, and supply counts per `k` is at
  most 1.
- (I7) The bridge's, minter's and wallets' own TON balances never fall
  below their reserves, and no participant's balance pays for a protocol
  leg. Each leg's outgoing value plus fees does not exceed its incoming
  value. The exception is G1, which spends the swap's recorded payment and
  nothing more.

| Id | Scenario | Controls | Asserts, beyond the ledger check | Property |
|---|---|---|---|---|
| T-M1 | mint, one pass | none | `consumed_swaps` set; `pending_mints` empty; minter COUNTED, folded; wallet `k` recorded; supply = amount | P1, P2 |
| T-M2..5 | mint; lose M1, M2, M3, M4 in turn | drop that message; then advance MINT at the bridge (and variants: advance at the minter; advance REPORT at the wallet) | final state equals T-M1; one credit; one count; caller paid exactly `get_advance_cost`; cost - 1 refused with no effect | P1, P2 |
| T-M6 | mint; gas rise before each leg | for each of M1..M4: raise the gas price of the receiving chain so the leg is short; deliver it (throws, no effect, value kept); then advance at the risen price | as T-M1; the risen-price advance succeeds at exactly its cost | P1, P2 |
| T-M7 | mint without ConfigParam 79 | remove 79 after G1, then before each later leg; repeat with 79 *changed* (bridge address elsewhere, fees changed, all flags suspended) | completes; advance accepted; no handler reads 79 (exit codes) | P1 |
| T-M8 | old and duplicate messages after completion | re-deliver held copies of M1, M2, M3, M4 after final; deliver each twice in flight | no second credit, count or fee; balances, supply and `in_flight` unchanged; `pending_mints` empty | P2 |
| T-M9 | reorder | two mints to one holder; deliver `k+1` before `k`, `s+1` before `s` | `credits_above` and `mints` hold the out-of-order entry; watermarks fold after; one credit each | P2 |
| T-M10 | identity reuse | forge (sender = bridge) M1 with an existing `s` and a different amount; forge M2 with an existing `k` in `credits_above` and a different hash; a second vote for a consumed swap, identical and different | `operation_mismatch` or `swap_consumed`; no state change; payment untouched | P1, P2 |
| T-M11 | bounces | forge a bounced copy of every mint message to every participant; and suppress all bounces in T-M2..7 | no state change from any bounce; outcomes identical with bounces suppressed | P1, P2 |
| T-M12 | advance hygiene | stranger advances: unfinished (accepted), final (refused, value bounced), absent (refused), underfunded (refused); suspension set | destination, amount and recipient unchanged; caller's change bounced | P1, P2 |
| T-M13 | deferrals | supply bound reached; mint deferred; a burn frees room; advance | deferred mint completes; never a failure state | P1 |
| T-B1 | burn, one pass | none | exactly one `LOG_BURN`; wallet `burns` empty; minter RECORDED, folded; bridge `m` folded | P3, P4 |
| T-B2..5 | burn; lose B1, B2, B3, B4 in turn | drop it; advance BURN at the wallet (and variants: advance at the minter; advance BURN_RESULT at the bridge) | final state equals T-B1; `LOG_BURN` count 1 | P3, P4 |
| T-B6 | burn; gas rise before each leg | raise masterchain prices before B2 and basechain prices before B1, B3, B4; then advance at the risen price | as T-B1; exact-threshold advance | P3, P4 |
| T-B7 | burn without ConfigParam 79 | remove or change 79 after B0 and before each later leg; set `STATE_BURN_SUSPENDED` after B0 | completes; new burns refused while suspended; advance and cancel accepted | P3, P4 |
| T-B8 | cancellation | (a) B2 lost, owner cancels: CANCELLED, one refund, 0 logs, then deliver the old B2(`cancel=0`): CANCELLED again, 0 logs, no second refund; (b) cancel after RECORDED: RECORDED again, no refund; (c) B1 lost then cancel: the minter takes the new-burn path with `cancel=1`; (d) refund M2 lost, and refund M3 lost: advance, refund once; (e) cancel by a non-owner: refused; (f) both B2 flags queued, in both orders: exactly one of {log, refund} | I2..I4; supply restored once on refund | P3, P4 |
| T-B9 | old and duplicate messages after completion or cancellation | re-deliver held B1, B2, B3, B4, X0 and refund M2/M3 after final | no second log, refund, debit or supply transition | P3, P4 |
| T-B10 | bounces cannot refund | forge a bounced B2 at the minter, and a bounced B1 at the wallet; suppress all bounces in T-B2..8 | no refund, no balance restore, no state change; the previous refund-on-bounce behaviour is gone | P4 |
| T-B11 | identity reuse | forge B2 (sender = derived minter) with an existing `m` in `burns_above` and a different amount; forge B1 with an existing `b` and a different destination | `operation_mismatch`; no log; no state change | P3, P4 |
| T-P4 | deferral | burn before its credit's M3 is counted | deferred (minter throws), wallet `burns[b]` kept; after M3, advance completes; one log | P3 |
| T-G | gas ceilings | age every new dictionary to 65 536 entries (bridge channels, `consumed_swaps`, `cancelled`, minter `holders`, `mints`, `notices`, per-holder dictionaries, wallet dictionaries), then run every leg and every advance path including folding at `FOLD_LIMIT` | each measured step <= its declared gas | all (budget soundness) |
| T-S | storage and deployment | `new-bridge.fif` deploys a bridge that completes a mint and a burn; counters at `2^64 - 1` refuse new operations and still advance existing ones | | compatibility |

**Mutation controls** (run in implementation, each must turn its test red
for the stated reason, then green on restore):

- Remove the wallet's watermark check (T-M8: double credit).
- Remove the minter's `credits[k]` presence check (T-M8: double count).
- Remove the bridge's `burn_watermark` / `burns_above` check (T-B9: second
  `LOG_BURN`).
- Let the bridge honour the second B2's flag (T-B8f: log and refund).
- Restore refund-on-bounce (T-B10).
- Read ConfigParam 79 in any completion handler (T-M7, T-B7: exit 666).
- Drop the hash comparison (T-M10, T-B11).
- Send any protocol message with mode `+2` (T-M6 or T-B6: a record commits
  without its message).
- Let `advance` take any field from the message body (T-M12).
- Remove the per-leg need check (T-M6, T-B6: a record commits while its
  path is unfundable; the ledger check still holds, but the exact-threshold
  assertion fails).

The existing tests are kept or replaced as follows. The refund-on-bounce and
`retry_*` tests (`token_bridge_sandbox.rs:833`, `:882`, `:1035`, `:1057`,
`:1091`) assert behaviour this design removes. They are rewritten as T-B10,
T-P4 and T-M2..5, and each rewrite states the changed outcome.
`a_report_the_minter_cannot_fund_is_skipped_and_the_supply_still_counted`
(`:1484`) currently asserts the documented residual (`MINT_IN_FLIGHT`
forever). It becomes T-M5, which asserts recovery.

## 13. Open questions for a ruling

- **Q1. Permanent masterchain growth.** `consumed_swaps` (one entry per
  swap) and the bridge's `cancelled` (one per cancellation) never compact.
  At the fixture's masterchain storage prices (1 000 per bit and 500 000
  per cell per 2^16 s) an entry of about one cell and 600 bits costs about
  0.5 TOS a year, permanently. Options: (a) accept, and charge the cost into
  the mint fee policy; (b) make swaps compactable by adding a dense lock
  nonce to the EVM `Lock` event and to the vote, so the bridge can keep a
  watermark per EVM bridge (this changes `Bridge.sol`, the oracle vote
  format and `test_protocol_model.py`); (c) keep today's oracle-trust model
  for swap replay and record only `pending_mints`. Recommendation: (a) now,
  (b) before volume.
- **Q2. Cancellation.** Keep owner-initiated cancellation (as designed) or
  remove it. It only helps a burn whose notice has not executed at the
  bridge. A permanently non-executing bridge cannot cancel either, since the
  bridge decides. Removing it drops REFUNDING/REFUNDED, both `cancelled`
  sets, X0 and T-B8. Recommendation: keep, since the condition and today's
  users expect a refund path.
- **Q3. Pinning the bridge in the minter's StateInit.** Replacing the
  bridge through ConfigParam 79 then creates new tokens rather than
  re-pointing the old ones. The alternative, a minter that reads the bridge
  from the ConfigParam, is what the condition refuses. Confirm.
- **Q4. Address change.** Every wallet and minter address changes.
  Confirm that no slot (79, 81, 82, 83) is populated on any operated
  network.
- **Q5. Excess value** of a funded path stays with the participant that
  ends it, not with the funder. Accept, or add a response address to every
  leg?
- **Q6. Account deletion** (section 11.2). Accept as a boundary, or require
  a mitigation, for example a minimum wallet reserve sized for a stated
  horizon at a stated price ceiling?
- **Q7. Storage reserves become code constants.** Values: 0.05 TOS
  (wallet) and 0.1 TOS (minter)?
- **Q8. Mismatched reuse below a watermark** is answered with the recorded
  result and has no effect, but is not compared field by field (the hashes
  are compacted). Is "no effect" an acceptable refusal there?
- **Q9. Removed entry points.** `retry_mint` (25), `retry_refund` (27) and
  the failure states and logs are removed, and old opcodes become
  `unknown_op`. Confirm.
- **Q10. `LOG_BURN` format.** Keep it unchanged (recommended: emission is
  exactly once, so the transaction identity the EVM uses stays unique), or
  add `(minter, m)` for oracle bookkeeping, which is a coordinated oracle
  change?
