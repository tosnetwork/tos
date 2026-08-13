# TOS Global Versions

Global versioning is controlled by `ConfigParam 8`, defined in [block.tlb](../crypto/block/block.tlb).

It enables protocol capability bits and gates behavior across validators, contracts, and VM execution.

AI actor protocol primitives that affect consensus-visible behavior, such as scheduled task timeouts, delivery failure records, supervision, or new execution semantics, must be gated through the same global-version and capability process.

## Why It Matters

`ConfigParam 8` is one of the most operationally sensitive settings in the chain:

- it changes feature availability
- it can affect validator acceptance rules
- it may unlock new VM behavior
- it often needs careful rollout coordination

## What the Value Contains

At a high level, the stored object includes:

- protocol version
- capability flags

See [block.tlb](../crypto/block/block.tlb) for the authoritative layout.

## How to Inspect It

Use the lite client:

```bash
cd build
./lite-client/lite-client -C /data/tos-global.json -c "getconfig 8"
```

## Upgrade Guidance

- Treat version bumps as coordinated network changes.
- Review related validator and VM code paths before activation.
- Test changes in a non-production environment first.
- Record both the old value and the intended replacement before voting.
- Document whether the change affects agent accounts, task actors, service actors, verifier actors, or workflow message handling.

## Related Docs

- [ConfigParam.md](ConfigParam.md)
- [ai-actors.md](ai-actors.md)
- [block.tlb](../crypto/block/block.tlb)
* `GETGASFEE` (`gas_used is_mc - price`) - calculates gas fee.
* `GETSTORAGEFEE` (`cells bits seconds is_mc - price`) - calculates storage fees (only current StoragePrices entry is used).
* `GETFORWARDFEE` (`cells bits is_mc - price`) - calculates forward fee.
* `GETPRECOMPILEDGAS` (`- x`) - returns gas usage for the current contract if it is precompiled, `null` otherwise.
* `GETORIGINALFWDFEE` (`fwd_fee is_mc - orig_fwd_fee`) - calculate `fwd_fee * 2^16 / first_frac`. Can be used to get the original `fwd_fee` of the message.
* `GETGASFEESIMPLE` (`gas_used is_mc - price`) - same as `GETGASFEE`, but without flat price (just `(gas_used * price) / 2^16`).
* `GETFORWARDFEESIMPLE` (`cells bits is_mc - price`) - same as `GETFORWARDFEE`, but without lump price (just `(bits*bit_price + cells*cell_price) / 2^16`).

`gas_used`, `cells`, `bits`, `time_delta` are integers in range `0..2^63-1`.

#### Cell operations
Operations for working with Merkle proofs, where cells can have non-zero level and multiple hashes.
* `CLEVEL` (`cell - level`) - returns level of the cell.
* `CLEVELMASK` (`cell - level_mask`) - returns level mask of the cell.
* `i CHASHI` (`cell - hash`) - returns `i`th hash of the cell.
* `i CDEPTHI` (`cell - depth`) - returns `i`th depth of the cell.
* `CHASHIX` (`cell i - hash`) - returns `i`th hash of the cell.
* `CDEPTHIX` (`cell i - depth`) - returns `i`th depth of the cell.

`i` is in range `0..3`.

### Other changes
* `GLOBALID` gets `ConfigParam 19` from the tuple, not from the config dict. This decreases gas usage.
* `SENDMSG` gets `ConfigParam 24/25` (message prices) from the tuple, not from the config dict, and also uses `ConfigParam 43` to get max_msg_cells.


## Version 7
__Enabled in mainnet on 2024-04-18__

Explicitly nullify `due_payment` after due reimbursement.

## Version 8
__Enabled in mainnet on 2024-08-25__

- Check mode on invalid `action_send_msg`. Ignore action if `IGNORE_ERROR` (+2) bit is set, bounce if `BOUNCE_ON_FAIL` (+16) bit is set.
- Slightly change random seed generation to fix mix of `addr_rewrite` and `addr`.
- Fill in `skipped_actions` for both invalid and valid messages with `IGNORE_ERROR` mode that can't be sent.
- Allow unfreeze through external messages.
- Don't use user-provided `fwd_fee` and `ihr_fee` for internal messages.

## Version 9
__Enabled in mainnet on 2025-02-13__

### c7 tuple
c7 tuple parameter number **13** (previous blocks info tuple) now has the third element. It contains ids of the 16 last masterchain blocks with seqno divisible by 100.
Example: if the last masterchain block seqno is `19071` then the list contains block ids with seqnos `19000`, `18900`, ..., `17500`.

### New TVM instructions
- `SECP256K1_XONLY_PUBKEY_TWEAK_ADD` (`key tweak - 0 or f x y -1`) - performs [`secp256k1_xonly_pubkey_tweak_add`](https://github.com/bitcoin-core/secp256k1/blob/master/include/secp256k1_extrakeys.h#L120).
`key` and `tweak` are 256-bit unsigned integers. 65-byte public key is returned as `uint8 f`, `uint256 x, y` (as in `ECRECOVER`). Gas cost: `1276`.
- `mask SETCONTCTRMANY` (`cont - cont'`) - takes continuation, performs the equivalent of `c[i] PUSHCTR SWAP c[i] SETCONTCNR` for each `i` that is set in `mask` (mask is in `0..255`).
- `SETCONTCTRMANYX` (`cont mask - cont'`) - same as `SETCONTCTRMANY`, but takes `mask` from stack.
- `PREVMCBLOCKS_100` returns the third element of the previous block info tuple (see above).

### Other changes
- Fix `RAWRESERVE` action with flag `4` (use original balance of the account) by explicitly setting `original_balance` to `balance - msg_balance_remaining`.
  - Previously it did not work if storage fee was greater than the original balance.
- Jumps to nested continuations of depth more than 8 consume 1 gas for eact subsequent continuation (this does not affect most of TVM code).
- Support extra currencies in reserve action with `+2` mode.
- Fix exception code in some TVM instructions: now `stk_und` has priority over other error codes.
  - `PFXDICTADD`, `PFXDICTSET`, `PFXDICTREPLACE`, `PFXDICTDEL`, `GETGASFEE`, `GETSTORAGEFEE`, `GETFORWARDFEE`, `GETORIGINALFWDFEE`, `GETGASFEESIMPLE`, `GETFORWARDFEESIMPLE`, `HASHEXT`
- Now setting the contract code to a library cell does not consume additional gas on execution of the code.
- Temporary increase gas limit for some accounts (`override_gas_limit` in `transaction.cpp` contains the list of accounts).
- Fix recursive jump to continuations with non-null control data.

## Version 10
__Enabled in mainnet on 2025-05-07__

### Extra currencies
- Internal messages cannot carry more than 2 different extra currencies. The limit can be changed in size limits config (`ConfigParam 43`).
- Amount of an extra currency in an output action "send message" can be zero.
  - In action phase zero values are automatically deleted from the dictionary before sending.
  - However, the size of the extra currency dictionary in the "send message" action should not be greater than 2 (or the value in size limits config).
- Extra currency dictionary is not counted in message size and does not affect message fees.
- Message mode `+64` (carry all remaining message balance) is now considered as "carry all remaining TOS from message balance".
- Message mode `+128` (carry all remaining account balance) is now considered as "carry all remaining TOS from account balance".
- Message mode `+32` (delete account if balance is zero) deletes account if it has zero TOS, regardless of extra currencies.
  - Deleted accounts with extra currencies become `account_uninit`, extra currencies remain on the account.
- `SENDMSG` in TVM calculates message size and fees without extra currencies, uses new `+64` and `+128` mode behavior.
  - `SENDMSG` does not check the number of extra currencies.
- Extra currency dictionary is not counted in the account size and does not affect storage fees.
  - Accounts with already existing extra currencies will get their sizes recomputed without EC only after modifying `AccountState`.
- Reserve action cannot reserve extra currencies.
Reserve modes `+1`, `+4` and `+8` ("reserve all except", "add original balance" and "negate amount") now only affect TOS, but not extra currencies.

### Anycast addresses and address rewrite
- Anycast addresses are not allowed in `dest` of internal and external messages.
- `addr_var` are not allowed in `dest` of external messages.
  - Note: as before, `addr_var` in `dest` of internal messages are automatically replaced with `addr_std`.
- TVM instructions `LDMSGADDR(Q)`, `PARSEMSGADDR(Q)`, `REWRITESTDADDR(Q)`, `REWRITEVARADDR(Q)` no more support anycast addresses and `addr_var`.
- `addr:MsgAddressInt` in `Account` cannot be an anycast address.
  - Therefore, `src` of outbound messages cannot be an anycast address.
  - Existing accounts with anycast addresses change to non-anycast addresses in the first transaction.
- When deploying an account with `fixed_prefix_length` in `StateInit` of the message (it was called `split_depth` before), the first `fixed_prefix_length` bits of the address are not compared against the state hash.
  - This allows deploying an account to an arbitrary shard regardless of the hash of state init.
  - `fixed_prefix_length` remains in the account state.
  - `fixed_prefix_length` of the account can be at most 8. The limit can be changed in size limits config (`ConfigParam 43`).

### TVM changes
- `SENDMSG` calculates messages size and fees without extra currencies, uses new +64 and +128 mode behavior.
  - `SENDMSG` does not check the number of extra currencies.
- New instruction `GETEXTRABALANCE` (`id - amount`). Takes id of the extra currency (integer in range `0..2^32-1`), returns the amount of this extra currency on the account balance.
  - This is equivalent to taking the extra currency dictionary (`BALANCE SECOND`), loading value (`UDICTGET`) and parsing it (`LDVARUINT32`). If `id` is not present in the dictionary, `0` is returned.
  - `GETEXTRABALANCE` has special gas cost that allows writing gas-efficient code with predictable gas usage even if there are a lot of different extra currencies.
  - The full gas cost of `GETEXTRABALANCE` is `26` (normal instruction cost) plus gas for loading cells (up to `3300` if the dictionary has maximum depth).
  - However, the first `5` executions of `GETEXTRABALANCE` cost at most `26+200` gas units. All subsequent executions cost the full price.
  - `RUNVM` interacts with this instructions in the following way:
    - Without "isolate gas" mode, the child VM shares `GETEXTRABALANCE` counter with the parent vm.
    - With "isolate gas" mode, in the beginning of `RUNVM` the parent VM spends full gas for all already executed `GETEXTRABALANCE` and resets the counter.
- `LDMSGADDR(Q)`, `PARSEMSGADDR(Q)`, `REWRITESTDADDR(Q)`, `REWRITEVARADDR(Q)` no more support anycast addresses and `addr_var`.
- Fixed bug in `RUNVM` caused by throwing out-of-gas exception with "isolate gas" enabled.
- Fixed setting gas limits in `RUNVM` after consuming "free gas" (e.g. after `CHKSIGN` instructions).

### Other changes
- Exceeding state limits in transaction now reverts `end_lt` back to `start_lt + 1` and collects action fines.

## Version 11
__Enabled in mainnet on 2025-07-05__

### c7 tuple
**c7** tuple extended from 17 to 18 elements:
* **17**: tuple with inbound message parameters. Asm opcode: `INMSGPARAMS`.
  * The tuple contains:
    * `bounce` (boolean)
    * `bounced` (boolean)
    * `src_addr` (slice)
    * `fwd_fee` (int)
    * `created_lt` (int)
    * `created_at` (int)
    * `orig_value` (int) - this is sometimes different from the value in `INCOMINGVALUE` and TVM stack because of storage fees
    * `value` (int) - same as in `INCOMINGVALUE` and TVM stack.
    * `value_extra` (cell or null) - same as in `INCOMINGVALUE`.
    * `state_init` (cell or null)
  * For external messages, tick-tock transactions and get methods: `bounce`, `bounced`, `fwd_fee`, `created_lt`, `created_at`, `orig_value`, `value` are 0, `value_extra` is null.
  * For tick-tock transactions and get methods: `src_addr` is `addr_none`.

### New TVM instructions
- `x GETPARAMLONG` - same as `x GETPARAM`, but `x` is in range `[0..254]`. Gas cost: `34`.
- `x INMSGPARAM` - equivalent to `INMSGPARAMS` `x INDEX`. Gas cost: `26`.
  - Aliases: `INMSG_BOUNCE`, `INMSG_BOUNCED`, `INMSG_SRC`, `INMSG_FWDFEE`, `INMSG_LT`, `INMSG_UTIME`, `INMSG_ORIGVALUE`, `INMSG_VALUE`, `INMSG_VALUEEXTRA`, `INMSG_STATEINIT`.

### New account storage stat
Along with the storage stat (cells and bits count), each account now stores the hash of the **storage dict**.

**Storage dict** is the dictionary that stores refcnt for each cell in the account state.
This is required to help computing storage stats in the future, after collator-validator separation.

### Other changes
- Fix returning `null` as `c4` and `c5` (when VM state is not committed) in `RUNVM`.
- In new internal messages `ihr_disabled` is automatically set to `1`, `ihr_fee` is always zero.

## Version 12

### Extra message flags and new bounce format
Field `ihr_fee:Tomis` in internal message is now called `extra_flags:(VarUInteger 16)` (it's the same format).
This field does not represent fees. `ihr_fee` is always zero since version 11, so this field was essentially unused.

`(extra_flags & 1) = 1` enables the new bounce format for the message. The bounced message contains information about the transaction.
If `(extra_flags & 3) = 3`, the bounced message contains the whole body of the original message. Otherwise, only the bits from the root of the original body are returned.

All other bits in `extra_flags` are reserved for future use and are not allowed now (internal messages with flags other than `0..3` are invalid).

When the message with new bounce flag is bounced, the bounced message body has the following format (`new_bounce_body`):
```
_ value:CurrencyCollection created_lt:uint64 created_at:uint32 = NewBounceOriginalInfo;
_ gas_used:uint32 vm_steps:uint32 = NewBounceComputePhaseInfo;

new_bounce_body#fffffffe
    original_body:^Cell
    original_info:^NewBounceOriginalInfo
    bounced_by_phase:uint8 exit_code:int32
    compute_phase:(Maybe NewBounceComputePhaseInfo)
    = NewBounceBody;
```
- `original_body` - cell that contains the body of the original message. If `extra_flags & 2` then the whole body is returned, otherwise it is only the root without refs.
- `original_info` - value, lt and unixtime of the original message.
- `bounced_by_phase`:
  - `0` - compute phase was skipped. `exit_code` denotes the skip reason:
    - `exit_code = -1` - no state (account is uninit or frozen, and no state init is present in the message).
    - `exit_code = -2` - bad state (account is uninit or frozen, and state init in the message has the wrong hash).
    - `exit_code = -3` - no gas.
    - `exit_code = -4` - account is suspended.
  - `1` - compute phase failed. `exit_code` is the value from the compute phase.
  - `2` - action phase failed. `exit_code` is the value from the action phase.
- `exit_code` - 32-bit exit code, see above.
- `compute_phase` - exists if it was not skipped (`bounced_by_phase > 0`):
  - `gas_used`, `vm_steps` - same as in `TrComputePhase` of the transaction.

The bounced message has the same 0th and 1st bits in `extra_flags` as the original message.

### New TVM instructions
- `BTOS` (`b - s`) - same as `ENDC CTOS`, but without gas cost for cell creation and loading. Gas cost: `26`.
- `HASHBU` (`b - hash`) - same as `ENDC HASHCU`, but without gas cost for cell creation. Gas cost: `26`.
- `LDSTDADDR` (`s - a s'`) - loads `addr_std$10`, if address is not `addr_std`, throws an error 9 (`cannot load a MsgAddressInt`). Gas cost: `26`.
- `LDSTDADDRQ` (`s - a s' -1 or s 0`) - quiet version of `LDSTDADDR`. Gas cost: `26`.
- `LDOPTSTDADDR` (`s - a s or null s`) - loads `addr_std$10` or `addr_none$00`, if address is `addr_none$00` pushes a Null, if address is not `addr_std` or `addr_none`, throws an error 9 (`cannot load a MsgAddressInt`). Gas cost: `26`.
- `LDOPTSTDADDRQ` (`s - (a s' -1 or null s' -1) or s 0`) - quiet version of `LDOPTSTDADDR`. Gas cost: `26`.
- `STSTDADDR` (`s b - b'`) - stores `addr_std$10`, if address is not `addr_std`, throws an error 9 (`cannot load a MsgAddressInt`). Gas cost: `26`.
- `STSTDADDRQ` (`s b - b' 0 or s b -1`) - quiet version of `STSTDADDR`. Gas cost: `26`.
- `STOPTSTDADDR` (`s b - b'`) - stores `addr_std$10` or Null. Null is stored as `addr_none$00`, if address is not `addr_std`, throws an error 9 (`cannot load a MsgAddressInt`). Gas cost: `26`.
- `STOPTSTDADDRQ` (`s b - b' 0 or s b -1`) - quiet version of `STOPTSTDADDR`. Gas cost: `26`.

### Other TVM changes
- `SENDMSG` instruction treats `extra_flags` field accordingly (see above).

### Other changes
- Account size in masterchain is now limited to `2048` cells. This can be configured in size limits config (`ConfigParam 43`).
  - The previous limit was the same as in basechain (`65536`).

## Version 13

### TVM changes
- Instructions `LSHIFT`, `RSHIFT`, `LSHIFTDIV`, `MULRSHIFT`, `POW2`, `AND`, `OR` now correctly return an error (or `NaN`, if quiet) when one of the arguments is `NaN` (or out of bounds for shifts).

### Transaction changes
- `end_status` of a transaction is now correctly set to `uninit` when the account is frozen with `frozen_hash` equal to its address.
- Message flag `+2` now correctly works when sending fails because of invalid `src` (code `35`), invalid libraries in `StateInit` or invalid mode.
- Fix `fwd_fee` for bounced messages with extra currencies: now extra currency dict is not charged.
- Correctly set `destroyed` flag in transaction when the account is deleted in storage phase.

### Other changes
- Block timestamps are now non-strictly increasing. Block timestamp now can be equal to the timestamp of:
  - Previous block
  - Reference masterchain block
  - Top shard block (in masterchain)

## Version 14

Not yet activated on any TOS network (`ConfigParam 8` stays below `14` until all validators run
binaries that support it). The node binary supports it; see the near-term rollout notes at the
end of this file for the activation plan.

### TVM changes
- `SENDMSG` no longer uses user-provided `fwd_fee` / `ihr_fee` as a lower bound for the returned
  fee estimate of an internal message. This aligns the compute-phase estimate with action-phase
  behavior, which has been ignoring those fields since version 8. Previously a large `fwd_fee`
  written into the message cell could inflate the value returned by `SENDMSG` (and its
  estimate-only mode `+1024`) arbitrarily, while the action phase still charged only the
  recomputed network price.
- `RIST255_MUL` and `RIST255_QMUL` now accept the identity element (integer `0`) and return `0`
  in that case. They also validate point `x` and number `n` on all paths. Previously, libsodium's
  non-zero return code (which it also uses to signal "result is identity") was misinterpreted as
  "invalid x or n".
- `ECRECOVER` now accepts Ethereum legacy recovery bytes `v = 27` and `v = 28`, normalizing them
  to raw recovery ids `0` and `1`.
- `CHKSIGNS` and `CHKSIGNU` now reject the canonical Ed25519 identity public key (`01 00..00`,
  that is, `2^248`) and the zero public key before invoking the verifier and return `false`. The
  check is a fixed 32-byte comparison and does not affect gas. This is directly relevant to the
  native AI-actor contracts (Agent Account, Task Escrow, Proof Attestation), which all use
  `CHKSIGNU` to verify controller/attestor signatures.
- Quiet `RSHIFT`/`MODPOW2` compound opcodes now return `NaN` instead of throwing `range_chk` when
  their stack-provided shift argument is `NaN` or out of range.
- `LSHIFT` and similar invoked with `NaN` return `NaN`, not zero.
- The savelist-writing opcodes `SETCONTCTR`, `SETCONTCTRX`, `SETRETCTR`, `SETALTCTR`, `SAVECTR`,
  `SAVEALTCTR`, `SETCONTCTRMANY`, and `SETCONTCTRMANYX` now silently do nothing when the targeted
  savelist slot is already filled (as required by the TVM whitepaper). Earlier they threw
  `type_chk` in that case.

### Transaction changes
- When the action phase fails with bounce-on-fail, bounce now returns the whole remaining
  message balance from before the action phase, instead of whatever was left after partially
  processed actions.
- TOS-specific (not part of upstream TON's version 14): deploy activation after a StateInit
  message now requires the compute phase to have committed successfully (`success`), rather than
  merely accepted gas (`accepted`). Before version 14, an account could be deployed by a message
  that accepted gas but then threw during compute, matching legacy TON behavior. See
  `compute_phase_can_activate_account` in `crypto/block/transaction.cpp`.

## Version 15

Not yet activated on any TOS network, same as version 14 above.

### Transaction changes
- Libraries:
  - The `change_library` action can only be performed by governance (special) contracts.
  - Private libraries (mode `+1`) can no longer be added at all, by anyone.
  - Private/account libraries (message-init and account-state library cells) are no longer added
    to the TVM library search context; only the global governance-controlled library dictionary
    is available to `CALLREF`/library lookups. `LiteQuery::finish_runSmcMethod` mirrors this for
    read-only get-method calls.
  - An account cannot be deployed (from `acc_uninit`) with a non-null library dictionary in its
    `StateInit`. Unfreezing an existing frozen account with libraries is still allowed.
- When action phase fails, the action fine is now collected for all successful messages processed
  before the failure as well (`ActionPhase::fail_action_fine`), not just the one that failed.
  Closes a way to submit a large batch of actions that partially succeed and then deliberately
  fail the last one to dodge the fine on the successful ones.
- Total bits/cells across all outgoing messages of a transaction are now limited to
  `5242880` bits / `20480` cells (`SizeLimitsConfig` v3, `max_total_msg_bits` /
  `max_total_msg_cells`, configured in `ConfigParam 43`). Older v1/v2 `ConfigParam 43` records
  fall back to these same defaults.

## Capability: capAipow (bit `1024`)

AIPoW native issuance is gated by a capability flag rather than a protocol
version bump, because it toggles a discrete feature (a per-epoch aggregate mint
to the registered AIPoW settlement contract) rather than changing existing
version-gated transaction/VM semantics. `SUPPORTED_VERSION` is therefore
unchanged.

- Defined as `capAipow = 1024` in `tos/tos-types.h`, the next free bit after
  `capFullCollatedData = 512`.
- Node readiness is declared by including it in `Collator::supported_capabilities()`
  and `ValidateQuery::supported_capabilities()`. A binary that declares it will
  accept a configuration that enables the bit; a binary that does not will reject
  such blocks (`collator-node.cpp`) -- so, exactly as for a version bump, every
  validator must run a capable binary before the bit is set in `ConfigParam 8`.
- `block::Config::aipow_enabled()` reads the bit. It is **inert** until a
  governance config vote sets `capAipow` in `ConfigParam 8`; until then the
  entire Phase C mint path is a no-op. Shipping the readiness declaration ahead
  of activation is the "dark scaffolding" step (Phase C, W1).
- Activation follows the same all-validators-first sequence as the versions
  below.

### Mainnet activation gates (do NOT set `capAipow` until all are met)

`capAipow` is inert while unset, so the AIPoW stack ships **dark** with no live
exploit surface. But once the bit is set on a network with value at stake, the
native mint path becomes a token-issuance authority, and several open items make
issuance **forgeable or haltable**. These are hard gates: on mainnet, activation
must be provably blocked until every item below is closed, audited, and
governance-ratified. (They are safe to exercise on a throwaway localnet/testnet
for development.) The blockers were surfaced by the Phase C consensus reviews and
are also tracked in the Phase C plan's launch-gate section.

1. **Commitment finalization provenance — RESOLVED (window floor + C1 address binding).** The
   native path pins a
   registered commitment's **code** hash but cannot, from state alone, prove its
   finalization was legitimate; `window_deadline` is a commitment *deploy
   parameter*, so an attacker could once deploy the audited code with a **past**
   window and a fabricated `(score_root, total_score, organic)` tuple, call
   `finalize` instantly, and mint a forged pool. Fixed by anchoring the challenge
   window to the settlement's own clock, which the committer cannot backdate: the
   commitment now registers at **commit (`announce`)**, not finalize, so the
   settlement records `registered_at` early while the challenge op is open; and
   the native path authorizes a candidate only when its `window_deadline >=
   registered_at + challenge_window` (the window was demonstrably open) **and**
   `gen_utime >= registered_at + challenge_window` (it has elapsed). A fabricated
   commitment must therefore sit through a real, observable dispute window and can
   no longer be finalized instantly. See `derive_masterchain_epoch_mint` in
   `crypto/block/aipow.cpp` and the commitment FunC `announce` handler. The
   challenge window is now a **governed settlement deploy parameter**
   (`SettlementCursor::challenge_window`, read by the native path; the SDK
   `build_data` enforces `0 < challenge_window < register_grace` so a valid
   candidate always mints before its epoch becomes skippable);
   `kAipowChallengeWindow` is only the recommended SDK default. **But a codex review
   found a deeper hole (C1):** on an account model with `SETCODE`, checking only the
   *current* code hash + data does not prove the account followed the bonded state
   machine. A bootstrap contract can `register`, then `SETCODE` to the audited
   commitment code and overwrite its data with a forged `final` state (matching
   tuple/reviewer/methodology/window) — no bond was ever locked and no challengeable
   `committed` state existed; the reviewer/methodology checks do not help (the forged
   data simply names the approved values). **Fixed:** the native derivation now binds
   the commitment account's address to a canonical `StateInit` — it verifies
   `account_id == hash(StateInit(audited_code, reconstructed initial data))`, where the
   audited code is the account's own current code (already proven equal to the registry
   hash) and the initial data is the current data with the four mutable fields reset to
   their deploy defaults. An account deployed with different (SETCODE-capable) initial
   code has a different, deploy-fixed address and is rejected; the audited commitment
   code has no `SETCODE`, so a canonically-addressed account can only follow the real
   bonded state machine. No registry/config change was needed (the code cell comes from
   the account itself). See `commitment_canonical_address` +
   `derive_masterchain_epoch_mint` in `crypto/block/aipow.cpp`, a dedicated C1 cell-test
   regression, and the full-node e2e (which proves the reconstruction matches the
   commitment SDK's deploy `build_data` byte for byte). The H1 Sybil admission DoS (a
   related follow-up: require registration's sender to be a canonically-addressed
   commitment) remains open but is not a supply-safety hole. Details + the full
   codex-findings ledger (C1/C2/H1-H4/M1-M3/L1-L2) are in the Phase C design doc.
2. **First-wins registration griefing — RESOLVED.** `register` was once
   first-wins per epoch, letting an attacker's bogus nomination block the genuine
   commitment and freeze the cursor. Now the settlement keeps a **bounded
   candidate set** per epoch (retaining the smallest addresses), `skip` advances
   past the grace deadline regardless of candidates, and the native path selects
   the **min-address valid** finalized commitment — so a bogus nomination can
   neither exclude the genuine commitment nor freeze the cursor. The
   address-grindable min-address tie-break is safe only because gate 1 now forces
   every candidate through a real, elapsed challenge window before selection.
3. **Threshold reviewer policy — code RESOLVED; governance deployment remains.**
   Once `status == final` authorizes native issuance, whoever can force `final`
   controls minting, and a committer could name a reviewer it controls to dismiss
   any challenge. The native path now **anchors** the reviewer: `AipowRegistry`
   (ConfigParam 93) carries a governance-approved `reviewer_addr`, and
   `derive_masterchain_epoch_mint` authorizes a commitment only if its own reviewer
   equals that masterchain account id (`check_aipow_config` requires it set, so
   `capAipow` cannot activate without it). The commitment's `rule` op already
   requires `sender == reviewer`, so registering a real **M-of-N multisig** as
   `reviewer_addr` makes M-of-N agreement necessary to rule — the multisig enforces
   the threshold, the native enforces provenance. **Remaining before activation:**
   governance must deploy the actual threshold multisig and register its address
   (this is part of gate 5's registry ratification); a single-key reviewer stays
   devnet/testnet only.
4. **Audits.** A dedicated audit + red-team of the **settlement contract**
   (custody, replay, double-pay, beneficiary-auth bypass) and the **consensus
   mint math** (per-epoch once-only, cap bypass, collator/validator divergence,
   unregistered-address mint), plus the mint-math determinism audit.
5. **Registry published and ratified.** `AipowRegistry` (ConfigParam 93) —
   settlement address, the audited **commitment code hash**, audited distributor
   code hashes, methodology and rate-card hashes — must be published and
   governance-ratified, and the configured settlement account's stored
   `total_cap` verified to equal ConfigParam 92 (`AipowLimits.total_cap`) at
   activation. The AIPoW ConfigParams (90–93) ship **absent** at genesis; a
   partial or inconsistent set is a hard config error once `capAipow` is set.
6. **Supply-cap dry-run.** A dry-run over a simulated ~7-year schedule shows
   cumulative emission ≤ the 4.5B cap under adversarial demand.

**End-to-end verified (not a gate, a milestone).** The native mint produce/check
paths and the settle round-trip are exercised on a full-node localnet with
`capAipow` active and ConfigParams 90–93 injected at genesis
(`scripts/aipow-native-mint-e2e.py`): a commitment is announced → finalized past
its (seconds-long, test-tuned) challenge window → the masterchain collator
originates the epoch mint → validate-query independently re-derives and accepts it
→ the settlement's settle advances the cursor, records the mint, and funds a
distributor; a later block mints 0 and the cap holds. This run caught and fixed a
real produce/check divergence (validate-query must split `value_flow_.minted` by
currency type exactly as the collator does) — evidence that gate 4's
collator/validator-divergence review is grounded, not a formality. The formal
audits in gate 4 still stand.

Gate 2 is resolved in code; gate 3's native anchor is done (its residue is
operational — governance deploys/registers the real threshold multisig, folded into
gate 5). Gate 1 is only PARTIALLY resolved: a codex review reopened it (**C1**,
above) and surfaced a second Critical (**C2**: base grams were counted in
`value_flow_.minted` before the settle transaction, and validation never required the
settle to succeed — so a settle that throws/out-of-gas/bounces, or is preempted by an
in-block `skip`, creates supply the settlement ledger never records, permitting
re-mint of one epoch and issuance past the cap).

**C2's safety half is now resolved in code + e2e.** validate-query ties base-gram
issuance to the settlement's own ledger: it requires the settlement account's
`minted_total` to advance, between the previous and new state, by exactly the
re-derived mint amount, and rejects (fail closed) otherwise — so a settle that fails
to record the mint halts issuance instead of leaking uncounted, cap-bypassing,
re-mintable supply. The full-node native-mint e2e passes with the guard active (mint
fires, `minted_total == pool`, cursor advances). What remains for C2 is the
*liveness* half — the collator should not emit the mint unless the settle will record
it (derive from post-dispatch state + fund the settle), so the fail-closed guard does
not merely stall a bad-config/attacked epoch; that is a follow-up, not a safety hole.

**C1 is now resolved in code + e2e** (canonical-address binding in
`derive_masterchain_epoch_mint`; the account's own current code — proven equal to the
registry hash — supplies the audited code cell, so no registry/ConfigParam-93 change
was needed; a dedicated cell regression plus the full-node e2e confirm genuine
commitments mint and non-canonical ones do not). The native-only robustness batch
M1/M2/L1 is fixed in code, as is the settlement-contract robustness batch H4/H3/L2
(bounded registration horizon + pruning of settled/skipped epoch buckets; exact-pool
forward to the distributor; uint32 cursor-wrap guard — all sandbox-tested and
e2e-verified). C2's *liveness* half is also resolved: the collator drops a mint that
a same-block skip preempted (re-reading only the live cursor, so winner selection
stays consistent) and validate-query accepts that as a legitimate no-mint (cursor
advanced, minted_total unchanged) while still rejecting a causeless withhold, so the
skip-race no longer stalls the chain; the only remaining fail-closed stall is the
operational underfunded-settlement case (a gate-5 funding concern).

**H1 (Sybil admission) is mitigated in code + e2e.** Registration is now
authenticated: the settlement stores the audited commitment code and admits a
candidate only if `sender == hash(StateInit(commitment_code, presented_data))`, so
plain wallets can no longer occupy candidate slots and evict a genuine commitment;
the native derivation cross-checks the settlement's stored code against the registry
hash. This is not a full economic close — an attacker can still deploy the audited
commitment code with throwaway data to grind small canonical addresses, so a minimum
registration bond is the economic deterrent — **now added (H1 economic close):** the
settlement requires every register to lock `MIN_REGISTRATION_BOND` (0.5 TOS,
non-refundable, funding its own gas + forward reserve), so grinding the 8 smallest
addresses costs at least 8× the bond per epoch. **H2 (late-candidate skip race) is
also fixed:** the provenance window is anchored to announce time while the skip
deadline is anchored to the epoch boundary + grace, so a late nomination could be
skipped while still inside its window; registration now rejects a nomination whose
challenge window cannot elapse before the epoch is skippable
(`now()+challenge_window ≤ (epoch+1)·epoch_seconds+register_grace`), so skip never
preempts an in-window candidate. **M3 was assessed and is not a bug:** the settle is a
mandatory special transaction whose bounded gas is intentionally not counted toward the
block limit (like recover/mint) — special transactions run after the main tx loop, so
counting their gas would risk a full block being unable to fit a mandatory settle; the
compute phase is still normally gas-limited (the settlement is not a config-special
account) so its gas is bounded, and the collator and validate-query use identical logic
(no divergence). With the whole codex-findings ledger closed or assessed, what remains
before mainnet activation is only **gates 3-6** — governance/operational actions (deploy
the real threshold multisig, cap-consistency check, supply-cap dry-run), not code. Until
those are closed, native AIPoW minting is **testnet/devnet only** and must remain
unactivatable on mainnet.

### Mainnet activation runbook (governance)

The gates above say *what* must be true; this is the ordered *how*. Every step is
backed by a native fail-closed guard (noted inline), so a misconfiguration halts
issuance rather than mis-mints — but governance must still perform and verify each
step, in this order, before `capAipow` is set. All of this is safe to rehearse on a
throwaway testnet first (that is what `scripts/aipow-native-mint-e2e.py` automates in
miniature).

1. **Finish gate 4 (audits).** Complete the external audit + red-team of the
   settlement/commitment/distributor contracts and the consensus mint math
   (per-epoch once-only, cap, collator/validator divergence, custody/replay). Do not
   proceed until sign-off. Code freeze the audited artifacts.

2. **Deploy the reviewer multisig (gate 3).** Deploy the real **M-of-N threshold
   multisig** that will govern challenge resolution. Record its masterchain account
   id; it becomes `AipowRegistry.reviewer_addr`. A single-key reviewer is
   testnet-only.

3. **Deploy the settlement account.** Deploy the audited settlement code with
   `build_data`: `challenge_window < register_grace` (SDK-enforced, and native M1
   re-checks), `total_cap` = the intended supply cap, `distributor_code` = the audited
   distributor code, `commitment_code` = the audited commitment code (H1 auth; the
   native cross-checks its hash against the registry). Record the resulting settlement
   address; it becomes `AipowRegistry.settlement_addr`.

4. **Publish + ratify ConfigParams 90–93 (gate 5).** They ship **absent** at genesis;
   a partial or inconsistent set is a hard config error the activation guard
   (`check_aipow_config`) rejects once `capAipow` is set. Set, and governance-ratify:
   - **ConfigParam 90 — `AipowConfig`:** the pool formula (`k_num/k_den`,
     `schedule_cap`, `cold_start_floor`, challenge multiplier).
   - **ConfigParam 91 — `AipowMaturation`:** the distributor maturation snapshot
     (`immediate_bps`, `stream_epochs`, `mat_epoch_seconds`) — must equal what the
     settlement was deployed with.
   - **ConfigParam 92 — `AipowLimits`:** `total_cap` (the ~4.5B cap).
   - **ConfigParam 93 — `AipowRegistry`:** `settlement_addr` (step 3),
     `commitment_code_hash` (the audited commitment code every real commitment runs),
     `reviewer_addr` (step 2's multisig), `methodology_hash`, `rate_card_hash`, and the
     audited `distributor_code_hashes`.

5. **Pre-flight consistency checks (do before flipping the bit).** Each is also a
   native fail-closed guard, so an error blocks issuance — verify them up front anyway:
   - settlement's stored `total_cap` **==** ConfigParam 92 `total_cap` (gate 5).
   - settlement's stored `commitment_code` hash **==** ConfigParam 93
     `commitment_code_hash` (native cross-check; else derive fails closed).
   - settlement's `challenge_window` **<** `register_grace` (native M1).
   - ConfigParam 93 `reviewer_addr` **==** the deployed multisig, and every genuine
     commitment's own `reviewer` equals it (native gate-3 anchor; the commitment `rule`
     op requires `sender == reviewer`).
   - ConfigParam 93 `settlement_addr` **==** the deployed settlement, and
     `commitment_code_hash` **==** the code the deployed commitments actually run
     (else C1 address binding rejects them).

6. **Supply-cap dry-run (gate 6).** Simulate the ~7-year emission schedule under
   adversarial demand and confirm cumulative emission ≤ the cap (the native clamps
   each pool to the remaining cap and terminates at exhaustion; the dry-run confirms
   the schedule as a whole).

7. **Activate, all-validators-first.** Only now set `capAipow` (bit `1024`) in
   ConfigParam 8, following the same sequence as the version Rollout plan below: every
   validator must run a binary that supports the AIPoW path before the bit is set, or
   validators would diverge. If any ConfigParam 90–93 is missing or inconsistent when
   the bit is set, `check_aipow_config` makes the block invalid — activation is blocked
   at the config-install level, not silently mis-minted.

8. **Post-activation.** Monitor the first epochs: the settlement `minted_total`
   advances by exactly each derived pool, the cursor advances once per settled epoch,
   and cumulative issuance stays under the cap. Keep the reviewer multisig keys and the
   settlement's gas/forward reserve funded (an underfunded settle fails closed and
   halts issuance until refunded).

## Rollout plan

Enabling version 14/15 on a live TOS network is a consensus-level change and must not be done by
simply bumping `SUPPORTED_VERSION` on a subset of nodes -- that would let different validators
compute different results for the same transaction and fork the chain. The safe sequence:

1. Ship a node binary that supports version 15 (this is what `SUPPORTED_VERSION = 15` means --
   the ceiling this binary is capable of executing), while `ConfigParam 8` on every live network
   stays at its current active version.
2. Get every validator upgraded to a binary that supports the new version before touching
   `ConfigParam 8`.
3. Activate version 14 first via `ConfigParam 8` once all validators are upgraded; observe
   stability.
4. Activate version 15 only after 14 has been stable for a period, following the same
   all-validators-first rule.
5. Mainnet activation happens last, after both versions have proven stable on a public testnet.
