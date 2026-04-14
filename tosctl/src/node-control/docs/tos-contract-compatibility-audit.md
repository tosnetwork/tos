# TOS Contract Compatibility Audit

This document audits all wallet, elector, and nominator contract code for TOS-specific assumptions
and assesses compatibility with TOS deployment.

---

## 1. Wallet Contracts

### 1.1 Hard-coded Code Cells

| Constant | File | Line | Format | Description |
|----------|------|------|--------|-------------|
| `V1R3_CODE` | `contracts/src/wallet/wallet_contract.rs` | 19 | hex | Wallet V1R3 bytecode |
| `V3R2_CODE` | `contracts/src/wallet/wallet_contract.rs` | 21 | hex | Wallet V3R2 bytecode |
| `V4R2_CODE_B64` | `contracts/src/wallet/wallet_contract.rs` | 23 | base64 | Wallet V4R2 bytecode |
| `V5R1_CODE_B64` | `contracts/src/wallet/wallet_contract.rs` | 35 | base64 | Wallet V5R1 bytecode |

**Known Hashes (from tests):**
- V3R2: `84dafa449f98a6987789ba232358072bc0f76dc4524002a5d0918b9a75d2d599`
- V4R2: `feb5ff6820e2ff0d9483e7e0d62c817d846789fb4ae580c878866d959dabd5c0`
- V5R1: `20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f`

**Compatibility Assessment: Needs verification**

These are standard TOS wallet contract bytecodes. If TOS uses the same TVM and accepts the same
wallet contracts (which is expected since TOS is a TOS fork), these should work unmodified. However,
they must be verified against the actual TOS genesis/system contracts to confirm deployment is possible.

**Required Action:**
- Verify that TOS network accepts these wallet code cells for deployment
- Confirm that address derivation produces valid addresses on TOS
- If TOS introduces new wallet versions, add them to the `WalletVersion` enum

### 1.2 Wallet Version Enum

| Item | File | Line | Status |
|------|------|------|--------|
| `WalletVersion` enum (V1R3, V3R2, V4R2, V5R1) | `common/src/wallet_version.rs` | 16-21 | TOS-compatible |
| `TonWalletVersion` type alias | `common/src/wallet_version.rs` | 24 | TOS-compatible (backward compat) |

**Compatibility Assessment: TOS-compatible**

The wallet versions are protocol-level constructs that should be identical on TOS. The enum has been
renamed to `WalletVersion` with a backward-compatible `TonWalletVersion` alias.

### 1.3 Wallet Message Layout

| Item | File | Line | Description |
|------|------|------|-------------|
| `SEND_MODE = 3` | `wallet_contract.rs` | 48 | Standard send mode |
| `V4_OP_SIMPLE_SEND = 0` | `wallet_contract.rs` | 49 | V4 opcode |
| `LIFETIME = 120` | `wallet_contract.rs` | 59 | Message TTL (2 minutes) |
| `V5_PREFIX_SIGNED_EXTERNAL = 0x7369_676e` | `wallet_contract.rs` | 60 | V5 signature prefix |
| Subwallet ID `698983191` | `wallet_contract.rs` | 424-446 (tests) | Default TOS subwallet ID |

**Compatibility Assessment: TOS-compatible**

These are ABI-level constants defined by the wallet contract code itself (not by the network).
Since the same wallet bytecode is used, these values remain correct.

**Required Action:**
- If TOS defines a different default subwallet ID, update test constants
- The subwallet ID `698983191` (0x29A9A317) is the TOS mainnet default; TOS may use a different value

---

## 2. Elector Contract

### 2.1 Hard-coded Addresses

| Constant | File | Line | Value |
|----------|------|------|-------|
| `elector_addr` | `contracts/src/elector/elector_impl.rs` | 27 | `-1:3333333333333333333333333333333333333333333333333333333333333333` |

**Compatibility Assessment: Needs verification**

The elector address `-1:3333...` is a well-known system contract address on TOS. TOS, as a fork,
is expected to preserve this convention, but it must be confirmed.

**Required Action:**
- Verify TOS uses the same elector address
- If different, make the address configurable (constructor parameter or config)

### 2.2 Get Methods Called

| Method | File | Line | Purpose |
|--------|------|------|---------|
| `active_election_id` | `elector_impl.rs` | 47 | Get current election ID |
| `participates_in` | `elector_impl.rs` | 62 | Check if pubkey participates |
| `compute_returned_stake` | `elector_impl.rs` | 76 | Get stake amount to return |
| `participant_list_extended` | `elector_impl.rs` | 84 | Full election info |
| `past_elections` | `elector_impl.rs` | 128 | Historical election data |

**Compatibility Assessment: Needs verification**

These get-methods are part of the elector contract ABI. If TOS uses the same elector contract code
(expected for a fork), these will work. If TOS modifies the elector, the ABI must be re-verified.

### 2.3 Data Structures

| Struct | File | Fields |
|--------|------|--------|
| `Participant` | `elector/wrapper.rs` | pub_key, adnl_addr, wallet_addr, stake, max_factor, election_id |
| `ElectionsInfo` | `elector/wrapper.rs` | election_id, elect_close, min_stake, total_stake, failed, finished, participants |
| `FrozenParticipant` | `elector/wrapper.rs` | wallet_addr, weight, stake, banned |
| `PastElections` | `elector/wrapper.rs` | election_id, unfreeze_at, stake_held, vset_hash, frozen_map, total_stake, bonuses |

**Compatibility Assessment: Needs verification**

These structures mirror the elector contract's internal data layout. Any changes to the TOS elector
would require corresponding updates.

---

## 3. Nominator Contract

### 3.1 Hard-coded Code Cells

| Constant | File | Line | Description |
|----------|------|------|-------------|
| `CODE_V1_1` | `contracts/src/nominator/single_nominator.rs` | 20 | Single-nominator contract v1.1 bytecode |
| `NOMINATOR_POOL_WORKCHAIN = -1` | `contracts/src/nominator/single_nominator.rs` | 21 | Masterchain workchain ID |

**Compatibility Assessment: Needs verification**

The single-nominator contract is a standard contract from `single-nominator contract` repo.
TOS should support deploying this contract, but it needs testing.

**Required Action:**
- Test deployment of single-nominator contract on TOS testnet
- Verify that nominator contract interactions with the elector work on TOS

### 3.2 Opcodes

| Opcode | Name | Value | File | Line |
|--------|------|-------|------|------|
| `WITHDRAW` | Withdraw funds | `0x1000` | `nominator/messages.rs` | 14 |
| `CHANGE_VALIDATOR_ADDRESS` | Change validator | `0x1001` | `nominator/messages.rs` | 16 |
| `SEND_RAW_MSG` | Send raw message | `0x7702` | `nominator/messages.rs` | 18 |
| `UPGRADE` | Upgrade contract | `0x9903` | `nominator/messages.rs` | 20 |
| `NEW_STAKE` | New stake to elector | `0x4e73744b` | `nominator/messages.rs` | 22 |
| `RECOVER_STAKE` | Recover from elector | `0x47657424` | `nominator/messages.rs` | 24 |

**Compatibility Assessment: TOS-compatible**

These opcodes are defined by the nominator contract itself (CODE_V1_1), not by the network.
As long as the same contract bytecode is deployed, these opcodes are correct.

### 3.3 Get Methods Called

| Method | File | Purpose |
|--------|------|---------|
| `get_roles` | `single_nominator.rs` | Get owner + validator addresses |
| `get_pool_data` | `single_nominator.rs` | Get full pool state |

**Compatibility Assessment: TOS-compatible**

These are ABI methods of the deployed nominator contract code, not network-level calls.

---

## 4. Config Params

### 4.1 Parameters Used

| Param # | Parser Function | File | Purpose |
|---------|----------------|------|---------|
| 15 | `parse_config_param_15` | `control-client/src/config_params.rs` | Election timing parameters |
| 34 | `parse_config_param_34` | `control-client/src/config_params.rs` | Current validator set |
| 36 | `parse_config_param_36` | `control-client/src/config_params.rs` | Next validator set |

**Config Param 15 Fields:**
- `validators_elected_for` — duration validators serve
- `elections_start_before` — when elections open before end of current round
- `elections_end_before` — when elections close
- `stake_held_for` — how long stake is frozen after round

**Config Params 34/36 Fields:**
- `utime_since`, `utime_until` — validity period
- `main` — number of main validators
- `list[]` — validator descriptors (public_key, weight_dec, adnl_addr)

**Compatibility Assessment: Needs verification**

Config params 15, 34, and 36 are fundamental to TOS's proof-of-stake mechanism. TOS as a fork
should preserve these parameters with the same structure, but values will differ.

**Required Action:**
- Verify TOS config param numbers match (15, 34, 36)
- Verify JSON structure returned by TOS RPC matches expected format
- TOS may have different timing values — this is expected and handled by the code

---

## 5. Provider Layer

### 5.1 ContractProvider

| Item | File | Description |
|------|------|-------------|
| `ContractProvider` trait | `contracts/src/provider.rs` | RPC abstraction for get_method + balance |
| `ContractProviderImpl` | `contracts/src/provider.rs` | Implementation using `ClientJsonRpc` |

**Compatibility Assessment: TOS-compatible**

The provider is a thin wrapper around JSON-RPC calls (`runGetMethod`, `getAddressInformation`).
These are standard TOS HTTP API methods. TOS should expose the same API.

**Required Action:**
- Verify TOS HTTP API supports `runGetMethod` and `getAddressInformation`
- Ensure TOS RPC response format matches expected structure

---

## 6. Summary Risk Assessment

### High Risk (Must verify before TOS deployment)
1. **Elector address** (`-1:3333...`) — if TOS uses a different address, elections will fail
2. **Wallet code cells** — if TOS rejects standard wallet bytecode, no wallets can be deployed
3. **Config params 15/34/36** — if structure differs, election timing will be miscalculated

### Medium Risk (Should verify)
4. **Single-nominator contract deployment** — must test on TOS testnet
5. **Default subwallet ID** — TOS may use a different default
6. **Elector get-method ABI** — if TOS modifies elector, parsing will break

### Low Risk (Likely compatible)
7. **Wallet message layout** — defined by wallet contract code, not network
8. **Nominator opcodes** — defined by nominator contract code, not network
9. **Provider layer** — standard JSON-RPC interface

### Recommendation
Before TOS mainnet deployment:
1. Deploy and test all wallet versions (V1R3, V3R2, V4R2, V5R1) on TOS testnet
2. Confirm elector address and get-method ABI on TOS
3. Test full election cycle with single-nominator contract on TOS
4. Verify config param structure and values on TOS testnet

---

## 7. Changes Made in This Phase

| File | Change | Purpose |
|------|--------|---------|
| `common/src/wallet_version.rs` | Renamed `TonWalletVersion` -> `WalletVersion` with type alias | Network-agnostic naming |
| `common/src/wallet_version.rs` | Renamed `ParseTonWalletVersionError` -> `ParseWalletVersionError` with type alias | Network-agnostic naming |
| `common/src/wallet_version.rs` | Updated error message from "TON wallet version" to "wallet version" | Network-agnostic user-facing text |
| `common/src/lib.rs` | Export both `WalletVersion` and `TonWalletVersion` | Backward compatibility |
| `contracts/src/wallet.rs` | Renamed `TonWallet` trait -> `Wallet` with re-export alias | Network-agnostic naming |
| `contracts/src/lib.rs` | Export both `Wallet` and `TonWallet` | Backward compatibility |
| `contracts/src/wallet/wallet_contract.rs` | Added TOS compatibility comments on code cells | Documentation |
| `contracts/src/wallet/wallet_contract.rs` | Updated impl to use `Wallet` trait name | Consistency |
| `contracts/src/elector/elector_impl.rs` | Added TOS compatibility comment on elector address | Documentation |
| `contracts/src/nominator/single_nominator.rs` | Added TOS compatibility comment on contract code | Documentation |
| `contracts/src/nominator/wrapper.rs` | Updated doc comment to be network-agnostic | Documentation |
