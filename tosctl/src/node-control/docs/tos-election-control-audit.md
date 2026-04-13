# TOS Election & Control Plane Compatibility Audit

## Overview

This document audits the election automation system and control client for TOS
(The Open Source) network compatibility. The codebase was originally built for
TON (The Open Network) and is being adapted for TOS.

---

## 1. Election Flow Analysis

### Step-by-step flow as implemented

| # | Step | Code Location | Description |
|---|------|---------------|-------------|
| 1 | **Tick loop starts** | `runner.rs:run_loop()` | A periodic timer fires every `tick_interval` seconds. |
| 2 | **Refresh validator sets** | `runner.rs:refresh_validator_set()`, `refresh_next_validator_set()` | Fetches config param 34 (current vset) and param 36 (next vset) from any available node. |
| 3 | **Refresh validator configs** | `runner.rs:refresh_validator_configs()` | Fetches the local engine validator config from each node via ADNL control interface. |
| 4 | **Get election parameters** | `runner.rs:election_parameters()` | Fetches config param 15 (election timing parameters). |
| 5 | **Get active election ID** | `runner.rs:run()` via `elector.get_active_election_id()` | Queries the elector smart contract for open elections. If 0, no elections are active. |
| 6 | **Fetch elections info** | `elector.elections_info()` | Gets close time, min_stake, total_stake, participants list from elector. |
| 7 | **Recover stake** | `runner.rs:recover_stake()` | For each node, checks `compute_returned_stake` on elector; sends recover message if amount > 0. |
| 8 | **Participate** | `runner.rs:participate()` | For each non-excluded node with no pending recovery: find/create validator key, build stake payload, send stake message. |
| 9 | **Generate validator key** | `providers/default.rs:new_validator_key()` | If no key exists for the election: generate keypair, add permanent key, add temp key via ADNL. |
| 10 | **Generate ADNL address** | `providers/default.rs:new_adnl_addr()` | Generate new keypair, register as ADNL address (category 0), associate with validator key. |
| 11 | **Build stake payload** | `runner.rs:build_new_stake_payload()` | Constructs `validator-elect-req` message: magic `0x654C5074`, election_id, max_factor, wallet_addr, adnl_addr. Signs with validator key. |
| 12 | **Send stake** | `runner.rs:send_stake()` | Constructs external message via wallet (or pool), sends BOC via ADNL lite_server.sendMessage. |
| 13 | **Publish snapshot** | `runner.rs:publish_snapshot()` | Updates in-memory snapshot store with election/validator status for HTTP API. |
| 14 | **Binding status callback** | `runner.rs:run_loop()` | Reports binding status changes to the service for config persistence. |

### TON-specific assumptions at each step

| Step | Assumption | Risk Level |
|------|-----------|------------|
| 2 | Config params 34/36 use TON validator set format (`ValidatorSet` with `utime_since`, `utime_until`, `main`, `list`) | **Low** - TOS inherits same config param structure |
| 4 | Config param 15 uses TON format (`validators_elected_for`, `elections_start_before`, `elections_end_before`, `stake_held_for`) | **Low** - TOS inherits same structure |
| 5 | Elector contract at standard address with `get_active_election_id` getter | **Medium** - TOS must deploy compatible elector |
| 6 | Elector `elections_info` getter returns `ElectionsInfo` struct | **Medium** - Same elector contract dependency |
| 7 | Elector `compute_returned_stake` getter and recover message format | **Medium** - Same elector contract dependency |
| 8-10 | ADNL control protocol for key management (TON validator engine protocol) | **Low** - TOS node uses same engine |
| 11 | Stake message magic `0x654C5074` and payload format matches elector ABI | **High** - Must match TOS elector exactly |
| 12 | BOC format and wallet message construction are TON-standard | **Low** - TOS uses same BOC/cell format |

### TOS Compatibility Assessment

- **COMPATIBLE**: Steps 1-4, 8-10, 12-14 use infrastructure-level protocols that TOS inherits directly from TON.
- **REQUIRES VERIFICATION**: Steps 5-7, 11 depend on the elector smart contract interface. TOS must deploy an elector contract with the same ABI or these steps need adaptation.
- **KEY RISK**: The election stake message magic (`0x654C5074`) and elector getters must be identical on TOS.

---

## 2. Control Client Analysis

### All control commands used

| Command | TL Schema | Purpose | File |
|---------|-----------|---------|------|
| `GetShardAccountState` | `raw.getShardAccountState` | Fetch account state (balance, data) | `client_adnl.rs` |
| `GetConfigAll` | `lite_server.getConfigAll` | Fetch full blockchain config | `client_adnl.rs` |
| `GetConfig` | `engine.validator.getConfig` | Fetch local engine validator config (keys, ADNL addrs) | `client_adnl.rs` |
| `GetConfigParams` | `lite_server.getConfigParams` | Fetch specific config params (15, 34, 36) | `client_adnl.rs` |
| `Sign` | `engine.validator.sign` | Sign data with a validator key | `client_adnl.rs` |
| `GenerateKeyPair` | `engine.validator.generateKeyPair` | Generate new Ed25519 keypair | `client_adnl.rs` |
| `ExportPublicKey` | `engine.validator.exportPublicKey` | Export public key by key hash | `client_adnl.rs` |
| `AddValidatorPermanentKey` | `engine.validator.addValidatorPermanentKey` | Register permanent validator key | `client_adnl.rs` |
| `AddValidatorTempKey` | `engine.validator.addValidatorTempKey` | Register temp validator key | `client_adnl.rs` |
| `AddAdnlId` | `engine.validator.addAdnlId` | Register ADNL address | `client_adnl.rs` |
| `AddValidatorAdnlAddress` | `engine.validator.addValidatorAdnlAddress` | Associate ADNL addr with validator key | `client_adnl.rs` |
| `SendMessage` | `lite_server.sendMessage` | Broadcast external message (BOC) | `client_adnl.rs` |

### ADNL Protocol Assumptions

1. **Transport**: Uses ADNL TCP client with Ed25519 handshake to connect to the validator engine control port.
2. **Framing**: TL-serialized requests wrapped in `engine.validator.controlQuery`.
3. **Authentication**: Server key (from config) is used for ADNL handshake authentication.
4. **Reconnection**: Auto-reconnects on failure, up to `max_rq_attempts` (default: 4).
5. **Error handling**: Responses are either success objects or `engine.validator.controlQueryError`.

### TOS Compatibility Assessment

- **FULLY COMPATIBLE**: The TOS node uses the same ADNL control interface, same TL schema, same engine.validator.* RPC methods.
- **No changes required** to the control client for TOS deployment.
- The `AdnlClient` and `AdnlClientConfig` from the `adnl` crate handle the transport layer identically.

---

## 3. Config Param Analysis

### All config params referenced

| Param | Field | Controls | Used In | TOS Status |
|-------|-------|----------|---------|------------|
| **15** | `validators_elected_for` | Duration validators serve (seconds) | Election cycle calculation | Compatible |
| **15** | `elections_start_before` | How early elections open before validation ends | Election window timing | Compatible |
| **15** | `elections_end_before` | How early elections close before validation starts | Election close timing | Compatible |
| **15** | `stake_held_for` | How long stake remains locked after validation | Stake lifecycle | Compatible |
| **34** | Current validator set | `utime_since`, `utime_until`, `main`, validator list (pubkey, weight, adnl_addr) | Active validator check, binding status | Compatible |
| **36** | Next validator set | Same structure as p34, represents elected-but-not-yet-active validators | Next-cycle elected check | Compatible |

### Config Param Format Details

- **Param 15**: Parsed from JSON with key `p15` containing timing fields as integers.
- **Param 34**: Parsed from JSON with key `p34` containing `utime_since`, `utime_until`, `total`, `main`, and `list` array of validators.
- **Param 36**: Same format as p34, key `p36`. May not exist if no election has concluded.

### TOS Compatibility Status

All config params use the same numeric IDs and data format on TOS as on TON. The parsing logic in `config_params.rs` is fully compatible.

---

## 4. Snapshot/Status Analysis

### Lifecycle States Defined

#### ElectionsStatus (global election state)
| State | Meaning |
|-------|---------|
| `Closed` | No active elections (election_id == 0) |
| `Finished` | Elections completed, winners determined |
| `Failed` | Elections marked as failed by elector |
| `Postponed` | Elections past close time but not finalized |
| `Active` | Elections open and accepting stakes |

#### ParticipationStatus (per-node lifecycle)
| State | Meaning | Transition |
|-------|---------|-----------|
| `Idle` | Not participating | Initial state |
| `Participating` | Key generated, preparing stake | After key creation |
| `Submitted` | Stake sent to elector | After send_stake() |
| `Accepted` | Stake confirmed in elector participants | After elector confirms |
| `Elected` | Node in next validator set (p36) | After election concludes |
| `Validating` | Node in current validator set (p34) | After round starts |

#### BindingStatus (operational status)
| State | Meaning |
|-------|---------|
| `Idle` | No activity |
| `Participating` | Actively trying to join elections |
| `Validating` | Currently in validator set |
| `Draining` | Recovering stake (excluded or post-validation) |

### Dependencies on Config Params

- **ElectionsStatus**: Depends on elector contract state (not config params directly).
- **ParticipationStatus**: Transitions depend on p34 (is_validator) and p36 (is_next_validator).
- **BindingStatus**: `Validating` requires being in p34 validator set.
- **TimeRange calculations**: `next_elections_range` uses p15 timing + p34 `utime_until`.
- **Validation range**: Directly from p34 `utime_since`/`utime_until`.

---

## 5. Critical Risks for TOS Deployment

### High Risk
1. **Elector contract compatibility** - The election automation depends on the elector contract having identical getters (`active_election_id`, `participant_list_extended`, `compute_returned_stake`, `past_elections`) and accepting the same stake message format (magic `0x654C5074`).

### Medium Risk
2. **Elector address** - The elector address must be configured correctly for TOS. The code obtains it from `ElectorWrapper` which is initialized from config.
3. **Nominator pool contracts** - If TOS uses different nominator pool contracts, the `new_stake` and `recover_stake` message formats in the `contracts` crate may need adaptation.

### Low Risk
4. **Config param format** - Minor JSON structure differences could break parsing (unlikely as TOS inherits TON format).
5. **ADNL protocol** - TOS uses the same ADNL stack; no incompatibilities expected.
6. **BOC/Cell encoding** - Standard across TON/TOS.

---

## 6. Files Audited

- `elections/Cargo.toml`
- `elections/src/lib.rs`
- `elections/src/election_task.rs`
- `elections/src/runner.rs` (full, 1288 lines)
- `elections/src/runner_tests.rs`
- `elections/src/providers/mod.rs`
- `elections/src/providers/traits.rs`
- `elections/src/providers/default.rs`
- `control-client/Cargo.toml`
- `control-client/src/lib.rs`
- `control-client/src/client_api.rs`
- `control-client/src/client_adnl.rs`
- `control-client/src/config_params.rs`
- `common/src/snapshot.rs`
- `service/src/service_main_task.rs`
- `service/src/task/mod.rs`
- `service/src/task/task_manager.rs`

---

## 7. Recommendations

1. **Validate elector contract ABI** on TOS testnet before enabling election automation.
2. **Test config param fetching** (15, 34, 36) against a TOS node to confirm JSON format matches.
3. **Verify nominator pool compatibility** if using pool-based staking on TOS.
4. **Monitor the `0x654C5074` stake message** format for any TOS-specific changes.
5. **Keep the election runner as-is** -- the protocol logic is sound and compatible.
