# TOS Control Plane Compatibility

**Date:** 2026-04-12  
**Status:** Active  
**Scope:** `control-client`, `elections`, node management commands

---

## Overview

The `tosctl` control plane communicates with TOS validator nodes via the ADNL control protocol. This document records the compatibility assumptions between the imported TOS control-client and TOS validator nodes.

---

## Protocol Compatibility

### ADNL Control Server

TOS validator nodes expose the same ADNL control server interface as TOS. The following TL RPC methods are used:

| Method | TL Type | Purpose | Status |
|--------|---------|---------|--------|
| GenerateKeyPair | `engine.validator.GenerateKeyPair` | Create validator keys | Compatible |
| ExportPublicKey | `engine.validator.ExportPublicKey` | Export public key | Compatible |
| Sign | `engine.validator.Sign` | Sign data with validator key | Compatible |
| AddValidatorPermanentKey | `engine.validator.AddValidatorPermanentKey` | Register permanent key | Compatible |
| AddValidatorTempKey | `engine.validator.AddValidatorTempKey` | Register temporary key | Compatible |
| AddAdnlId | `engine.validator.AddAdnlId` | Register ADNL address | Compatible |
| AddValidatorAdnlAddress | `engine.validator.AddValidatorAdnlAddress` | Link ADNL to validator | Compatible |
| GetConfig | `engine.validator.GetConfig` | Fetch validator config | Compatible |
| GetShardAccountState | `raw.GetShardAccountState` | Query account state | Compatible |
| GetConfigAll | `lite_server.GetConfigAll` | Fetch blockchain config | Compatible |
| GetConfigParams | `lite_server.GetConfigParams` | Fetch specific config params | Compatible |
| SendMessage | `lite_server.SendMessage` | Broadcast messages | Compatible |

**Compatibility basis:** TOS inherits the TOS validator engine and uses the same TL schema for control-plane communication.

### Config Parameters

| Param | Name | Fields | Status |
|-------|------|--------|--------|
| 15 | Election config | `validators_elected_for`, `elections_start_before`, `elections_end_before`, `stake_held_for` | Compatible — same structure |
| 34 | Current validator set | `utime_since`, `utime_until`, `main`, `list[]` with `public_key`, `weight`, `adnl_addr` | Compatible — same structure |
| 36 | Next validator set | Same as param 34 (may be absent before election completes) | Compatible |

---

## Constants and Assumptions

### Gas Fees (Require Testnet Verification)

| Constant | Value | Purpose | Verify On |
|----------|-------|---------|-----------|
| `ELECTOR_STAKE_FEE` | 1,000,000,000 (1 TOS) | Elector stake/recover gas | TOS testnet |
| `RECOVER_FEE` | 200,000,000 (0.2 TOS) | Elector recover message gas | TOS testnet |
| `NPOOL_COMPUTE_FEE` | 200,000,000 (0.2 TOS) | Nominator pool compute gas | TOS testnet |
| `WALLET_COMPUTE_FEE` | 200,000,000 (0.2 TOS) | Wallet message gas | TOS testnet |
| `MIN_NANOCOIN_FOR_STORAGE` | 1,000,000,000 (1 TOS) | Reserved storage balance | TOS testnet |

### Key Types

| Type ID | Algorithm | Status |
|---------|-----------|--------|
| `1209251014` | Ed25519 | Compatible — TOS uses same Ed25519 keys |

### Elector Address

| Address | Status |
|---------|--------|
| `-1:3333...3333` | Compatible — TOS uses same elector address |

---

## Node Management

Node management commands (add, list, remove) are network-agnostic:
- Operate on ADNL endpoint + public key configuration
- Connectivity check uses `ping()` protocol command
- No chain-specific assumptions

Multi-node configuration supports:
- Multiple validator nodes with independent control endpoints
- Per-node wallet and pool bindings
- Per-node stake policy overrides

---

## What Would Break If TOS Diverges

| Divergence | Impact | Mitigation |
|------------|--------|------------|
| Different TL schema | All control-client methods fail | Update `tl_api` crate TL definitions |
| Different config param numbers | Election automation uses wrong data | Add config param mapping layer |
| Different gas schedule | Stake transactions fail or overpay | Update fee constants after testnet verification |
| Different elector ABI | Election participation fails | Update elector wrapper (Phase 4) |
| Different key algorithm | Key generation and signing fail | Update key type constants |
