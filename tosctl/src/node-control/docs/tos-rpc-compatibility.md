# TOS Chain RPC Compatibility Decision

**Date:** 2026-04-12  
**Status:** Active  
**Scope:** `src/node-control/chain-rpc-client`, `contracts/src/chain_provider.rs`

---

## Decision

TOS uses **JSON-RPC** as its chain RPC interface for the initial release. The `tosctl` codebase retains the existing HTTP API client (`chain-rpc-rs`) as the default backend behind a TOS-neutral provider abstraction (`ChainProvider` trait).

---

## Architecture

```text
Operator code (elections, commands, service tasks)
        │
        ▼
ChainProvider trait  ← TOS-neutral interface
        │
        ▼
DefaultChainProvider ← adapter, delegates to ClientJsonRpc
        │
        ▼
ClientJsonRpc        ← multi-endpoint failover, round-robin
        │
        ▼
chain-rpc-rs         ← JSON-RPC 2.0 transport
```

When TOS introduces a native RPC backend, a new `ChainProvider` implementation replaces `DefaultChainProvider` without changing any higher-level code.

---

## RPC Methods Used

| Method | Purpose | Used By |
|--------|---------|---------|
| `getConfigParam` | Fetch blockchain config parameters | `get_config_param_cmd`, `ChainProvider` |
| `runGetMethod` | Execute TVM get-methods on contracts | contract wrappers (elector, nominator, wallet) |
| `sendBoc` | Broadcast serialized messages | wallet send, deploy, election stake submission |
| `getAddressInformation` | Account state + balance | contracts monitor, wallet commands |
| `getExtendedAddressInformation` | Raw account state | pool/wallet diagnostics |
| `getWalletInformation` | Wallet-specific info (type, seqno) | wallet commands |

---

## Compatibility Assumptions

The following assumptions must hold for JSON-RPC to work with TOS:

1. **TVM execution model** is identical — `runGetMethod` returns the same stack format
2. **Account states** (`active`, `uninitialized`, `frozen`) are the same
3. **BOC serialization** format is unchanged
4. **Config parameters** (particularly `15`, `34`, `36`) use the same cell encoding
5. **Address format** (`MsgAddressInt`) is unchanged
6. **JSON-RPC 2.0 envelope** with `id`, `method`, `params` fields

If any of these diverge, the `DefaultChainProvider` adapter or `ClientJsonRpc` must be updated.

---

## What Would Change for a TOS-Native RPC

If TOS introduces its own RPC protocol:

1. Implement a new `TosNativeProvider` that satisfies `ChainProvider`
2. Update `RuntimeConfigStore::load_rpc_client` to construct the new provider
3. The `ClientJsonRpc` and `chain-rpc-rs` dependency become optional
4. No changes needed in elections, contracts, commands, or service code

---

## Remaining TON-Specific Internals

These are implementation details behind the `ChainProvider` abstraction:

| Item | Location | Notes |
|------|----------|-------|
| `chain-rpc-rs` crate | `chain-rpc-client/Cargo.toml` | External dependency, provides JSON-RPC 2.0 transport |
| `ApiClientV2` | `client_json_rpc.rs` | chain-rpc-rs client type |
| `Network::Custom(url)` | `client_json_rpc.rs` | Flexible — works with any URL |
| `RPCStackEntry` | `chain-rpc-client/src/v2/stack.rs` | TVM stack serialization for RPC |
| Response types | `chain-rpc-client/src/v2/data_models.rs` | `GetAddressInformationRes`, `RunGetMethodRes`, etc. |

These are encapsulated behind `DefaultChainProvider` and do not leak to higher-level code that uses `ChainProvider`.
