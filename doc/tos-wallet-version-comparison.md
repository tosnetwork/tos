# TOS Wallet Version Comparison

Version: v0.1

## 1. Purpose

This document compares the wallet versions that are explicitly modeled in the current TOS repository, with a focus on the standard wallet line:

- `wallet v3 r2`
- `wallet v4 r2`
- `wallet v5 r1`

The goal is practical interoperability guidance for implementers. This is an implementation-oriented document based on the current repository state. It does not attempt to restate external TOS ecosystem history beyond what can be verified locally.

## 2. Scope and Evidence

This comparison is derived from the current codebase, especially:

- wallet type detection in `validator-engine`
- wallet address derivation in `tosctl`
- wallet signing-body construction in `tosctl`
- wallet storage layout fixtures in `test/tostester`
- deployed-wallet fixture generation in `test/json-rpc`

## 3. Summary Table

| Wallet version | Persistent data layout | Address derivation inputs | Outbound signing body shape | Distinct implementation-visible features | Inter-wallet transfer compatibility |
|----------------|------------------------|----------------------------|-----------------------------|------------------------------------------|-------------------------------------|
| `wallet v3 r2` | `seqno + wallet_id + public_key` | `code(v3) + data(seqno=0, wallet_id, public_key)` | `subwallet_id + expire + seqno + [ref: msg] + mode` | Baseline standard wallet model with `seqno` and `wallet_id` | Can send to and receive from `v4` and `v5` |
| `wallet v4 r2` | `seqno + wallet_id + public_key + plugins` | `code(v4) + data(seqno=0, wallet_id, public_key, plugins=null)` | `subwallet_id + expire + seqno + simple_send_opcode + [ref: msg] + mode` | Adds `plugins` field to persistent state and an explicit simple-send opcode in the signing body | Can send to and receive from `v3` and `v5` |
| `wallet v5 r1` | `is_signature_allowed + seqno + wallet_id + public_key + extensions_dict` | `code(v5) + data(is_signature_allowed=1, seqno=0, wallet_id, public_key, extensions=empty)` | `prefix + wallet_id + expire + seqno + has_actions + actions_ref + has_other_actions` | Adds a signature-allowance flag and an extensions dictionary; uses an action-based send body instead of the `v3/v4` simple layout | Can send to and receive from `v3` and `v4` |

## 4. Detailed Notes

### 4.1 `wallet v3 r2`

The repository models `wallet v3 r2` as a standard wallet with the classic data layout:

- `seqno:uint32`
- `wallet_id:uint32`
- `public_key:bits256`

The address is derived from the wallet code plus that initial data. In `tosctl`, the `V3R2` address path builds `StateInit`, hashes it, and converts the result into a standard internal address.

The transfer signing body uses:

- `subwallet_id`
- `expire`
- `seqno`
- a referenced outbound internal message
- `mode`

This is the simplest baseline among the three versions compared here.

### 4.2 `wallet v4 r2`

`wallet v4 r2` keeps the same core fields as `v3`:

- `seqno`
- `wallet_id`
- `public_key`

but adds:

- `plugins:(Maybe ^Cell)`

The address derivation path differs because the initial data cell includes the plugins slot, even when it is empty.

Its signing body is similar to `v3`, but the current `tosctl` implementation inserts a dedicated `wallet-v4 simple transfer opcode` before the referenced internal message.

In practical terms, the main repository-visible delta from `v3` is:

- extra on-chain state for plugins
- a slightly different external signing-body format

### 4.3 `wallet v5 r1`

`wallet v5 r1` changes both the state layout and the send format more substantially.

Its modeled persistent data includes:

- `is_signature_allowed`
- `seqno`
- `wallet_id`
- `public_key`
- `extensions_dict`

The current implementation also derives the address from a different initial data layout, where:

- signature allowance is initialized to enabled
- extensions are initialized empty

The send path is no longer the `v3/v4` flat "simple transfer body". Instead, the current `tosctl` implementation builds a `v5` signed external body with:

- a version-specific prefix
- `wallet_id`
- `expire`
- `seqno`
- an actions reference
- an "other actions" flag

Within the repository, this is the clearest sign that `v5` is a more extensible wallet format than `v3/v4`.

## 5. What Is the Same Across `v3`, `v4`, and `v5`

The important compatibility point is that all three are treated as recognized wallet contracts and are surfaced through the same wallet-facing APIs:

- `getWalletInformation`
- `seqno`-based send flows
- external-message submission via `sendBocReturnHash`

The server also classifies wallet types that start with `wallet ` under the same default account model family:

- `default.wallet.v1`

That means the protocol-facing integration model is intentionally unified even though the wallet internals differ.

For ordinary value transfer, the sender wallet version and the recipient wallet version do not need to match. A `v3` wallet can send to a `v4` or `v5` wallet address, and vice versa. The sender-side implementation must build the correct external message for its own wallet version, but the destination is still just a normal account address.

## 6. What This Document Does Not Claim

This document does not claim that the repository fully documents all semantic differences between these wallet versions. In particular, it does not try to prove:

- the full external standard surface of each version
- historical rationale for version changes
- feature parity with external wallet implementations outside this repository

Where the repository only exposes a structural difference, this document describes it as such and avoids stronger claims.

## 7. Source Pointers

- Wallet type detection: `validator-engine/json-rpc-server-account-capability.cpp`
- Wallet fixtures and data-layout hints: `test/json-rpc/deployer.py`
- TLB wallet data models: `test/tostester/src/pytosiq_core/tlb/custom/wallet.py`
- Address derivation and signing-body construction: `tosctl/src/node-control/contracts/src/wallet/wallet_contract.rs`
