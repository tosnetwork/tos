# TOS Token Extension Proposals: Jetton and NFT Standards

Version: v1.0

## 1. Purpose

This document defines the canonical token standards for TOS: TOS-TEP-74 (Jetton / fungible tokens) and TOS-TEP-62 (NFT / non-fungible tokens).

These are TOS token standards for fungible tokens and NFTs. The contract interfaces, operation codes, and get-method signatures are kept stable for wallet, explorer, SDK, and AI agent integrations. TOS naming conventions apply: the native currency is "Tomi", and internal field names use `tomis`.

This document is the authoritative reference for:

- contract developers implementing Jetton or NFT contracts on TOS
- wallet and explorer developers integrating token display and transfer
- SDK authors building token abstraction layers
- AI agent developers that need machine-readable token ownership, payment, and metadata flows
- the JSON-RPC `getTokenData` endpoint that performs token type detection

This document complements:

- [tos-standards-map.md](tos-standards-map.md) (Standard Family 6: contract and application standards)
- [Currency.md](Currency.md) (TOS denomination and naming conventions)
- [openapi.yaml](openapi.yaml) (JSON-RPC endpoint definitions)

## 2. TOS-TEP-74: Jetton Standard (Fungible Tokens)

### 2.1 Architecture

The Jetton standard uses a sharded design with two contract types:

- **Jetton Master**: a single contract that holds the token metadata, tracks total supply, and controls minting authority.
- **Jetton Wallet**: a per-user contract that holds that user's token balance. There is exactly one Jetton Wallet contract per (master, owner) pair.

This sharded architecture means each user's balance lives in a separate contract. Transfers between users are messages between their respective Jetton Wallet contracts, not state mutations on a single contract. This design enables horizontal scalability across shards.

```
┌─────────────────────┐
│    Jetton Master    │
│  total_supply       │
│  mintable           │
│  admin_address      │
│  jetton_content     │
│  jetton_wallet_code │
└────────┬────────────┘
         │ deploys
    ┌────┴────┐
    │         │
┌───▼───┐ ┌──▼────┐
│Wallet │ │Wallet │  ...one per owner
│(Alice)│ │(Bob)  │
│balance│ │balance│
│owner  │ │owner  │
└───────┘ └───────┘
```

### 2.2 Jetton Master Get-Methods

The Jetton Master contract exposes one canonical get-method:

**`get_jetton_data()`**

Returns five values on the TVM stack (bottom to top):

| Position | Name | Type | Description |
|---|---|---|---|
| 0 (bottom) | `total_supply` | int | Total number of tokens in circulation (in token base units) |
| 1 | `mintable` | int | Non-zero if minting is allowed, zero if frozen |
| 2 | `admin_address` | slice | Address of the minting authority |
| 3 | `jetton_content` | cell | Token metadata (see Section 2.5) |
| 4 (top) | `jetton_wallet_code` | cell | Code cell used to deploy per-user wallets |

**JSON-RPC representation**

The `getTokenData` endpoint returns Jetton Master data with `@type: "ext.tokens.jettonMasterData"`:

```json
{
  "@type": "ext.tokens.jettonMasterData",
  "total_supply": "1000000000000",
  "mintable": true,
  "admin_address": "EQ...",
  "jetton_content": "<base64-encoded BOC>",
  "jetton_wallet_code": "<base64-encoded BOC>"
}
```

- `total_supply` is a decimal string (not a number) to avoid integer overflow in JSON.
- `jetton_content` and `jetton_wallet_code` are base64-encoded standard BOC serializations of the respective cells.
- `admin_address` is a base64url user-friendly bounceable address.

### 2.3 Jetton Wallet Get-Methods

Each Jetton Wallet contract exposes one canonical get-method:

**`get_wallet_data()`**

Returns four values on the TVM stack (bottom to top):

| Position | Name | Type | Description |
|---|---|---|---|
| 0 (bottom) | `balance` | int | Token balance held by this wallet |
| 1 | `owner_address` | slice | Address of the wallet owner |
| 2 | `jetton_master_address` | slice | Address of the Jetton Master contract |
| 3 (top) | `jetton_wallet_code` | cell | Code cell (for address verification) |

**JSON-RPC representation**

The `getTokenData` endpoint returns Jetton Wallet data with `@type: "ext.tokens.jettonWalletData"`.

Note: in the current implementation, `getTokenData` probes `get_jetton_data` first. A Jetton Wallet contract does not have `get_jetton_data`, so the probe falls through to `get_nft_data`, then `get_collection_data`. If the wallet contract also does not match those, detection will fail. Dedicated Jetton Wallet detection requires calling `runGetMethod` with method name `get_wallet_data` directly.

### 2.4 Operations (Op Codes)

Jetton operations are identified by 32-bit operation codes in the message body.

| Op Code | Hex | Name | Direction | Description |
|---|---|---|---|---|
| `op::transfer` | `0x0f8a7ea5` | Transfer | Owner -> Wallet | Initiate outgoing token transfer |
| `op::internal_transfer` | `0x178d4519` | Internal Transfer | Wallet -> Wallet | Carry tokens between sender and recipient wallets |
| `op::burn` | `0x595f07bc` | Burn | Owner -> Wallet | Destroy tokens, reducing total supply |
| `op::transfer_notification` | `0x7362d09c` | Transfer Notification | Wallet -> Destination | Notify the recipient that tokens have arrived |
| `op::burn_notification` | `0x7bdd97de` | Burn Notification | Wallet -> Master | Notify master to decrease total supply |
| `op::excesses` | `0xd53276db` | Excesses | Wallet -> Owner | Return excess Tomis from the operation |
| `op::mint` | `0x00000015` (21) | Mint | Admin -> Master | Mint new tokens (admin only) |

**Transfer flow**

1. Owner sends `op::transfer` to their Jetton Wallet with the recipient address and token amount.
2. Sender's Jetton Wallet decreases its balance and sends `op::internal_transfer` to the recipient's Jetton Wallet.
3. Recipient's Jetton Wallet increases its balance and sends `op::transfer_notification` to the recipient's owner address.
4. Excess Tomis are returned via `op::excesses`.

**Burn flow**

1. Owner sends `op::burn` to their Jetton Wallet with the amount to burn.
2. Wallet decreases its balance and sends `op::burn_notification` to the Jetton Master.
3. Master decreases `total_supply`.

### 2.5 Jetton Content

Token metadata is encoded in one of two formats, identified by a single-byte prefix:

**On-chain content** (prefix `0x00`)

The cell starts with byte `0x00`, followed by a dictionary (hashmap) of key-value pairs. Standard keys include `name`, `description`, `symbol`, `image`, and `decimals`. Keys are SHA-256 hashes; values are `snake` data format cells.

**Off-chain content** (prefix `0x01`)

The cell starts with byte `0x01`, followed by a UTF-8 URL string. The URL should point to a JSON document conforming to the token metadata schema (fields: `name`, `description`, `symbol`, `image`, `decimals`).

This encoding convention is shared between Jettons and NFTs.

## 3. TOS-TEP-62: NFT Standard (Non-Fungible Tokens)

### 3.1 Architecture

The NFT standard uses two contract types:

- **NFT Collection**: manages a set of items, holds collection-level metadata, defines royalty parameters, and can mint new items.
- **NFT Item**: an individual token with a unique index, an owner, and item-specific content.

Each NFT Item is a separate contract, enabling the same sharded scalability as Jettons.

```
┌──────────────────────┐
│    NFT Collection    │
│  next_item_index     │
│  collection_content  │
│  owner_address       │
│  royalty_params      │
└────────┬─────────────┘
         │ deploys
    ┌────┴────┬────────┐
    │         │        │
┌───▼───┐ ┌──▼────┐ ┌─▼─────┐
│Item #0│ │Item #1│ │Item #2│  ...
│owner  │ │owner  │ │owner  │
│content│ │content│ │content│
└───────┘ └───────┘ └───────┘
```

### 3.2 NFT Collection Get-Methods

The NFT Collection contract exposes one canonical get-method:

**`get_collection_data()`**

Returns three values on the TVM stack (bottom to top):

| Position | Name | Type | Description |
|---|---|---|---|
| 0 (bottom) | `next_item_index` | int | Index to be assigned to the next minted item |
| 1 | `collection_content` | cell | Collection-level metadata |
| 2 (top) | `owner_address` | slice | Address of the collection owner/admin |

**JSON-RPC representation**

The `getTokenData` endpoint returns NFT Collection data with `@type: "ext.tokens.nftCollectionData"`:

```json
{
  "@type": "ext.tokens.nftCollectionData",
  "next_item_index": 42,
  "collection_content": "<base64-encoded BOC>",
  "owner_address": "EQ..."
}
```

- `next_item_index` is an integer (collections are not expected to exceed JSON integer range).
- `collection_content` is a base64-encoded BOC.
- `owner_address` is a base64url user-friendly bounceable address.

### 3.3 NFT Item Get-Methods

Each NFT Item contract exposes one canonical get-method:

**`get_nft_data()`**

Returns five values on the TVM stack (bottom to top):

| Position | Name | Type | Description |
|---|---|---|---|
| 0 (bottom) | `init` | int | Non-zero if the item has been initialized |
| 1 | `index` | int | Item index within its collection |
| 2 | `collection_address` | slice | Address of the parent collection contract |
| 3 | `owner_address` | slice | Address of the current item owner |
| 4 (top) | `individual_content` | cell | Item-specific metadata |

**JSON-RPC representation**

The `getTokenData` endpoint returns NFT Item data with `@type: "ext.tokens.nftItemData"`:

```json
{
  "@type": "ext.tokens.nftItemData",
  "init": true,
  "index": 7,
  "collection_address": "EQ...",
  "owner_address": "EQ...",
  "individual_content": "<base64-encoded BOC>"
}
```

- `init` is a boolean indicating whether the item contract has been initialized.
- `index` is an integer.
- `individual_content` is a base64-encoded BOC of the item-specific metadata cell.

### 3.4 Operations (Op Codes)

| Op Code | Hex | Name | Direction | Description |
|---|---|---|---|---|
| `op::transfer` | `0x5fcc3d14` | Transfer | Owner -> Item | Transfer NFT ownership |
| `op::ownership_assigned` | `0x05138d91` | Ownership Assigned | Item -> New Owner | Notify new owner of received NFT |
| `op::get_static_data` | `0x2fcb26a2` | Get Static Data | Any -> Item | Request the item's static data (index, collection) |
| `op::report_static_data` | `0x8b771735` | Report Static Data | Item -> Requester | Response to get_static_data |
| `op::get_royalty_params` | `0x693d3950` | Get Royalty Params | Any -> Collection | Query royalty configuration |
| `op::report_royalty_params` | `0xa8cb00ad` | Report Royalty Params | Collection -> Requester | Response with royalty percentage and destination |
| `op::excesses` | `0xd53276db` | Excesses | Item -> Previous Owner | Return excess Tomis |

**Transfer flow**

1. Current owner sends `op::transfer` to the NFT Item contract with the new owner address.
2. Item contract updates its `owner_address`.
3. Item sends `op::ownership_assigned` to the new owner.
4. Excess Tomis are returned to the previous owner via `op::excesses`.

**Royalty query flow**

1. Any address sends `op::get_royalty_params` to the NFT Collection.
2. Collection responds with `op::report_royalty_params` containing the royalty numerator, denominator, and destination address.

### 3.5 NFT Content

NFT content uses the same on-chain/off-chain encoding as Jettons (Section 2.5).

For collection-based NFTs, the full item content is derived by combining `collection_content` and `individual_content`. The standard convention is:

- **Off-chain**: collection content provides a base URL; individual content provides a suffix. The full metadata URL is the concatenation.
- **On-chain**: individual content may override or extend collection-level metadata fields.

## 4. Token Detection via JSON-RPC

The `getTokenData` endpoint provides a single entry point for identifying any token contract.

### 4.1 Detection Order

When `getTokenData(address)` is called, the server probes the contract's get-methods in this order:

1. **`get_jetton_data`** -- if the method exists and returns 5 valid stack entries, the contract is identified as a Jetton Master and the response uses `@type: "ext.tokens.jettonMasterData"`.

2. **`get_nft_data`** -- if `get_jetton_data` fails, the server tries `get_nft_data`. If it succeeds with 5 valid stack entries, the contract is identified as an NFT Item and the response uses `@type: "ext.tokens.nftItemData"`.

3. **`get_collection_data`** -- if both previous probes fail, the server tries `get_collection_data`. If it succeeds with 3 valid stack entries, the contract is identified as an NFT Collection and the response uses `@type: "ext.tokens.nftCollectionData"`.

4. **Failure** -- if none of the get-methods succeed, the server returns HTTP 409 with the error message: `"Smart contract is not a Jetton or NFT"`.

### 4.2 Parameters

| Parameter | Required | Type | Description |
|---|---|---|---|
| `address` | Yes | string | Contract address to probe |
| `seqno` | No | integer | Masterchain block seqno for historical queries |

### 4.3 Client Usage

Client libraries should use `getTokenData` as the primary token detection mechanism rather than calling `runGetMethod` with individual method names. The `@type` field in the response unambiguously identifies the contract type, enabling a single code path for all token types:

```
response = rpc.getTokenData(address)
switch response["@type"]:
  "ext.tokens.jettonMasterData" -> handle as Jetton Master
  "ext.tokens.nftItemData"      -> handle as NFT Item
  "ext.tokens.nftCollectionData" -> handle as NFT Collection
```

### 4.4 Limitations

- The probe order means a contract that implements multiple get-methods will be classified by whichever method matches first. In practice, token contracts implement exactly one of the three get-methods.
- Jetton Wallet contracts (`get_wallet_data`) are not currently detected by `getTokenData`. To query a Jetton Wallet, use `runGetMethod` with method name `get_wallet_data` directly.

## 5. Naming Conventions

All TOS TEP standards follow TOS naming conventions as defined in [Currency.md](Currency.md):

| Context | Convention | Example |
|---|---|---|
| Native currency name | Tomi | "Transfer costs 0.05 Tomi in gas" |
| Internal field names (BOC/TLB) | `tomis` | `value:Tomis` in block.tlb |
| JSON-RPC numeric fields | String nanotomis | `"total_supply": "1000000000000"` |
| JSON-RPC balance fields | String nanotomis | `"balance": "500000000"` |
| Fift scripts | Tomi / TM$ | `TM$1.7` |

Token amounts (`total_supply`, `balance`) are denominated in the token's own base units, not in Tomis. Only gas and message value fields use Tomi/nanotomi denomination.

## 6. Contract Source Locations

The canonical reference implementations for TOS token contracts are:

| Contract | Source Path |
|---|---|
| Jetton Master | `crypto/func/auto-tests/legacy_tests/jetton-minter/jetton-minter.fc` |
| Jetton Wallet | `crypto/func/auto-tests/legacy_tests/jetton-wallet/jetton-wallet.fc` |
| Jetton Op Codes | `crypto/func/auto-tests/legacy_tests/jetton-wallet/imports/op-codes.fc` |
| NFT Collection | `crypto/func/auto-tests/legacy_tests/nft-collection/nft-collection-editable.fc` |
| NFT Op Codes | `crypto/func/auto-tests/legacy_tests/nft-collection/op-codes.fc` |
| NFT Item | `crypto/func/auto-tests/legacy_tests/tele-nft-item/nft-item.fc` |

These are FunC source files. They are tested as part of the legacy test suite and serve as the authoritative definition of each contract's behavior.

## 7. Stability Level

This section classifies the stability of each component using the levels defined in [tos-standards-map.md](tos-standards-map.md) and [tos-release-policy.md](tos-release-policy.md).

| Component | Stability Level | Rationale |
|---|---|---|
| Token get-method signatures | Level 1 (Canonical) | Protocol-defined interfaces; changing them would break all deployed contracts and tooling |
| Operation codes | Level 1 (Canonical) | Protocol-defined message format; encoded in deployed contract bytecode |
| Content encoding (on-chain/off-chain prefix) | Level 1 (Canonical) | Widely adopted convention; wallets and explorers depend on the 0x00/0x01 prefix |
| JSON-RPC `getTokenData` response shapes | Level 2 (Supported) | Fields may be added in future versions; existing fields will not be removed or renamed without deprecation |
| JSON-RPC `getTokenData` detection order | Level 2 (Supported) | Probe order is a server implementation detail; clients should rely on `@type`, not probe order |
| Reference contract implementations | Level 2 (Supported) | Source paths and contract logic may evolve; get-method signatures and op codes remain stable |

## 8. Open Questions

1. **Jetton Wallet detection**: Should `getTokenData` add `get_wallet_data` as a fourth probe to detect Jetton Wallets natively? This would complete the token detection surface but changes the probe chain.

2. **Metadata resolution**: Should the JSON-RPC server resolve off-chain metadata URLs and return parsed JSON alongside the raw content cell? This would simplify client implementations but introduces external HTTP dependencies in the RPC server.

3. **SBT (Soulbound Token) extension**: The NFT op-codes file includes SBT-related operations (`op::prove_ownership`, `op::request_owner`). Should TOS-TEP-62 formally document the SBT extension as part of the NFT standard?

4. **Royalty enforcement**: Royalty parameters are queryable but not enforced at the protocol level. Should the standard document recommended marketplace-level enforcement patterns?
