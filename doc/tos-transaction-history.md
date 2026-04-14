# TOS Transaction History and Indexed Data Model

Version: v1.0

## 1. Purpose

This document defines the canonical data model for transaction history in TOS.

It specifies how wallets, explorers, and indexers obtain and interpret transaction history from the TOS JSON-RPC API. It covers transaction identifiers, response fields, pagination, block-level access, transaction lookup, historical account state, data boundaries, and execution outcomes.

This document complements:

- [tos-wallet-send-track.md](tos-wallet-send-track.md) (send-and-track lifecycle)
- [tos-trust-tiers.md](tos-trust-tiers.md) (verification model for each client type)
- [tos-standards-map.md](tos-standards-map.md) (Standard Family 3: indexing and data standards)
- [tos-roadmap-12m.md](tos-roadmap-12m.md) (Q2: "one explicit model for balances, transaction identifiers, outcomes, and historical lookup")

All methods are accessed via `POST /jsonRPC` as standard JSON-RPC 2.0 requests, or via `POST /{methodName}` with a params JSON body. The OpenAPI definition is published in `doc/openapi.yaml`.

## 2. Transaction Identifiers

Every transaction on TOS is identified by three independent values.

### Logical time (lt)

A monotonically increasing integer per account. Represented as a string encoding of int64 in all JSON responses. Logical time establishes a total ordering of transactions within a single account and a partial ordering across accounts within the same block.

### Transaction hash

The SHA256 hash of the serialized transaction cell. Represented as a base64-encoded string in JSON responses. The hash uniquely identifies a specific transaction independently of the account.

### Message hash (in_msg_hash)

The hash of the inbound message cell that triggered the transaction. Represented as a base64-encoded string. Used for send-track correlation: the hash returned by `sendBocReturnHash` matches the `in_msg_hash` of the resulting on-chain transaction.

`in_msg_hash` is a TOS extension not present in standard TON HTTP API responses.

### Block ID

The block containing the transaction, identified by five fields:

| Field | Type | Description |
|---|---|---|
| `workchain` | integer | Workchain ID (-1 for masterchain) |
| `shard` | string | Shard identifier (int64 as string) |
| `seqno` | integer | Block sequence number within the shard |
| `root_hash` | string | Base64-encoded root hash of the block |
| `file_hash` | string | Base64-encoded file hash of the block |

The `@type` of a block ID object is `"ton.blockIdExt"`.

### Uniqueness

The tuple `(account, lt, hash)` uniquely identifies a transaction on-chain. Any two of these three values are sufficient for practical deduplication in most cases, but all three should be stored by indexers and explorers for unambiguous reference.

## 3. Transaction Fields

### `getTransactions` response

`getTransactions` returns a JSON array of transaction objects. Each object has `@type` `"raw.transaction"` and contains the following fields:

| Field | Type | Description |
|---|---|---|
| `@type` | string | Always `"raw.transaction"` |
| `transaction_id` | object | Primary identifier: `{lt, hash}` (see `InternalTransactionId` schema) |
| `block_id` | object | Containing block (see `TonBlockIdExt` schema) |
| `utime` | integer | Unix timestamp of the block containing this transaction |
| `fee` | string | Total fees charged, in nanotomis |
| `account` | string | 256-bit account address in hex |
| `in_msg_hash` | string | Base64-encoded hash of the inbound message cell (TOS extension) |
| `data` | string | Base64-encoded BOC of the raw transaction cell |

The `transaction_id` object has `@type` `"internal.transactionId"` and contains:

| Field | Type | Description |
|---|---|---|
| `lt` | string | Logical time (int64 as string) |
| `hash` | string | Base64-encoded transaction hash |

The `data` field contains the full serialized transaction. Clients that need to inspect outbound messages, compute phases, action phases, or TVM exit codes must deserialize this BOC using a TOS/TON SDK. The JSON-RPC API does not parse the transaction body into structured fields.

### `getTransactionsStd` response

`getTransactionsStd` returns the same transaction objects wrapped in a `blocks.rawTransactions` envelope:

```json
{
  "ok": true,
  "result": {
    "@type": "blocks.rawTransactions",
    "transactions": [
      {
        "@type": "raw.transaction",
        "block_id": { ... },
        "data": "base64-encoded-transaction-BOC",
        "utime": 1714000000,
        "transaction_id": {
          "@type": "internal.transactionId",
          "lt": "12345678",
          "hash": "base64-encoded-hash"
        }
      }
    ],
    "previous_transaction_id": {
      "@type": "internal.transactionId",
      "lt": "12345670",
      "hash": "base64-encoded-hash"
    }
  }
}
```

The `previous_transaction_id` field provides the cursor for the next page of results. If it is absent or has `lt` equal to `"0"`, there are no more transactions to fetch.

## 4. Pagination Model

Transaction history is paginated backward from a starting point.

### Latest transactions

```
getTransactions(address, limit)
```

When `lt` and `hash` are omitted, the response starts from the most recent transaction and returns up to `limit` transactions in reverse chronological order.

### Cursor-based pagination

```
getTransactions(address, lt, hash, limit)
```

When `lt` and `hash` are both provided, the response starts from the transaction at `(lt, hash)` and returns up to `limit` transactions going backward. The transaction at the specified `(lt, hash)` is included in the response.

`lt` and `hash` must be provided together. Providing one without the other is an error.

### Pagination with `getTransactionsStd`

`getTransactionsStd` includes a `previous_transaction_id` field in the response envelope. To fetch the next page, use the `lt` and `hash` from `previous_transaction_id` as the cursor for the next request:

```
page1 = getTransactionsStd(address, limit=10)
cursor = page1.result.previous_transaction_id
page2 = getTransactionsStd(address, limit=10, lt=cursor.lt, hash=cursor.hash)
```

### Limits

| Parameter | Default | Maximum |
|---|---|---|
| `limit` | 10 | 100 |

Requesting more than 100 transactions per call will be clamped to 100.

### Entry point

The `last_transaction_id` field in account state responses (`getAddressInformation`, `getWalletInformation`) provides the `(lt, hash)` of the most recent transaction. This is the canonical entry point for starting transaction pagination.

## 5. Block-Level Transaction Access

Block-level methods allow clients to enumerate all transactions in a specific block, regardless of account.

### `getBlockTransactions`

Returns short transaction identifiers for a block.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `workchain` | integer | yes | Workchain ID |
| `shard` | string | yes | Shard identifier |
| `seqno` | integer | yes | Block sequence number |
| `count` | integer | no | Number of transactions to return (default: 40, max: 256) |
| `after_lt` | string | no | Pagination cursor: logical time |
| `after_hash` | string | no | Pagination cursor: account hash (base64) |

Response:

```json
{
  "ok": true,
  "result": {
    "@type": "blocks.transactions",
    "id": { "@type": "ton.blockIdExt", ... },
    "req_count": 40,
    "incomplete": false,
    "transactions": [
      {
        "@type": "blocks.shortTxId",
        "account": "hex-encoded-256-bit-account-address",
        "lt": "12345678",
        "hash": "base64-encoded-hash"
      }
    ]
  }
}
```

When `incomplete` is `true`, there are more transactions in the block. Use the `lt` and `hash` (account hash) of the last entry as `after_lt` and `after_hash` to fetch the next page.

### `getBlockTransactionsExt`

Returns full transaction BOCs for a block. Same parameters as `getBlockTransactions`. The response includes complete `raw.transaction` objects with `data` fields instead of short identifiers.

This method is suitable for indexers that need to process all transactions in a block without making per-account queries.

## 6. Transaction Lookup

These methods locate a transaction by matching source address, destination address, and the `created_lt` of the internal message that connects them.

### `tryLocateTx`

```
tryLocateTx(source, destination, created_lt)
```

Locates the incoming transaction on the destination account triggered by an internal message from `source` with the given `created_lt`.

### `tryLocateResultTx`

```
tryLocateResultTx(source, destination, created_lt)
```

Locates the result (inbound) transaction on the destination account. Functionally equivalent to `tryLocateTx` in most cases.

### `tryLocateSourceTx`

```
tryLocateSourceTx(source, destination, created_lt)
```

Locates the source (outbound) transaction on the source account that produced the internal message.

### Parameters (all three methods)

| Parameter | Type | Required | Description |
|---|---|---|---|
| `source` | string | yes | Source account address |
| `destination` | string | yes | Destination account address |
| `created_lt` | string | yes | Logical time when the internal message was created |

### Use case

These methods are used to trace the causal chain of internal messages. When a wallet sends a transfer and the destination contract produces further internal messages, `tryLocateResultTx` can find the transaction that processed the inbound message, and `tryLocateSourceTx` can find the transaction that originated it.

The `created_lt` is available by deserializing the outbound messages from the transaction `data` BOC.

## 7. Account State and Balance History

### Current state

- `getAddressInformation(address)` -- returns full account state including `balance`, `code`, `data`, `state`, and `last_transaction_id`
- `getAddressBalance(address)` -- returns only the balance in nanotomis
- `getWalletInformation(address)` -- returns wallet-specific fields including `seqno`, `wallet_type`, and `wallet_id`

### Historical state

All three methods accept an optional `seqno` parameter specifying a masterchain block sequence number:

- `getAddressInformation(address, seqno)` -- account state as of masterchain block `seqno`
- `getAddressBalance(address, seqno)` -- balance as of masterchain block `seqno`
- `getWalletInformation(address, seqno)` -- wallet state as of masterchain block `seqno`

When `seqno` is omitted, the latest state is returned.

### `last_transaction_id`

The `last_transaction_id` field in account state responses contains the `lt` and `hash` of the most recent transaction for the account at the queried point in time. This serves as the entry point for backward transaction pagination via `getTransactions`.

When querying historical state with a `seqno` parameter, `last_transaction_id` reflects the most recent transaction as of that masterchain block, not the current chain tip.

### Balance history reconstruction

TOS does not provide a dedicated balance-history API. To reconstruct balance at arbitrary points in time:

1. Query `getAddressBalance(address, seqno)` for a specific masterchain block.
2. Alternatively, iterate through transaction history and compute balance deltas from the `data` BOC.

Option 1 is simpler but requires knowing the masterchain seqno of interest. Option 2 provides full resolution but requires BOC deserialization.

## 8. Data Boundaries

The TOS API serves data from the node's local storage. Different data categories have different availability characteristics.

### Node-native data

Recent blocks and transactions are available from any synced node. The retention depth is governed by the node's storage configuration. A default node retains recent history sufficient for normal wallet and application use, but does not guarantee availability of the full chain history.

### Archival data

Full transaction history from genesis is available only from nodes configured for archival storage, or from dedicated archival services. Clients that need to query transactions older than the node's retention window must connect to an archival node.

Whether a node is archival is an operational configuration choice. The API behavior is identical; the difference is in which `(lt, hash)` ranges return data versus errors.

### Indexed data

Aggregated views -- token transfer histories, address activity rankings, contract event logs, decoded message bodies -- are derived data not provided by the node API. These views are the responsibility of third-party indexers that ingest raw block and transaction data from Tier 1 or Tier 3 nodes.

The node API provides the raw substrate. Interpretation, aggregation, and search are the client's or indexer's responsibility.

### Boundary summary

| Data Category | Source | Availability | Trust Tier (per tos-trust-tiers.md) |
|---|---|---|---|
| Recent blocks and transactions | Node-native | Governed by node storage config | Tier 1 (local node) or Tier 3 (remote node) |
| Full chain history | Archival node | Requires archival configuration | Tier 1 (local archival) or Tier 3 (remote archival) |
| Aggregated/derived views | Third-party indexer | Depends on indexer | Tier 4 (indexed/derived) |

## 9. Execution Outcomes

### Transaction success and failure

Transaction success or failure is encoded within the serialized transaction cell (the `data` field). The relevant information includes:

- **TVM exit code**: 0 or 1 indicates success; other values indicate failure
- **Compute phase**: contains gas usage, exit code, and success/failure flag
- **Action phase**: contains result code and success/failure flag for message sending actions
- **Bounce phase**: present if an inbound message bounced

The JSON-RPC API does not parse these fields out of the `data` BOC. Clients must deserialize the transaction BOC to inspect execution outcomes.

### Interpreting outcomes

To determine whether a transaction succeeded:

1. Deserialize the `data` BOC using a TOS/TON SDK.
2. Check the compute phase exit code. Exit code 0 or 1 means TVM execution succeeded.
3. Check the action phase result code. Result code 0 means all actions (outbound messages) were processed successfully.
4. If both phases succeeded, the transaction executed as intended.

A transaction that appears on-chain is always "confirmed" in the sense that it was included in a block and fees were charged. But the smart contract execution within it may have failed (non-zero exit code), and outbound messages may have been rejected (non-zero action result code). Confirmation and success are distinct concepts.

### Smart contract get-method execution

For direct get-method execution without a transaction, use `runGetMethod`:

```
runGetMethod(address, method, stack)
```

The response includes an `exit_code` field directly in the JSON response (not buried in a BOC). Exit code 0 indicates success.

This is the appropriate method for querying contract state (token balances, pool reserves, etc.) without needing to parse transaction BOCs.

## 10. Stability Level

This section classifies the stability of each component of the transaction history data model, using the levels defined in [tos-release-policy.md](tos-release-policy.md) and [tos-standards-map.md](tos-standards-map.md).

| Component | Stability Level | Rationale |
|---|---|---|
| Transaction identifiers (`lt`, `hash`) | Level 1 (Canonical) | Protocol-defined; cannot change without a protocol upgrade |
| Response field names (`@type`, `transaction_id`, `block_id`, `utime`, `fee`, `account`, `data`) | Level 1 (Canonical) | Defined in `doc/openapi.yaml`; stable for ecosystem compatibility |
| `in_msg_hash` field | Level 1 (Canonical) | TOS extension; required for send-track correlation |
| Pagination model (`lt`/`hash` cursor, `previous_transaction_id`) | Level 2 (Supported) | Stable for current use; may evolve if new pagination patterns emerge |
| Data BOC format (`data` field content) | Level 1 (Canonical) | Protocol-defined serialization; stable |
| Block-level transaction methods (`getBlockTransactions`, `getBlockTransactionsExt`) | Level 2 (Supported) | Stable for indexer use; parameters may evolve |
| Transaction lookup methods (`tryLocateTx`, `tryLocateResultTx`, `tryLocateSourceTx`) | Level 2 (Supported) | Useful but not yet broadly depended on |
| Historical state queries (`seqno` parameter) | Level 2 (Supported) | Mechanism is stable; availability depends on node configuration |

## References

- OpenAPI specification: `doc/openapi.yaml`
- Wallet send-and-track specification: `doc/tos-wallet-send-track.md`
- Trust and verification tiers: `doc/tos-trust-tiers.md`
- Standards map: `doc/tos-standards-map.md`
- Release policy: `doc/tos-release-policy.md`
- 12-month roadmap: `doc/tos-roadmap-12m.md` (Q2: "one explicit model for balances, transaction identifiers, outcomes, and historical lookup")
