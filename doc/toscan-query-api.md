# TOSCAN Query API

Status: implemented public-beta contract.

TOSCAN uses two read-only surfaces:

1. the validator-engine JSON-RPC/REST adapter for node-authoritative bodies;
2. the `tosctld` explorer index for global discovery, pagination and search.

The explorer index is not an alternative ledger. Every row records a chain identity or a decoded contract state observed while walking finalized shard blocks. Full state remains authoritative on the node.

## Index behavior

`tosctld` advances one canonical masterchain block at a time. For each height it reads the exact shard heads referenced by that masterchain block; repeated heads are deduplicated by root hash, while newly split shards are indexed directly from their reported (possibly non-zero) height. Zerostate descriptors are anchors, not queryable blocks. Schema version 5 rebuilds the chain-derived tables from genesis so upgraded installations acquire topology-correct history and rich transaction summaries.

The durable tables cover:

- block identity, chain-authored generation time and indexed time;
- transaction hash, canonical account, unsigned 64-bit logical time, block identity, total fee and inbound-message hash;
- classified contract DTOs and their last observed block;
- per-shard checkpoints and checkpoint block hashes.

Block insertion is atomic with all transaction identities returned across its paginated node scan. Pagination uses `(logical time, account hash)`, matching the liteserver cursor. Repeated scanning is idempotent and replacing a block removes identities retired by the replacement. If the committed masterchain root changes, all chain-derived explorer, contract, lifecycle and settlement state is cleared and deterministically replayed.

## Public routes

These routes are registered outside the operator-authenticated `tosctld` router. They are GET-only and contain no secret or mutation surface.

| Route | Query | Result |
| --- | --- | --- |
| `/explorer/status` | — | index totals, latest index time, shard checkpoints, node masterchain head, indexed masterchain head and lag |
| `/explorer/blocks` | `offset`, `limit` | newest-first block page with exact indexed transaction counts |
| `/explorer/block` | `hash` | block resolved by root or file hash |
| `/explorer/transactions` | `offset`, `limit`; optional `account`; or exact `workchain`, `shard`, `seqno` tuple | newest-first global/account page or logical-time-ordered block page |
| `/explorer/transaction` | `hash` | transaction identity resolved by hash |
| `/explorer/contracts/{kind}` | `creator`, `status`, `deadline_after`, `deadline_before`, `offset`, `limit` | classified contract page |
| `/explorer/contracts/{kind}/{address}` | — | one classified contract |
| `/explorer/search` | `q` | exact transaction hash, block hash or classified address match |

`limit` is clamped to 1–200. Account/address filters are parsed and returned in canonical TOS form. Partial block tuples and a simultaneous account/block filter are rejected with HTTP 400 rather than silently broadening a query.

Supported contract kinds are `agent_account`, `task_escrow`, `dispute`, `service_actor`, `capability_registry`, `aipow_commitment` and `aipow_distributor`.

## Node transport for a public explorer

Run the source node with `--json-rpc-readonly` and normally with `--json-rpc-api-key`. TOSCAN's same-origin gateway injects that key server-side and publishes only the exact read-method REST paths it uses. It must not proxy the general `/jsonRPC` route.

The REST adapter supports the wallet-index reads required by TOSCAN: `getAccountEvents`, `getAccountEvent`, `getAccountJettons` and `getAccountNfts`, in addition to the block, transaction, account, authority, token and consensus reads documented in [json-rpc-policy.md](json-rpc-policy.md).

`getBlockTransactionsExt` is the preferred index feed. It returns the same canonical identity page as `getBlockTransactions` plus fee and inbound-message hash. `getTransactions` transaction bodies expose structured `in_msg` and `out_msgs` summaries (hash, kind, source, destination, value, bounce state and creation time) while preserving the raw BOC for independent decoding.

Defense in depth is intentional: validator-engine read-only mode rejects mutations even if a proxy is misconfigured; the proxy method allowlist prevents public callers from reaching methods TOSCAN does not need.

## Operational acceptance

Before declaring an index caught up:

1. `/explorer/status.masterchain_lag` is zero;
2. expected shard checkpoints are present;
3. block/transaction counts continue monotonically except during an explicitly observed reorg;
4. exact search resolves a recently observed transaction and block hash;
5. a genesis replay and checkpoint resume produce the same indexed identities.

The `service` Rust test gate covers schema migration, unsigned logical times, cursor pagination, split-shard starts, zerostate handling, exact block replacement, public-route isolation and exact search. `scripts/toscan-explorer-e2e.py` is the real-chain release gate: it deploys five real Agent Economy contracts, waits for chain-wide discovery, verifies rich message data, restarts the explorer and proves recovery. TOSCAN separately runs browser, accessibility, PostgreSQL projection and production-container gates.
