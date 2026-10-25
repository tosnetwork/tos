# Standalone wallet services

Build the services from the same checkout as the node:

```sh
cmake --build build --target tos-rpc tos-wallet-index validator-engine
```

The deployment has three independent processes. A validator or a non-validating
full node owns the canonical chain database and serves the binary liteserver
protocol. `tos-wallet-index` reads that database and owns a separate RocksDB index.
`tos-rpc` owns the public wallet HTTP endpoint. No index queue, index WAL sync or
index get-method execution runs on a validator's block-application path.

## Start

```sh
build/services/tos-wallet-index \
  --source-db /srv/tos-node/db \
  --data-dir /srv/tos-wallet-index \
  --listen 127.0.0.1:8081

build/services/tos-rpc \
  --global-config /etc/tos/liteservers.json \
  --index-address 127.0.0.1:8081 \
  --listen 127.0.0.1:8080
```

Use a full-node replica for the source when possible, so read I/O does not compete
with consensus. Mount the source database read-only in the index process's mount
namespace/container. Its own data directory must be writable and must not overlap
with the source. The secondary reader follows the running primary without taking
its RocksDB writer lock. It uses no validator key and does not modify node state.
Use the same software version and database layout for the reader and source.

The liteserver configuration uses the usual global-config JSON format with between
1 and 16 `liteservers`. These are **trusted** backends: authentication of their
ADNL keys does not independently verify every RPC answer against chain proofs.
Configure the same network as the index source. The two services are separate
connections; operators are responsible for matching their networks.

Put a TLS reverse proxy in front of `tos-rpc`. Write-enabled HTTP binds must be
loopback; `--readonly` permits a non-loopback bind. Optional `--api-key-file`,
`--cors-origin`, `--trust-proxy-headers` and repeatable `--trusted-proxy` retain the
existing HTTP controls. `--request-timeout` bounds backend waits (default inherited
from the RPC server, configurable 1–300 seconds). The internal index endpoint is
loopback-only and serves only `getAccountTokens`, `getAccountNfts`,
`getAccountEvents` and `getAccountEvent`; keep it out of public proxy routes.
Omitting `--index-address` makes the aggregate methods report index disabled.

## Replay, retention and restarts

A fresh index starts at masterchain block 1. It follows the source shard-client
cursor, which represents applied masterchain and referenced shard data. Every
interval walks full shard block identities, including split/merge predecessors,
and processes parents before children. It verifies block root hashes and refuses
a different chain anchor or a discontinuous masterchain sequence.

Keep the complete block archive from block 1 on the source, including through
bootstrap, recovery and a full rebuild. The default seven-day archive retention
is insufficient for rebuilding an older chain: configure `--archive-ttl` to cover
the chain's full age and the planned rebuild/outage period, and monitor available
disk space. An index process cannot hold back another process's archive pruning.
Missing or pruned blocks pause replay at its durable cursor; they never cause a
skip. Restore the archive before restarting replay. Historical shard *states*
are not required: pending token candidates use current shard states.

Index entries and a per-block replay receipt commit in one WAL-synced batch.
After all blocks in an interval are committed, another atomic batch advances the
masterchain cursor and removes that interval's receipts. SIGKILL between these
steps causes bounded replay; committed receipts prevent duplicate effects.
SIGTERM stops the replay thread and closes its database before process teardown.
Neither shutdown method permanently marks the new index as needing a rebuild.

`GET /readyz` on the index service reports its replay cursor, observed source tip
and whether block replay has caught up (HTTP 200/503). Readiness expires if the
source has not been checked successfully for five seconds. Token and NFT responses
retain `index_state` and add `index_state.replay`. Pending, parked, lost or
unfinished candidates still make `index_state.complete` false independently of
block catch-up. Ownership discovery covers accounts nominated by transactions;
custom genesis token/NFT contracts that never transact are outside that coverage.
Event retention remains bounded by the existing index's age and per-account limits.

## Migrate or rebuild

1. Keep the old `<node-db>/wc0-index` for rollback; the new node ignores it.
2. Start the index with a **fresh** service data directory and the retained archive.
   A legacy embedded index has no replay checkpoint and cannot be resumed safely.
3. Start `tos-rpc` with the liteserver and index addresses. Wait for replay to catch
   up and inspect token completeness before moving the wallet proxy endpoint.
4. Keep operator RPC on validator loopback. A previous public validator RPC bind
   now fails startup explicitly; move that bind to `tos-rpc`.

For a rebuild, stop the index service and select a new data directory. The source
node and public RPC can keep running. Do not delete or overwrite the node database.
The new index replays history; it does not merely erase the old warning.

## Limits and failure handling

The RPC transport admits at most 128 outstanding liteserver queries (each request
at most 4 MiB) and 16 index HTTP queries. Index HTTP responses are bounded by the
HTTP parser and an additional 16 MiB accumulation ceiling; timeout or disconnect
releases the request actor and its connection. Writes are not retried by the RPC
adapter. Saturation/backend failure returns an RPC error; it does not fall back
to an embedded validator index.

Replay holds one source request at a time, at most 4096 shard identities per
masterchain interval, and opens at most 128 archive packages. Its cell block cache
is configured to 128 MiB. A source request that fails to finish within 30 seconds
stops the service with exit status 1; restart resumes its durable cursor. The existing bounded token
backlog and per-block verification gas budgets remain in effect. Disk usage for
indexed owners follows the account population; event retention is bounded as
before. Monitor process memory, source archive retention, cursor lag and disk space.
