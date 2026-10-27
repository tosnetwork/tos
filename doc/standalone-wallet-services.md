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
  --submission-address 127.0.0.1:8082 \
  --listen 127.0.0.1:8080
```

The submission backend is the same-version node's private operator RPC, configured
with `--json-rpc-address 127.0.0.1:8082 --json-rpc-trust-proxy-headers`.
Use a non-validating full-node replica for this endpoint when possible. The public
RPC forwards only write methods there; chain reads continue through liteservers.
A write-enabled `tos-rpc` requires `--submission-address`; use `--readonly` when no
submission backend is configured. The backend must belong to the same network as
the liteservers and index. These internal endpoints must not be public proxy routes.

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

The frontend resolves the client IP using its trusted-proxy policy, then replaces
forwarded identity with that validated IP on each internal HTTP hop. The index
listener trusts loopback proxy headers. The submission backend must also enable
proxy attribution: a reserved `_tos_relay_source` assertion is overwritten by the
frontend and checked against the backend's resolved source before submission.
A mismatched or disabled backend proxy policy returns an RPC error. The backend
retains its per-client mempool submission limits; the shared liteserver connection
is never used for writes. Keep loopback listeners accessible only to trusted local
processes, and use the same service/node release for this assertion protocol.
If using a TLS reverse proxy, enable `--trust-proxy-headers` on `tos-rpc` and ensure
the proxy replaces client-supplied identity headers.

`getConsensusBlock`, `getMasterchainBlockSignatures`, and `getNodeConsensusStatus`
require a local validator manager and are not served by `tos-rpc`. They return
method-not-found and are omitted from its `/api-info` listing.

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
at most 4 MiB), 16 index HTTP queries and 16 submission HTTP queries, each with a
4 MiB request ceiling. These are separate aggregate concurrency budgets, not
per-client rate buckets. Each HTTP response is bounded by the
HTTP parser and an additional 16 MiB accumulation ceiling; timeout or disconnect
releases the request actor and its connection. Writes are not retried by the RPC
adapter. Saturation/backend failure returns an RPC error; it does not fall back
to an embedded validator index.

Replay holds one source request at a time and at most 4096 shard identities per
masterchain interval. Its cell block cache is configured to 128 MiB.

Source archive slices are opened on demand and closed by an LRU. A slice weighs
its package files plus five for its index database. Older slices of a long chain
often weigh several hundred. A validator closes the least recently used slices,
including the one just read, whenever the total exceeds its target. A reader
that reads one old slice many times in a row would then reopen that slice's
database for every read. The index therefore:

- keeps the `--archive-keep-recent` (default 2, at most 16) most recently read
  slices open past the target. Two cover a replay that crosses a slice boundary
  and alternates between the two slices; 0 restores the validator behaviour.
- closes other non-permanent slices above `--archive-open-files` (default 128,
  the target).
- never closes the newest normal, key and temp slices: they are written by the
  node and are permanent.

The descriptors held are therefore the permanent slices, plus up to
`--archive-keep-recent` retained slices, plus the target, plus the index's own
databases and sockets. Because that sum depends on slice sizes, it is bounded by
a descriptor budget:

1. At startup the soft `RLIMIT_NOFILE` is raised to the hard limit. The service
   exits with status 2 when the limit is below `--archive-open-files` + 1280.
2. The budget is the limit less 256. While the descriptors the process holds
   plus 128 exceed the budget, retained and other non-permanent slices are
   closed oldest first.
3. Every archive slice open is admitted on its own demand before anything is
   opened. The demand is every file in the slice's index directory, since a
   secondary keeps all its table files open, plus one descriptor per package,
   checked again before the packages are opened. Catching up an open slice is
   admitted the same way, for its new files. Every source read is also admitted
   for 128 descriptors beyond the slices it opens. No weight seen earlier is
   assumed for the next open.
4. When an open or a read does not fit, it is refused before anything is opened,
   and the query fails instead of the process. If closing archive slices would
   make room, the LRU is asked to close enough for that demand, and replay
   pauses at its durable cursor and retries after five seconds.
5. If nothing the process can close would make room (a shortage), the refusal
   says by how much the descriptor limit must be raised. After three consecutive
   replay steps that end in a shortage, replay stops: the service logs
   `replay stopped: too few file descriptors (...)` and exits with status 3.
   The cursor is durable; restart after raising `LimitNOFILE`.

`--archive-keep-recent 0 --archive-open-files 1024` is the control setting for
comparing against a larger target without retention. A source request that fails to finish within 30 seconds
stops the service with exit status 1; restart resumes its durable cursor.
Cancellation refuses new source requests, clears undispatched mailbox entries and
stops the current bounded candidate drain without losing its persisted work. The existing bounded token
backlog and per-block verification gas budgets remain in effect. Disk usage for
indexed owners follows the account population; event retention is bounded as
before. Monitor process memory, source archive retention, cursor lag and disk space.
