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

An archive reader can discover a package just before the source prunes it. If
its lazy index open then fails, queries return `notready` and the slice remains
closed; a secondary's next catch-up retires the deleted package. A missing or
unopenable global archive index also reports `notready`, with a new open attempt
on later queries, so restoring the source index does not require restarting the
reader. These refusals do not recreate source indexes or repair package files.
Warnings are limited to one per minute for each slice and for the global index.
The owning node still treats an index it cannot open as a fatal local fault.

### Preparing the source node

A node that joins the network the default way starts at the newest persistent
state, so its database never contains masterchain block 1, and validators no
longer serve the oldest archive packages to a node that asks for them. Such a
node can serve liteserver reads but cannot be the source of a fresh index. The
index then logs `source has no masterchain block 1` every few seconds and reports
`"initialized": false` in `/readyz`; nothing is indexed and nothing is lost.

To prepare a source for a full replay:

1. Obtain archive packages from masterchain block 0 up to some later block: a
   copy of another node's `<db>/archive/packages/` tree (`arch*/archive.*.pack`
   and `key*/`), with a SHA-256 manifest from its operator. Verify every file
   against the manifest, for example `sha256sum -c packages.SHA256SUMS`.
2. Create a **fresh** node database and place the packages under `<db>/import/`,
   keeping their directory layout. The node imports every `archive.*.pack` it
   finds there at startup. Packages are checked block by block from the zero
   state as they are applied, so a damaged or foreign package stops the import
   and is not accepted.
3. Start the node with `--skip-key-sync`, so it starts from the zero state in
   the global configuration instead of the newest persistent state. Set
   `--archive-ttl` to cover the chain's age and the planned rebuild time. The
   network supplies the blocks after the last imported package.
4. Start the index against this database. It records its first checkpoint once
   block 1 has been applied. Check progress with `GET /readyz` (below).

An existing node that joined at a persistent state cannot be converted in place:
its database starts after block 1. Prepare a second node as above.

Index entries and a per-block replay receipt commit in one WAL-synced batch.
After all blocks in an interval are committed, another atomic batch advances the
masterchain cursor and removes that interval's receipts. SIGKILL between these
steps causes bounded replay; committed receipts prevent duplicate effects.
SIGTERM stops the replay thread and closes its database before process teardown.
Neither shutdown method permanently marks the new index as needing a rebuild.

`GET /readyz` on the index service reports its replay cursor, observed source tip
and whether block replay has caught up (HTTP 200/503). Readiness expires if the
source has not been checked successfully for five seconds. The fields are:

- `masterchain_seqno`: the durable replay cursor. It is read from the index
  before the service listens, so the first answer after a restart already shows
  the cursor replay resumes from. It is `null` only for an index that has never
  recorded a checkpoint (a fresh directory), and `initialized` is then `false`.
- `source_seqno`: the source tip, `null` until the source has been read once.
- `caught_up`: whether replay has reached the observed tip. Readiness expires
  five seconds after the tip was *asked for*, not after the replay that
  followed finished, so a slow walk or a source that stops answering never
  makes an old observation look fresh.
- `replay_ceiling`: the `--replay-ceiling` value, `null` without one.
- `settled`: replay has reached its limit (the tip, or the ceiling below it)
  and the last token-candidate pass had nothing left to do.
- `replay_stats` (readiness only): cumulative counters since the process
  started: `mc_blocks`, `shard_blocks`, `source_requests` (every source read
  issued, by the replay or the prefetch thread), `source_wait_ms` (time the
  replay thread waited for source results), of which `prefetch_wait_ms` (waits
  for blocks read ahead), `source_completed` and `source_service_ms` (reads
  completed and their summed time from issue to completion),
  `source_outstanding_high_water` and `prefetch_bytes_high_water` (the most
  reads outstanding at once and the most read-ahead bytes held), `catch_ups`
  and `catch_up_ms` (observing the source tip), `walk_ms` (indexing shard
  blocks, including their write batches), `commits` and `commit_ms`
  (checkpoint advances), `drains` and `drain_ms` (token-candidate passes),
  `archive_slice_opens` and `archive_slice_closes` (source archive slice
  databases opened and closed), and `open_fds` (descriptors held, sampled once
  a second). The service also logs the change of these counters every 60
  seconds (`replay stats over 60s: ...`). A count of slice opens close to the
  count of source requests means the source archive slices are being reopened
  for each read.

`--replay-ceiling <seqno>` stops replay at that masterchain block, for
measurement and for comparing two replays of the same source. The index never
reports `caught_up` while it stops short of the source tip. A ceiling below the
index's durable cursor is refused (`durable index progress is past the replay
ceiling`): replay cannot go back, so such a run would never settle. To compare two
replays, stop both once `settled` is true at the same ceiling, then print each
index with `tos-wallet-index-dump --index-dir <data-dir>/index` (read-only; one
line per key and the digest of all of them) and compare the output.

`index_state.replay` in token and NFT responses carries the same fields except
`replay_stats`. Token and NFT responses
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

Replay reads ahead of its cursor: a prefetch thread reads up to 8 masterchain
intervals past the checkpoint, never past the observed tip, while the replay
thread walks and commits them in order. Only the replay thread changes the
index, the checkpoint or the reported cursor, and it repeats every application,
ancestry and root-hash check on what was read ahead. At most 8 source reads are
outstanding at once (queued, running, or completed and not yet walked), one of
them always kept for the replay thread's own reads. Read-ahead memory is
bounded twice over:

- *By count.* Read-ahead keeps blocks as serialized bytes only. Each
  read-ahead block read reserves 4 MiB (the largest block the read-ahead
  takes) plus 4 KiB before it is issued, and once it completes keeps exactly
  its serialized size plus 4 KiB, in a buffer holding only that block. No
  completion can grow a charge. Cells are decoded by the thread that uses a
  block: the replay thread decodes each shard block when it takes it, one at a
  time as before, and the prefetch thread decodes one masterchain block at a
  time to read its shard heads, keeping only the heads. Every handle a
  read-ahead interval keeps is charged 1 KiB. With 7 read-ahead places and 8
  intervals of at most 4096 shard blocks, that is at most
  7 x (4 MiB + 4 KiB) + 8 x 4097 KiB, about 60 MiB, of which the block bytes
  are at most min(7, 15) worst-case reservations (15 fit in 64 MiB).
- *By budget.* The charges above are also held to 64 MiB: a read waits until
  its reservation fits, except the read the replay thread needs next, which is
  admitted when nothing else is read ahead.

Besides these, at most two blocks are decoded at once: the shard block the
replay thread is walking and the masterchain block the prefetch thread is
reading heads from. The masterchain block comes from at most 4 MiB of
serialized bytes; so does the shard block, except a block over 4 MiB, which
the replay thread reads and decodes whole, as before.

A block larger than 4 MiB is not read ahead: the archive refuses it after
reading only its entry header, before allocating its bytes, and the replay
thread reads and decodes that block itself on its own lane when it reaches it,
as replay did before reading ahead (for a masterchain block, the replay thread
reads that whole interval itself). `replay_stats` reports the highest charge
reached (`prefetch_bytes_high_water`); compare it with the process's resident
memory, which this bound does not include. A source request that completes
after its 30 s deadline is treated as timed out and its result is never handed
over. A full
limit makes readers wait; it never fails a replay. A failed read is reported
when the replay thread reaches that block, after the blocks before it have been
committed, and everything read ahead is then dropped and read again. Replay
holds at most 4096 shard identities per masterchain interval, and configures
an archive LRU eviction target of 128 files. This is not a hard
ceiling: the newest normal/key/temp slices are permanent, and package files open
before eviction. File descriptors and transient usage can exceed this target. Its cell block cache
is configured to 128 MiB. A source request that fails to finish within 30 seconds
stops the service with exit status 1, whether or not anything still waits for
it; restart resumes its durable cursor. Cancellation refuses new source
requests, wakes every waiting reader, drops queued requests unrun and stops the
current bounded candidate drain without losing its persisted work. The existing bounded token
backlog and per-block verification gas budgets remain in effect. Disk usage for
indexed owners follows the account population; event retention is bounded as
before. Monitor process memory, source archive retention, cursor lag and disk space.
