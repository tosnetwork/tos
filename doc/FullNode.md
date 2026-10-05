# Running a TOS Full Node

This guide covers the direct binary workflow for running a TOS full node from this repository.

For AI actor deployments, a full node is the strongest read path for agents, service operators, and verifier actors that need locally verified task state, balances, permissions, and settlement outcomes.

## Components

- `validator-engine`: the main node process
- `validator-engine-console`: control interface
- `lite-client`: inspection and troubleshooting

## Before You Start

- Build the project with [BUILD.md](../BUILD.md)
- Prepare a global config file
- Prepare a local validator config file
- Ensure the machine has stable storage, bandwidth, and public connectivity

## Basic Startup

Example structure:

```text
/data/tos/
  db/
  logs/
  fift/
  global-config.json
  local-config.json
```

Start the node:

```bash
cd build
./validator-engine/validator-engine \
  -C /data/tos/global-config.json \
  -c /data/tos/local-config.json \
  -D /data/tos/db \
  -f ./crypto/fift/lib \
  -I <public-ip>:<port> \
  --initial-sync-delay 5 \
  --quic-flood-control -1 \
  -l /data/tos/logs/validator-engine.log
```

> **Note:** `--initial-sync-delay` and `--quic-flood-control -1` are required for ADNL connectivity. See [Validator.md](Validator.md) for details.

## Important Runtime Options

Useful flags from the current binary:

- `-C`: global config
- `-c`: local config
- `-D`: database root
- `-I`: advertised node address
- `-f`: Fift script directory
- `-t`: thread count
- `--parallel-validation`: enable parallel validation across accounts
- `--permanent-celldb`: archival-style cell retention
- `--unsynced-liteserver`: allow liteserver queries before full sync

## Sync and Storage

Plan separately for:

- hot database storage
- archived blocks
- logs
- metrics

Use dedicated storage paths and monitor disk growth continuously.

## Wallet Index

A node started with `--json-rpc-address` keeps a basechain wallet index under
`<db root>/wc0-index` for the account-index JSON-RPC methods
(`getAccountJettons`, `getAccountNfts`, `getAccountEvents`,
`getAccountEvent`). The index is built in the background, so the token lists
from `getAccountJettons` and `getAccountNfts` carry an `index_state`; read
`"complete": false` as "this list may be missing entries", not as the whole
truth.

- **Token candidates are never dropped for lack of room.** Candidates a block
  cannot verify at once wait in a bounded backlog (`pending`). When the
  backlog is full, the rest of the block's candidates are stored with the
  block, which stays unfinished (`unfinished_block`); the indexing worker
  verifies them by itself, against the newest state the node has, also after
  a restart and with no new block arriving. At most 1024 blocks can be
  unfinished this way; past that the worker finishes them before indexing
  more. A candidate whose verification stays indeterminate through every
  attempt, or needs the state of another shard the node does not have yet
  (a jetton master or NFT collection elsewhere), is `parked`: it is kept,
  retried by the worker in bounded rounds against each shard's newest state,
  and released only on a definite result. Any of these keeps
  `"complete": false`.
- **The index holds back archive pruning for blocks it has yet to read.** A
  block applied but not yet indexed (still queued, or only marked because
  the indexer was behind) is kept by the archive, past `--archive-ttl` if
  need be, until its token candidates are indexed or stored with it. On the
  next start the indexer reads such blocks back and indexes them first.
- **Jetton rows from older index versions are not served until verified.**
  An index upgraded from a version that kept no pair record per jetton row
  may hold owner/master mappings that have since changed. Those rows are left
  out of `getAccountJettons` (`"legacy_unverified": true`) while the indexing
  worker verifies each row's wallet against chain state, removes the stale
  ones, and records the rest; the verified rows are published together once
  none is left undecided. A row that cannot be verified on this node keeps
  them all unpublished and the index incomplete.
- **Stopping the node marks the index as incomplete.** Only an exit that
  happens after block application has stopped records the indexing run as
  finished. `systemctl stop` (SIGTERM), a crash, an out-of-memory kill and a
  scheduled shutdown do not. The next start then reports `"needs_rebuild":
  true` and `"complete": false` from then on, because a block applied just
  before the stop may never have reached the index.
- **There is no rebuild, only a reset.** Nothing recovers the entries such an
  index may be missing. Deleting `<db root>/wc0-index` while the node is
  stopped resets it to a fresh, forward-only index: the warning goes away,
  but the new index holds only blocks applied after the reset. Entries for
  earlier blocks, including any the old index was missing, are not recovered,
  because the index never replays history.
- **An index that cannot be opened is reported, not hidden.** If the index
  database fails to open (for example a lock held by another process, a disk
  fault, or a schema it cannot migrate), the node runs without indexing, logs
  the reason once at startup, and these methods answer with error -32603
  "wallet index unavailable on this node: ...". A node started without
  `--json-rpc-address` keeps no index, and these methods answer -32601
  "wallet index disabled on this node".

## Operational Checks

Use the console and lite client to confirm:

- node is reachable
- sync progresses
- no repeated catchain or overlay failures
- disk and archive policies are sane

## Recommendations

- Run as a service user
- Keep logs on a separate volume when possible
- Pin a consistent global config per environment
- Upgrade binaries and configs together, not independently

## AI Actor Operations

Operators running AI agents or service actors should prefer a local full node when:

- agents manage funds or task escrow
- verifier services make acceptance or dispute decisions
- service actors need reliable payment-settlement checks
- workflow systems must avoid trusting third-party indexed data for balances or permissions

## Related Docs

- [Validator.md](Validator.md)
- [LiteClient.md](LiteClient.md)
- [ai-actors.md](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/ai-actors.md)
