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

## Full-Node Masters and Slaves

A node can serve chain data to a fixed set of other nodes ("slaves") through
the full-node master service, configured by `fullnodemasters` entries (an
external port and an ADNL id) in the local config. A slave lists its masters in
`fullnodeslaves` (each master's address and ADNL public key) and signs in to
them with its own full-node ADNL key.

The master service is **allowlist-only**:

- Start the master with one `--full-node-master-trusted <adnl-id-hex>` per
  slave it serves (at most 8). The id is the slave's full-node ADNL id.
- A node configured with `fullnodemasters` but no `--full-node-master-trusted`
  id **refuses to start** (exit code 2) with an error naming the missing
  option. There is no open mode: remove the `fullnodemasters` entries if the
  node should not serve slaves.
- Every request from a source that is not a configured slave is refused before
  it is charged to any budget. This includes external connections that do not
  sign in, and connections that sign in with any other key.
- The service budget is 16 requests of burst and 4 requests per second in
  total, across every master port of the node. Each configured slave gets an
  equal, independent share of both (with two slaves, 8 of burst and 2 per
  second each). No other source, and no other slave, can use a slave's share;
  a slave that has used its share is refused until it refills. The set is read
  once at startup; changing it needs a restart.

A slave must sign in with the key of its configured full-node ADNL id:

- A node configured with `fullnodeslaves` but without a full-node ADNL id, or
  whose keyring does not hold that id's private key, **refuses to start**
  (exit code 2). It never falls back to an anonymous connection, which every
  master would refuse.
- A slave whose full-node ADNL id changes must be restarted to sign in with the
  new key, and each of its masters must list the new id.

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
