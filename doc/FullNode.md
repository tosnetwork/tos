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
- [ai-actors.md](ai-actors.md)
