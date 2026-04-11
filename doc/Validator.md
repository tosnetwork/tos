# Running a TOS Validator

This guide describes the operator view of the validator stack in this repository.

## Main Components

- [validator-engine](../validator-engine)
- [validator-engine-console](../validator-engine-console)
- [lite-client](../lite-client)

## Validator vs Full Node

- a full node follows and serves chain data
- a validator additionally manages validator keys, consensus participation, and stake-related operations

## Required Artifacts

- global config
- local validator config
- validator keys
- persistent database directory
- Fift scripts directory

## Starting the Validator Engine

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

### Required Launch Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `--initial-sync-delay` | `5` (seconds) | Delay before starting validation to allow initial state sync. Without this, ADNL handshake fails and liteserver connections time out. |
| `--quic-flood-control` | `-1` (disabled) | Disable QUIC flood control. Required for local/small networks. Without this, peer-to-peer communication may stall. |

These parameters are required for the node to accept external connections (lite-client, validator console). Omitting them causes the node to appear active but reject all ADNL handshakes.

### Optional Parameters

- `-t <N>`: worker threads (default: 7)
- `--parallel-validation`: enable account-level parallel validation
- `--collect-validator-telemetry`: export validator telemetry
- `--db-event-fifo`: publish DB events
- `--exporter-address`: bind metrics exporter
- `--session-logs <file>`: validator session statistics

## Using Validator Console

Connect with:

```bash
cd build
./validator-engine-console/validator-engine-console \
  -a <server-address> \
  -k <client-private-key> \
  -p <server-public-key>
```

Use the console for:

- key and permission management
- operational introspection
- validator maintenance actions
- governance and network management flows supported by the node

## Operating Guidelines

- rotate keys deliberately and document every change
- separate node identity, validator keys, and operator credentials
- pin logs and DB paths explicitly
- monitor sync status before attempting validator operations
- stage config or governance changes before main deployment

## Related Docs

- [FullNode.md](FullNode.md)
- [ConfigParam.md](ConfigParam.md)
- [Tests.md](Tests.md)
