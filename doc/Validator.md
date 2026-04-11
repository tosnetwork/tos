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
  -l /data/tos/logs/validator-engine.log
```

Useful options:

- `-t`: worker threads
- `--parallel-validation`: enable account-level parallel validation
- `--collect-validator-telemetry`: export validator telemetry
- `--db-event-fifo`: publish DB events
- `--exporter-address`: bind metrics exporter

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
