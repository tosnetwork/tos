# Running a TOS Full Node

This guide covers the direct binary workflow for running a TOS full node from this repository.

## Components

- `validator-engine`: the main node process
- `validator-engine-console`: control interface
- `lite-client`: inspection and troubleshooting

## Before You Start

- Build the project with [BUILD.md](/home/tomi/tos/BUILD.md)
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
cd /path/to/tos/build-clang21
./validator-engine/validator-engine \
  -C /data/tos/global-config.json \
  -c /data/tos/local-config.json \
  -D /data/tos/db \
  -f /path/to/tos/crypto/fift/lib \
  -I <public-ip>:<port> \
  -l /data/tos/logs/validator-engine.log
```

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

## Related Docs

- [Validator.md](/home/tomi/tos/doc/Validator.md)
- [LiteClient.md](/home/tomi/tos/doc/LiteClient.md)
- [Tests.md](/home/tomi/tos/doc/Tests.md)
