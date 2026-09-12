# Using the TOS Lite Client

The lite client is the fastest way to inspect chain state, configs, blocks, and DNS without operating the full validator stack.

For AI actor workflows, it is useful for read-only inspection of agent accounts, task contracts, service actor addresses, and verifier outputs during development and operations.

## Build

Use the verified build flow in [BUILD.md](../BUILD.md).

The binary is:

- [lite-client](../lite-client)

## Required Inputs

- a recent global config file
- an optional local database directory for cache and state

## Basic Launch

```bash
cd build
./lite-client/lite-client \
  -C /data/tos-global.json \
  -D ./lite-client-db
```

## Useful Flags

- `-C`: global config
- `-D`: local DB root
- `-a`: connect to an explicit liteserver address
- `-p` or `-b`: remote public key
- `-c`: run a single command in batch mode
- `-t`: timeout in batch mode

## Common Interactive Commands

Typical tasks:

```text
last
getconfig 8
getconfig 4
dnsresolve <domain> 1
```

Use the lite client for read-only operational inspection first. Reach for validator console only when you need node control operations.

## Batch Mode

For automation:

```bash
./lite-client/lite-client \
  -C /data/tos-global.json \
  -D ./lite-client-db \
  -c "getconfig 8"
```

## Troubleshooting

If the client cannot connect:

- confirm the global config file is current
- verify liteserver reachability
- check public key and address pairing when using explicit targets
- use a writable DB directory

## Related Docs

- [DNS.md](DNS.md)
- [ConfigParam.md](ConfigParam.md)
- [FullNode.md](FullNode.md)
- [ai-actors.md](ai-actors.md)
