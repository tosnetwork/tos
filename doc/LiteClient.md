# Using the TOS Lite Client

The lite client is the fastest way to inspect chain state, configs, blocks, and DNS without operating the full validator stack.

## Build

Use the verified build flow in [BUILD.md](/home/tomi/tos/BUILD.md).

The binary is:

- [lite-client](/home/tomi/tos/build-clang21/lite-client/lite-client)

## Required Inputs

- a recent global config file
- an optional local database directory for cache and state

## Basic Launch

```bash
cd /path/to/tos/build-clang21
./lite-client/lite-client \
  -C /path/to/tos-global.config.json \
  -D /path/to/lite-client-db
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
  -C /path/to/tos-global.config.json \
  -D /path/to/lite-client-db \
  -c "getconfig 8"
```

## Troubleshooting

If the client cannot connect:

- confirm the global config file is current
- verify liteserver reachability
- check public key and address pairing when using explicit targets
- use a writable DB directory

## Related Docs

- [DNS.md](/home/tomi/tos/doc/DNS.md)
- [ConfigParam.md](/home/tomi/tos/doc/ConfigParam.md)
- [FullNode.md](/home/tomi/tos/doc/FullNode.md)
