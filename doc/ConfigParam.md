# TOS Configuration Parameters

This document explains how configuration parameters work in TOS and how operators should approach changes safely.

## What Config Params Are

Configuration parameters are protocol values stored in masterchain state. They affect validator behavior, core contracts, feature flags, fees, limits, and network policy.

The canonical schema lives in [block.tlb](/home/tomi/tos/crypto/block/block.tlb). In particular:

- `ConfigParam 0`: config contract address
- `ConfigParam 1`: elector contract address
- `ConfigParam 4`: DNS root address
- `ConfigParam 8`: global version and capability bits

## Operational Model

- Validators read active config from masterchain state.
- Config changes are not "local settings"; they are on-chain state transitions.
- A proposal becomes effective only after it is accepted by the chain governance flow implemented by core contracts and validator software.

## Recommended Workflow

1. Inspect the current value with `lite-client`.
2. Prepare a replacement payload as a BoC or structured Fift/TL-B value.
3. Review the schema in [block.tlb](/home/tomi/tos/crypto/block/block.tlb) before publishing anything.
4. Use a staging or test environment first.
5. Only then coordinate voting or governance activation.

## Inspecting Current Values

Build the project first using [BUILD.md](/home/tomi/tos/BUILD.md), then run:

```bash
cd /path/to/tos/build-clang21
./lite-client/lite-client -C /path/to/tos-global.config.json
```

Inside the client:

```text
getconfig 8
getconfig 18
getconfig 20
getconfig 21
```

Use the output together with [block.tlb](/home/tomi/tos/crypto/block/block.tlb) to interpret fields precisely.

## Preparing a Change

There is no single safe "edit config" shortcut. The correct method depends on the target parameter:

- simple cells can be built directly in `fift`
- more structured values should be generated from the actual TL-B layout
- critical updates should be reviewed together with validator operators before any on-chain submission

Relevant tools in this repository:

- [fift](/home/tomi/tos/build-clang21/crypto/fift)
- [lite-client](/home/tomi/tos/build-clang21/lite-client/lite-client)
- [validator-engine-console](/home/tomi/tos/build-clang21/validator-engine-console/validator-engine-console)
- [create-state](/home/tomi/tos/build-clang21/crypto/create-state)

## Safety Rules

- Never change a config param unless you know its exact TL-B shape.
- Treat `ConfigParam 8` and validator-related params as high-risk changes.
- Keep a record of the previous value and hash before proposing a replacement.
- Coordinate validator rollout before activating protocol-level changes.
- Test every proposal in a disposable environment when possible.

## Related Files

- [block.tlb](/home/tomi/tos/crypto/block/block.tlb)
- [GlobalVersions.md](/home/tomi/tos/doc/GlobalVersions.md)
- [Validator.md](/home/tomi/tos/doc/Validator.md)
- [LiteClient.md](/home/tomi/tos/doc/LiteClient.md)
