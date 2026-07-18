# Zerostate

This document describes the current native-only zero-state layout.

## Scope

The canonical zero-state registers only the native chains:

| Chain | Workchain id | Execution |
|---|---:|---|
| Masterchain | `-1` | consensus and configuration |
| Basechain | `0` | native TVM |

## Templates

| File | Purpose |
|---|---|
| `crypto/smartcont/gen-zerostate.fif` | Canonical native zero-state template |
| `test/tostester/src/tostester/zerostate.py` | Local testnet zero-state generation |

The deleted multi-workchain templates and helper scripts must not be used for current genesis generation.

## Initial Supply

The native TOS supply is set at zero-state construction time. It is not controlled by ConfigParams 6 or 7, which are for extra currencies.

To change the TOS target supply, update the main-wallet allocation in the native zero-state template and the matching testnet generator.

## Workchain Descriptors

`ConfigParam 12` should contain only the native basechain descriptor:

- `workchain_id = 0`
- `vm_version = -1`
- TVM execution

Descriptors for the removed custom workchains are not valid for this binary because their execution engines are no longer registered.

## References

- [ConfigParam.md](ConfigParam.md)
- [gen-zerostate.fif](../crypto/smartcont/gen-zerostate.fif)
