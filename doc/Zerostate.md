# Zerostate

This document describes the current native zero-state layout for the focused TVM execution surface.
AI actor deployments inherit this same genesis model; agent, task, service, and verifier contracts are ordinary native accounts unless a future launch profile explicitly predeploys them.

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

Only the native zero-state template is valid for current genesis generation.

## Initial Supply

The production validator-led zerostate creates a provisional **101,000 TOS**:
100,000 TOS in a bounded validator-bootstrap wallet and 500 TOS in each of the
Elector and Configuration contracts.

Nearly all remaining native TOS is created per produced block under
ConfigParam 14. ConfigParams 6 and 7 govern extra-currency operations and do
not control this native block creation. Five billion TOS over roughly seven
years is a policy calibration target; it is not fully created at genesis and
is not a hard consensus cap.

Production genesis does not allocate native funds to AI actor bootstrap
programs. Those accounts and services must be deployed later through auditable
ordinary transactions.

PoW/test giver contracts are not registered in the genesis templates and do not receive a genesis balance. The standalone giver scripts are test/deployment tools only.

Do not encode off-chain model endpoints, private prompts, service API keys, or large evidence payloads into zero-state. Store only addresses, balances, code/data cells, and compact metadata references that are safe to publish.

## Workchain Descriptors

`ConfigParam 12` should contain only the native basechain descriptor:

- `workchain_id = 0`
- `vm_version = -1`
- TVM execution

Descriptors for unsupported execution domains are not valid for this binary because their execution engines are not registered.

## References

- [ConfigParam.md](ConfigParam.md)
- [Validator-led token economics](tos-validator-only-token-economics.md)
- [gen-zerostate.fif](../crypto/smartcont/gen-zerostate.fif)
