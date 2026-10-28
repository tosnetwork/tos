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

After genesis, native TOS is created only per produced block under
ConfigParam 14 and routed to validators. ConfigParams 6 and 7 govern
extra-currency operations and do not control this native block creation.
The production template calibrates ConfigParam 14 so that the validator
bootstrap reaches approximately 10,000,000 TOS gross over roughly two years,
including the 101,000-TOS genesis supply. The rate is flat and continues until
governance changes it; the later policy target of about 2% of the prevailing
supply per year needs that separate ConfigParam 14 change. There is no fixed
maximum supply. Nothing beyond the 101,000-TOS bootstrap supply is created at
genesis, and none of these targets is a hard consensus cap.

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
- `actual_min_split = 0`, `min_split = 0`, `max_split = 2`: the basechain
  starts as one shard and load can split it into at most four. Mainnet-scale
  networks use these limits; a forced `min_split` multiplies the consensus
  groups every validator runs.
- `workchain_v2` constructor with the default split/merge timings written
  explicitly (100 s delay, 100 s interval, 30 s minimum interval, 1000 s
  maximum delay) and `persistent_state_split_depth = 4`, so the basechain's
  persistent state is serialized in 16 parts.

Descriptors for unsupported execution domains are not valid for this binary because their execution engines are not registered.

## References

- [ConfigParam.md](ConfigParam.md)
- [Validator-led token economics](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-validator-only-token-economics.md)
- [gen-zerostate.fif](../crypto/smartcont/gen-zerostate.fif)
