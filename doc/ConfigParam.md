# Configuration Parameters

This document tracks the configuration parameters used by the current native TOS build for actor-based applications.
AI actor features that need consensus-level activation, such as task deadline semantics, delivery failure records, or future service-actor pricing rules, should be introduced through explicit configuration and versioning rather than hidden local defaults.

The canonical TL-B schema is in [block.tlb](../crypto/block/block.tlb). Initial values are set during [zero state generation](Zerostate.md).

## Native TVM Scope

Additional execution-domain activation, gas, RPC, and chain-specific ConfigParam descriptions are intentionally absent from this native TVM tree.

The current node registers:

| Workchain | Execution | Descriptor |
|---|---|---|
| masterchain (`-1`) | consensus/config | reserved |
| basechain (`0`) | TVM | `vm_version = -1` |

## ConfigParam 8

`ConfigParam 8` is the `GlobalVersion`: `version:uint32 capabilities:uint64`. It is
treated as all-zero when absent. `version` gates protocol behaviour by height (for
example the storage-dict-hash serialization at version 11); `capabilities` is the
bitmask of activated global capabilities defined in [tos-types.h](../tos/tos-types.h).

Capabilities are the activation switch for consensus-level features and MUST be turned
on here rather than through a local default. The current bits, low to high, are
`capIhrEnabled(1)`, `capCreateStatsEnabled(2)`, `capBounceMsgBody(4)`,
`capReportVersion(8)`, `capSplitMergeTransactions(16)`, `capShortDequeue(32)`,
`capStoreOutMsgQueueSize(64)`, `capMsgMetadata(128)`, `capDeferMessages(256)`,
`capFullCollatedData(512)`, and `capAipow(1024)`.

`capAipow` gates the entire AIPoW native-issuance mint path and its parameter set
(ConfigParams 90–93). It is off in the genesis template; the mint path stays inert
until governance sets this bit. When it is set, a block — and zero-state generation —
is valid only if the complete, mutually consistent AIPoW parameter set is present
(see [GlobalVersions.md](GlobalVersions.md) and the AIPoW section below).

## ConfigParam 12

`ConfigParam 12` stores the workchain descriptor dictionary. In the current build it should contain only the native basechain descriptor for wc=0.

Validators register the native TVM execution engine. A descriptor for an unsupported workchain would not be executable by this binary.

AI actor applications should be deployed as native TVM contracts on wc=0 unless a future approved protocol change defines otherwise.

## ConfigParams 6 and 7

ConfigParams 6 and 7 govern extra currencies. They do not define the native TOS supply.

The native TOS supply is set at zero-state construction time in the genesis template; see [Zerostate.md](Zerostate.md).

## ConfigParam 14

`ConfigParam 14` is `BlockCreateFees`: `masterchain_block_fee:Tomis basechain_block_fee:Tomis`.
It sets the per-block creation fee credited for producing a masterchain or basechain
block. When the parameter is absent both fees are treated as zero. These are the
block-production fees only; they do not define the native TOS supply and are separate
from any future service-actor pricing rules.

## ConfigParams 90–93 (AIPoW native issuance)

These four parameters carry the Phase C AIPoW native-issuance configuration. They are
absent unless `capAipow` (ConfigParam 8) is activated. They are governance-set,
immutable inputs: the running supply ledger is **not** here — it lives in the AIPoW
settlement contract's own state. With `capAipow` set, block validation and zero-state
generation require this set to be present, complete, and mutually consistent; a partial
or malformed set is a hard error, never a silent default.

| Param | Type | Contents |
|---|---|---|
| **90** | `AipowConfig` | emission schedule slope `k_num/k_den`, `schedule_cap`, `cold_start_floor`, and the challenge multiplier `challenge_mult_num/challenge_mult_den` |
| **91** | `AipowMaturation` | reward maturation policy: `immediate_bps`, `stream_epochs`, `epoch_seconds`, `maturation_version` |
| **92** | `AipowLimits` | `total_cap` — the AIPoW total-supply ceiling (the running total is tracked in the settlement contract, not here) |
| **93** | `AipowRegistry` | `settlement_addr`, frozen `methodology_hash` and `rate_card_hash`, the audited `commitment_code_hash`, `reviewer_addr`, and the audited `distributor_code_hashes` dictionary |

See the exact cell shapes in [block.tlb](../crypto/block/block.tlb) and the activation
semantics in [GlobalVersions.md](GlobalVersions.md).

## Validator and Network Parameters

The remaining masterchain parameters follow the native TOS schema in [block.tlb](../crypto/block/block.tlb) and are consumed by the validator, collator, election, gas, storage, and networking code paths.

When adding or changing a parameter:

- update the TL-B schema if the cell shape changes
- update zero-state generation if the initial value changes
- add migration rules for active networks
- keep validator and collator validation paths consistent

## References

- [Zerostate.md](Zerostate.md)
- [block.tlb](../crypto/block/block.tlb)
