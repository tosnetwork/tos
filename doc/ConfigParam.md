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

The remaining masterchain parameters follow the native TOS schema in [block.tlb](../crypto/block/block.tlb) and are consumed by the validator, collator, election, gas, storage, and networking code paths. They are the standard base-protocol parameters; the canonical cell shapes live in the TL-B schema and are the authority for the fields below.

**Addresses and minting**

| Param | Type | Purpose |
|---|---|---|
| 0 | `config_addr:bits256` | configuration contract address |
| 1 | `elector_addr:bits256` | elector contract address |
| 2 | `minter_addr:bits256` | minter address (falls back to ConfigParam 0 if absent) |
| 3 | `fee_collector_addr:bits256` | fee-collector address (falls back to ConfigParam 1 if absent) |
| 4 | `dns_root_addr:bits256` | root native DNS resolver |
| 5 | `BurningConfig` | fee-burning configuration |

**Governance and config change**

| Param | Type | Purpose |
|---|---|---|
| 9 | `mandatory_params:(Hashmap 32 True)` | params that must always be present |
| 10 | `critical_params:(Hashmap 32 True)` | params whose change needs a critical vote |
| 11 | `ConfigVotingSetup` | config-change proposal/voting setup |
| 13 | `ComplaintPricing` | validator-complaint deposit and pricing |

**Validator election and stake**

| Param | Type | Purpose |
|---|---|---|
| 15 | `validators_elected_for / elections_start_before / elections_end_before / stake_held_for` | election timing windows |
| 16 | `max_validators / max_main_validators / min_validators` | validator-count bounds |
| 17 | `min_stake / max_stake / min_total_stake / max_stake_factor` | stake bounds |
| 32 / 33 | `ValidatorSet` | previous validator set / previous temp validator set |
| 34 / 35 | `ValidatorSet` | current validator set / current temp validator set |
| 36 / 37 | `ValidatorSet` | next validator set / next temp validator set |
| 39 | `(HashmapE 256 ValidatorSignedTempKey)` | validator temporary signing keys |
| 40 | `MisbehaviourPunishmentConfig` | slashing / misbehaviour punishment |

Production values for 15, 16, and 17 are in
[tos-validator-only-token-economics.md §5.1](tos-validator-only-token-economics.md).
Note that 16's `min_validators` and 17's `max_stake_factor` constrain each
other — the factor bounds how concentrated effective weight can become in the
smallest set the configuration permits, so neither can be changed alone. §5.2
of the same document gives the bound and the order the two move in.

**Gas, fees, storage, and block limits**

| Param | Type | Purpose |
|---|---|---|
| 18 | `(Hashmap 32 StoragePrices)` | per-workchain storage prices (masterchain vs basechain cell/bit rent) |
| 19 | `global_id:int32` | network global id |
| 20 / 21 | `GasLimitsPrices` | gas limits and prices (masterchain / basechain) |
| 22 / 23 | `BlockLimits` | block limits (masterchain / basechain) |
| 24 / 25 | `MsgForwardPrices` | message-forwarding prices (masterchain / basechain) |

**Consensus and networking**

| Param | Type | Purpose |
|---|---|---|
| 28 | `CatchainConfig` | catchain (block-consensus) parameters |
| 29 | `ConsensusConfig` | consensus parameters |
| 30 | `NewConsensusConfigAll` | extended/aggregated consensus configuration |
| 31 | `fundamental_smc_addr:(HashmapE 256 True)` | fundamental smart-contract addresses |

**Execution safety limits**

| Param | Type | Purpose |
|---|---|---|
| 43 | `SizeLimitsConfig` | account/message/state size limits |
| 44 | `SuspendedAddressList` | suspended (blocked) addresses |
| 45 | `PrecompiledContractsConfig` | precompiled-contract registry |

**External-chain bridges**

These slots select which counterparty chain a bridge contract serves. The contract planes live in `crosschain/`; see each bridge's `SECURITY.md` for the gates that apply before a slot may be populated. **No slot below is enabled or populated by this build**, and none is mandatory.

| Param | Type | Counterparty | Contract tree |
|---|---|---|---|
| 71 | `OracleBridgeParams` | Ethereum | `crosschain/coin-bridge/tvm/ethereum` |
| 72 | `OracleBridgeParams` | BNB Smart Chain | `crosschain/coin-bridge/tvm/bsc` |
| 73 | `OracleBridgeParams` | Polygon | declared in the schema; no contract tree in this repository |
| 79 | `JettonBridgeParams` | Ethereum | `crosschain/token-bridge/tvm/params/ethereum.fc` |
| 81 | `JettonBridgeParams` | BNB Smart Chain | `crosschain/token-bridge/tvm/params/bsc.fc` |
| 82 | `JettonBridgeParams` | Polygon | `crosschain/token-bridge/tvm/params/polygon.fc` |
| 83 | `JettonBridgeParams` | Tron | `crosschain/token-bridge/tvm/params/tron.fc` |

Slot 80 is unallocated. Slot 83 is TOS-specific: it has no counterpart in the base schema this bridge architecture came from, and no counterparty contract has been deployed or exercised on Tron.

Each bridge parameter file also fixes the chain id its contract compares against. For EVM chains that is the registered chain id (1, 56, 137). Tron is not an EVM chain and its `CHAINID` returns the last four bytes of the genesis block id, so slot 83 uses `728126428`, which must be confirmed against the target Tron network before the slot is populated.

## Adding or changing a parameter

- **A new index must be declared in [block.tlb](../crypto/block/block.tlb).** Config validation runs `block::gen::ConfigParam{idx}.validate_ref(...)`, and the generated `get_tag` returns `-1` for any index it does not know, which fails the whole configuration. A parameter file that compiles is therefore not enough: without a schema entry the slot can never be set on chain. `block-auto.cpp/h` are generated from `block.tlb` at build time and are not tracked, so only the schema source is committed.
- Negative indices are deliberately exempt from that validation (`check_one_config_param` returns true for `idx < 0`). The bridge contracts read `config_param(N)` and fall back to `config_param(-N)` for staging, so a negative slot carries no schema guarantee and must never be used to hold a value a production path depends on.
- Update the TL-B schema if the cell shape changes.
- Update zero-state generation if the initial value changes.
- Add migration rules for active networks.
- Keep validator and collator validation paths consistent.

## References

- [Zerostate.md](Zerostate.md)
- [block.tlb](../crypto/block/block.tlb)
