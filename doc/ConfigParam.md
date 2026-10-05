# Configuration Parameters

This document describes the configuration parameters understood by the current TOS source tree. The active value on a particular network must be read from that network's masterchain; a compiled limit or a local genesis template is not evidence that a parameter has been activated there.

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
`capStoreOutMsgQueueSize(64)`, `capMsgMetadata(128)`, `capDeferMessages(256)`, and
`capFullCollatedData(512)`. `GlobalCapabilities` in
[tos-types.h](../tos/tos-types.h) is the authority; this list is a convenience and
must be checked against it rather than trusted.

A binary declares which of these it implements in `Collator::supported_capabilities()`
and the matching validator method. Declaring fewer than the configuration enables does
not make a node refuse: see the fall-through described under `version` below, which
applies to capabilities in the same way.

### `version` is the activation point; the compiled constant is not

`capabilities` and `version` are both set here, but they are not enforced the same
way, and conflating them has already produced a wrong claim in this documentation
set. A capability the configuration enables but the binary does not implement is
reported and the block is still produced. The same is true of `version`: the
`get_global_version() > supported_version()` checks in
[collator.cpp](../validator/impl/collator.cpp) and
[validate-query.cpp](../validator/impl/validate-query.cpp) emit

```
block version N have been enabled in global configuration,
but we support only M (upgrade validator software?)
```

and then **fall through**. Neither refuses. A local chain built when
`SUPPORTED_VERSION` was still 15 was configured at `version = 16` and produced
blocks that executed version-16 instructions.

So `tos::SUPPORTED_VERSION` in [global-version.h](../common/global-version.h) is an
advertisement of what a binary implements, not a gate. Setting it low does not
protect a network from a configuration that is set high, and raising it does not
activate anything. It has two observable effects: a VM built with no configuration
to consult — `lite-client runmethod`, Fift, `run_get_method` — runs at that version,
and `Collator::store_version` writes it into each block's informational
`gen_software` field when `capReportVersion` is set. Block validation never reads
that field.

The only parameter that decides what a network executes is `version` here.

### Unified version 16 in this build

The compiled [SUPPORTED_VERSION](../common/global-version.h) is now **16**. It
does not activate that version on a network. The configured value gates these
instructions:

| Minimum version | Instruction | Reference |
|---|---|---|
| 16 | `PQCHECKSIG_MLDSA44` | [tvm-mldsa44.md](tvm-mldsa44.md) |
| 16 | `PQCHECKSIG_FALCON512_PADDED` | [wallet-falcon-fndsa.md](wallet-falcon-fndsa.md) |
| 16 | `POSEIDON2_PERM8`, `POSEIDON2_HASH7` | [GlobalVersions.md](GlobalVersions.md) |
| 16 | `POSEIDON2_PATH7` | [GlobalVersions.md](GlobalVersions.md) |

Version 16 also changes one transaction rule. All version-16 changes are
gated on the configured value, not on the compiled constant.

1. The TVM instruction `PQCHECKSIG_MLDSA44` (`F93100`) exists. Its gate is
   `vm::pq_mldsa44_min_version` in [pqops.h](../crypto/vm/pqops.h).
2. Unfreezing is validated less strictly. In
   [transaction.cpp](../crypto/block/transaction.cpp), an incoming
   `StateInit` that revives a **frozen** account skips the
   `check_addr_rewrite_length` test at version 16, where version 15 applies it to
   every account status. An uninitialized account is unaffected. This arrived
   with the pre-launch audit changes and is unrelated to the instruction above;
   it is recorded here because activating version 16 activates it too.

The transaction change is independent of the PQ and Poseidon2 instructions.
See [GlobalVersions.md](GlobalVersions.md) for their full semantics and activation requirements.

Because the checks above do not refuse, a mixed fleet will not fail loudly: nodes
that do not implement the configured version log an error and keep validating,
and disagreement appears as diverging execution rather than a refusal to start.
That is why the sequence in [GlobalVersions.md](GlobalVersions.md) is upgrade
every validator first, change this parameter second, and never the reverse.
`tools/pq/activation.py` validates a proposed 15 → 16 transition against that
sequence — evidence bound to one release, four explicit owner approvals, and a
roster in which every validator acknowledges the binary it actually runs — and
emits an **unsigned** ConfigParam 8 payload. A validated proposal is not an
activation, and the tool never broadcasts one.

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

## Shielded pool parameters

The V1 shielded pool does **not** introduce a masterchain ConfigParam index.
Its `profile_hash`, Poseidon2 manifest hash, Groth16 verifying-key hash,
withdrawal fee and denominations are encoded in the pool contract's deployment
state by [shielded-pool-genesis](../tools/shielded-pool-genesis/src/lib.rs).
The reserve floor is part of that initial state. A change to these inputs
changes the generated state or deployment identity; it is not a ConfigParam
vote. The VM instructions used by the pool are gated separately by
**ConfigParam 8**, at unified version 16 as described above.

The current **development fixture** records these amounts in the smallest
native units (tomis):

| Pool input | Value |
|---|---:|
| Reserve floor | 50,000,000,000 |
| Withdrawal fee | 20,000,000 |
| Note denominations | 1,000,000,000; 10,000,000,000; 100,000,000,000; 1,000,000,000,000 |

The byte-frozen [V1 profile](../artifacts/shielded-pool/PROFILE.md) defines the
wire format and rules. The [generated manifest](../artifacts/shielded-pool/genesis-manifest.json)
pins these inputs and the resulting state hash. Its verifying key is a
development fixture; neither the manifest nor compiled version 16 establishes
network activation or production deployment.

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

The current post-quantum launch code caps **total validators, masterchain
committee members and shard committee members at 21**; these are binary and
contract limits, not claims about a live network's current membership.
[mc-config.cpp](../crypto/block/mc-config.cpp) checks the ordering and shape of
Param 16, requires Param 28's `shard_validators_num` in `1..21`, and checks the
total and main counts of any present sets in Params 34–37. The config contract
applies corresponding limits when a proposal changes these values. The shared
constants are in [pq-launch-limits.h](../crypto/pq/pq-launch-limits.h) and
[pq-launch-limits.fc](../crypto/smartcont/pq-launch-limits.fc).

The `validator_pq#b3` entry in Param 34 (and the other validator sets) records
a stable `validator_id`, algorithm and `key_id`, the consensus public key,
weight, and a separate ADNL address. Its exact cell layout is in
[block.tlb](../crypto/block/block.tlb); the consensus key does not supply the
ADNL identity. A locally generated four-validator zerostate is an example,
not a fixed production membership.

Production values for 15, 16, and 17 are in
[tos-validator-only-token-economics.md §5.1](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-validator-only-token-economics.md).
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
| 30 | `NewConsensusConfigAll` | optional masterchain and shard Simplex configurations; `simplex_config#21` and `simplex_config_v2#22` are defined in TL-B |
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

Falcon wallet verification adds a version-16 candidate capability. See [wallet-falcon-fndsa.md](wallet-falcon-fndsa.md). Network activation and protocol approval remain separate from compiling support.
