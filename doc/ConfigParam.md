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

Genesis sets version 16 with capabilities `0x1ee`
([gen-zerostate.fif](../crypto/smartcont/gen-zerostate.fif#L189-L190)). `capFullCollatedData (512)` is
deliberately off: this is a bounded launch exception, not an oversight.
Mainnet-scale networks enable it; TOS enables it only after measured evidence
of proof size, validation latency and the ConfigParam 29 4 / 10 MiB limits on a
large or cold state.

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

The basechain descriptor uses the `workchain_v2` (#a7) constructor with
`min_split` 0, `max_split` 2 and `persistent_state_split_depth` 4, and explicit
split/merge timings ([gen-zerostate.fif](../crypto/smartcont/gen-zerostate.fif#L68-L88)). The collator splits any
shard shallower than `min_split` regardless of load and never merges back below
it, so `min_split` is the floor on how many basechain shards every validator must
run. An earlier value of 4 forced 16 shards about 400 s after genesis; with four
validators each node then ran 17 consensus groups, saturated its disk flushes and
let the masterchain interval drift from about 470 ms to about 1 s. With 0 the
basechain stays one shard until load asks for a split, and can split at most
twice.

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

## Genesis values and why they are set

[gen-zerostate.fif](../crypto/smartcont/gen-zerostate.fif) is the authority for every initial value; the links below
point at the lines that set them. This section records only why each value was
chosen. The general rule is to follow mainnet-scale networks unless TOS has a
measured or product reason to differ.

| Param | Where | Why |
|---|---|---|
| 5 `BurningConfig` | [L153-L157](../crypto/smartcont/gen-zerostate.fif#L153-L157), [L396-L401](../crypto/smartcont/gen-zerostate.fif#L396-L401) | Blackhole `-1:ffff…ffff`, fee burn 0/1. Inbound value to the blackhole is destroyed and counted in `ValueFlow.burned`; it is the bootstrap wallet's final sweep destination (mode 128+32), which burns the remainder and deletes the wallet. Fees are not burned: distribution is validator-led and there is no treasury. Critical (in ConfigParam 10), so an ordinary vote cannot move the blackhole onto a spendable account or start burning fees; not mandatory, because removing it only restores the 0/1, no-blackhole default. Mainnet-scale networks burn half of the fees to the same blackhole. |
| 8 `GlobalVersion` | [L189-L190](../crypto/smartcont/gen-zerostate.fif#L189-L190) | Version 16, capabilities `0x1ee`. `capFullCollatedData` stays off as a bounded launch exception; see [ConfigParam 8](#configparam-8). |
| 11 `ConfigVotingSetup` | [L422-L438](../crypto/smartcont/gen-zerostate.fif#L422-L438) | Mainnet-scale proposal rounds. Because the registering round already counts and a proposal is removed only when its remaining count goes negative, ordinary/critical proposals get 7/8 voting rounds. Acceptance happens at `min_wins`; removal happens only once losses exceed `max_losses`. `elector_sandbox.rs` exercises the lifecycle. |
| 12 workchains | [L91-L113](../crypto/smartcont/gen-zerostate.fif#L91-L113) | See [ConfigParam 12](#configparam-12): the forced split floor is removed. |
| 13 `ComplaintPricing` | [L440-L448](../crypto/smartcont/gen-zerostate.fif#L440-L448) | Deposit 1 TOS, 1 per bit, 500 per cell, as mainnet-scale networks charge. The elector charges `deposit + ((bits + 1024) * bit_price + (cells + 2) * cell_price) * seconds until the stake unfreezes` and accepts a complaint only while its fine exceeds that charge. At the former 100 TOS deposit the mildest ConfigParam 40 tier (62.5 TOS + 1/256 of a 10,000 TOS stake = 101.5625 TOS) barely cleared it and a complaint with a larger proof could not be filed; at 1 TOS a 4,096-bit, 8-cell complaint held for 32,768 s is charged 1.3316 TOS. `elector_sandbox.rs` files a mildest-tier complaint under both deposits. |
| 18 `StoragePrices` | [L228-L234](../crypto/smartcont/gen-zerostate.fif#L228-L234) | One entry, effective since 0: basechain 0 per bit and 135 per cell, masterchain 1,000 per bit and 500,000 per cell (per second, scaled by 2^16). The basechain values are the latest base rent of mainnet-scale networks, which charge cells only; TOS uses them from genesis instead of from a later activation time. Masterchain rent is unchanged on purpose: it is the state-cost boundary that keeps ordinary accounts off the masterchain. The 1/20 price cut applies to masterchain gas and forwarding (ConfigParams 20 and 24) only. |
| 21 basechain gas | [L237-L274](../crypto/smartcont/gen-zerostate.fif#L237-L274) | Per-transaction and special limits are 2,000,000. The worst measured shielded-pool withdrawal is 1,068,664 gas, against a contract ceiling of 1,380,000, so the mainnet-scale 1,000,000 would make every withdrawal fail. 2,000,000 keeps one worst-case transaction near 50 ms. `block_gas_limit` equals the ConfigParam 23 hard limit and is informational; blocks are bounded by ConfigParam 22/23. |
| 23 basechain block limits | [L326-L335](../crypto/smartcont/gen-zerostate.fif#L326-L335) | Gas tiers 2M / 10M / 20M follow mainnet-scale networks. They are to be re-measured as whole-block validation time on the production hardware class. |
| 29 consensus | [L286-L292](../crypto/smartcont/gen-zerostate.fif#L286-L292) | The 4 MiB block / 10 MiB collated-data limits sit above the ConfigParam 23 byte limit, so a collator size over-estimate does not turn into a dropped slot. |
| 30 Simplex | [L293-L318](../crypto/smartcont/gen-zerostate.fif#L293-L318) | The target block rate is 400 ms. `first_block_timeout` is 700 ms. `min_block_interval` is 300 ms, set explicitly. Shard leaders own 16 slots with `max_leader_window_desync` 64; masterchain leaders own 4 slots with a desync of 250. The issuance in ConfigParam 14 assumes the resulting block rate. |
| 31 fundamental addresses | [L143-L147](../crypto/smartcont/gen-zerostate.fif#L143-L147), [L179](../crypto/smartcont/gen-zerostate.fif#L179) | Only the elector is listed. The bootstrap main wallet is an ordinary account and pays fees. |
| 34 initial validator set | [L486-L489](../crypto/smartcont/gen-zerostate.fif#L486-L489) | The genesis set is valid for 21,600 s (6 h). With the ConfigParam 15 windows (65,536 / 32,768 / 8,192 / 32,768) the first election opens at genesis, closes about 3.7 h later and the elected set takes office at 6 h. Retired consensus sessions are deleted only after a key block; under a sustained ~6.4M gas per block load `consensus/` grew about 31 MB/min, which over the previous 131,072 s lifetime would exceed 60 GB on a 99 GB disk. |
| 43 size limits | [L337-L370](../crypto/smartcont/gen-zerostate.fif#L337-L370) | Mainnet-scale bounds, written out explicitly. No TOS contract on a production path loads more than 3 libraries per transaction or sends extra currencies. |

Measured on the four-validator public testnet (production hardware class: 6 vCPU,
12 GB RAM, virtio disk), comparing epoch 2 under the earlier values with epoch 3
under the values above:

- masterchain interval: 605 ms rising towards about 1 s, against about 400–430 ms;
- basechain shards: 16, against 1;
- validator CPU: about 2 cores, against under half a core;
- `consensus/` growth before the first key block: about 137 MB/min, against about 10 MB/min.

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
| 5 | `BurningConfig` | `blackhole_addr:(Maybe bits256) fee_burn_num:# fee_burn_denom:#`: inbound value to the masterchain blackhole account is destroyed, and `fee_burn_num/fee_burn_denom` of collected fees is burned. Absent means no blackhole and 0/1. Genesis: blackhole `-1:ffff…ffff`, 0/1, critical |

**Governance and config change**

| Param | Type | Purpose |
|---|---|---|
| 9 | `mandatory_params:(Hashmap 32 True)` | params that must always be present |
| 10 | `critical_params:(Hashmap 32 True)` | params whose change needs a critical vote |
| 11 | `ConfigVotingSetup` | config-change proposal/voting setup |
| 13 | `ComplaintPricing` | `deposit bit_price cell_price`: what filing a validator complaint costs; the elector charges `deposit + ((bits + 1024) * bit_price + (cells + 2) * cell_price) * seconds until the stake unfreezes`. Genesis: 1 TOS / 1 / 500 |

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
| 43 | `SizeLimitsConfig` | account/message/state size limits; v3 also carries `out_msg_queue_size_hard_limit` / `out_msg_queue_size_soft_limit`, the outbound message queue bounds of a shard (genesis 18000 / 12000, see [GlobalVersions.md](GlobalVersions.md)) |
| 44 | `SuspendedAddressList` | suspended (blocked) addresses |
| 45 | `PrecompiledContractsConfig` | precompiled-contract registry |

### Queue-limit proposals and collator settings

ConfigParam 43's outbound queue limits are coupled to block admission and message
deferral. The canonical genesis uses `hard = 18000` and `soft = 12000`. A previous
queue at or below `soft` does not generally permit deferring the first output of
a transaction or outputs of a fundamental masterchain account. An account's
existing deferred messages provide a separate exception. A queue already above
the hard limit after a merge or a parameter change may not grow beyond its old
size. See [GlobalVersions.md](GlobalVersions.md#version-16-unified-development-baseline)
for the baseline rules.

A positive `hard - soft` is not by itself a capacity guarantee. The capacity
review must cover all outputs that cannot be deferred, pending dispatch entries,
the final transaction admitted before a block becomes full, and forced
masterchain tick/tock and mint/recovery transactions. Different accounts can
share logical time, and a bounce can produce an output without compute gas;
neither the LT delta nor the gas limit alone bounds the aggregate message burst.
The serialized block byte limits in ConfigParams 22/23 are part of that review.

The existing [queue review evidence](evidence/a-class-review-20261022.md) is limited
to the canonical genesis and default collator options: deferring enabled, local
deferral threshold 2048, and an empty whitelist. Its source review and helper
tests are not a full candidate replay for arbitrary configurations.
Increasing the local threshold, disabling optional deferral, or whitelisting
senders changes how much capacity optional messages can consume. These local
changes need a capacity review even when no ConfigParam 43 vote is proposed.
Changing ConfigParam 12 routing/split limits, ConfigParam 31 fundamental accounts,
message-metadata capabilities, or block byte limits also invalidates assumptions
of the existing review. Deeper splits or additional routed workchains need a
separate saturation-and-recovery test for multi-hop transit queues.

Before approving a queue-related configuration proposal or local collator change:

- Record the old and proposed hard/soft limits, ConfigParams 22/23 byte limits,
  dispatch threshold, fundamental accounts, routing topology, and local deferral
  options. Review the transition from an existing queue as well as an empty state.
- Establish enough capacity for every output that cannot be deferred under the
  proposed settings, including pending dispatch entries and forced tail
  transactions. Do not reuse a first-output-only or LT-only bound. Preserve the
  canonical settings until the changed assumptions have been validated.
- Exercise a queue at the soft limit, a queue at the hard limit, an existing
  queue larger than a reduced limit, dispatch backlog, zero-gas bounces, and
  special-account bursts. Check the actual collator candidate with the validator;
  parser acceptance, helper tests and a positive gap do not establish liveness.
- Record the exact build, inputs and passing/failing controls. A change outside
  the canonical/default-options review requires new evidence before activation.
- Document recovery prerequisites. A corrective on-chain vote requires the
  masterchain and configuration contract to remain usable; do not assume it will
  recover a halted masterchain. Verify the recovery path before activation.

This is an operational review checklist, not an additional consensus rule.
TL-B shape checks and configuration parsing do not by themselves enforce these
cross-parameter capacity and recovery conditions.

**External-chain bridges**

These slots select which counterparty chain a bridge contract serves. The contract planes live in `crosschain/`; see each bridge's `SECURITY.md` for the gates that apply before a slot may be populated. **No slot below is enabled or populated by this build**, and none is mandatory.

| Param | Type | Counterparty | Contract tree |
|---|---|---|---|
| 71 | `OracleBridgeParams` | Ethereum | `crosschain/coin-bridge/tvm/ethereum` |
| 72 | `OracleBridgeParams` | BNB Smart Chain | `crosschain/coin-bridge/tvm/bsc` |
| 73 | `OracleBridgeParams` | Polygon | declared in the schema; no contract tree in this repository |
| 79 | `TokenBridgeParams` | Ethereum | `crosschain/token-bridge/tvm/params/ethereum.fc` |
| 81 | `TokenBridgeParams` | BNB Smart Chain | `crosschain/token-bridge/tvm/params/bsc.fc` |
| 82 | `TokenBridgeParams` | Polygon | `crosschain/token-bridge/tvm/params/polygon.fc` |
| 83 | `TokenBridgeParams` | Tron | `crosschain/token-bridge/tvm/params/tron.fc` |

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
