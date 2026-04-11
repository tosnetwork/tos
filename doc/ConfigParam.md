# TOS Configuration Parameters

Configuration parameters are protocol values stored in the masterchain state. They control validator behavior, fees, limits, smart contract addresses, feature flags, and network policy. All validators read the same config from the chain; changes require on-chain governance.

The canonical TL-B schema is in [block.tlb](../crypto/block/block.tlb). Initial values are set during [zero state generation](Zerostate.md).

## Complete Parameter Reference

### ConfigParam 0 — Config Smart Contract Address

| Field | Type | Description |
|-------|------|-------------|
| `config_addr` | bits256 | Address of the config smart contract in masterchain |

### ConfigParam 1 — Elector Smart Contract Address

| Field | Type | Description |
|-------|------|-------------|
| `elector_addr` | bits256 | Address of the elector smart contract in masterchain |

### ConfigParam 2 — Minter Address

| Field | Type | Description |
|-------|------|-------------|
| `minter_addr` | bits256 | Address of the minter. Falls back to ConfigParam 0 if absent. |

### ConfigParam 3 — Fee Collector Address

| Field | Type | Description |
|-------|------|-------------|
| `fee_collector_addr` | bits256 | Address that collects transaction fees. Falls back to ConfigParam 1 if absent. |

### ConfigParam 4 — DNS Root Address

| Field | Type | Description |
|-------|------|-------------|
| `dns_root_addr` | bits256 | Root TOS DNS resolver address |

### ConfigParam 5 — BurningConfig

| Field | Type | Description |
|-------|------|-------------|
| `fee_burn_num` | uint32 | Numerator of the fee burn fraction |
| `fee_burn_denom` | uint32 | Denominator (must be >= 1, num <= denom) |

Fraction `fee_burn_num / fee_burn_denom` of collected fees is burned (destroyed).

### ConfigParam 6 — Minting Prices

| Field | Type | Description |
|-------|------|-------------|
| `mint_new_price` | Tomis | Price to mint a new extra currency |
| `mint_add_price` | Tomis | Price to add to existing extra currency supply |

### ConfigParam 7 — Extra Currencies to Mint

| Field | Type | Description |
|-------|------|-------------|
| `to_mint` | ExtraCurrencyCollection | Dictionary of extra currency IDs and amounts to mint each block |

### ConfigParam 8 — GlobalVersion

| Field | Type | Description |
|-------|------|-------------|
| `version` | uint32 | Protocol version number. Controls which TVM features are enabled. |
| `capabilities` | uint64 | Bit flags for protocol capabilities |

Capability flags (bit positions):

| Bit | Value | Name | Description |
|-----|-------|------|-------------|
| 1 | 2 | capCreateStats | Enable account creation statistics |
| 2 | 4 | capBounceMsgBody | Include message body in bounce messages |
| 3 | 8 | capReportVersion | Validators report their software version |
| 5 | 32 | capShortDequeue | Short dequeue optimization |
| 6 | 64 | capStoreOutMsgQueueSize | Store output message queue size |
| 7 | 128 | capMsgMetadata | Message metadata support |
| 8 | 256 | capDeferMessages | Deferred message execution |

Recommended: version=13, capabilities=494 (all flags above).

See [GlobalVersions.md](GlobalVersions.md) for version history.

### ConfigParam 9 — Mandatory Parameters

| Field | Type | Description |
|-------|------|-------------|
| `mandatory_params` | Hashmap 32 True | Set of config parameter IDs that must always be present in the config |

Default: `{ 0, 1, 9, 10, 12, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 28, 34 }`

### ConfigParam 10 — Critical Parameters

| Field | Type | Description |
|-------|------|-------------|
| `critical_params` | Hashmap 32 True | Set of parameter IDs that require supermajority vote to change |

Default: `{ -999, -1000, -1001, 0, 1, 9, 10, 12, 14, 15, 16, 17, 32, 34, 36 }`

### ConfigParam 11 — ConfigVotingSetup

Defines voting rules for config proposals.

| Field | Type | Description |
|-------|------|-------------|
| `normal_params` | ConfigProposalSetup | Rules for ordinary (non-critical) proposals |
| `critical_params` | ConfigProposalSetup | Rules for critical proposals |

Each `ConfigProposalSetup` contains:

| Field | Type | Description |
|-------|------|-------------|
| `min_tot_rounds` | uint8 | Minimum total voting rounds |
| `max_tot_rounds` | uint8 | Maximum total voting rounds |
| `min_wins` | uint8 | Minimum wins required to pass |
| `max_losses` | uint8 | Maximum losses before rejection |
| `min_store_sec` | uint32 | Minimum time (seconds) to store proposal |
| `max_store_sec` | uint32 | Maximum time (seconds) to store proposal |
| `bit_price` | uint32 | Cost per bit of proposal data |
| `cell_price` | uint32 | Cost per cell of proposal data |

### ConfigParam 12 — Workchain Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `workchains` | HashmapE 32 WorkchainDescr | Map of workchain ID to description |

Each `WorkchainDescr` contains:

| Field | Type | Description |
|-------|------|-------------|
| `enabled_since` | uint32 | Unix timestamp when workchain was enabled |
| `monitor_min_split` | uint8 | Minimum split depth for monitoring |
| `min_split` | uint8 | Minimum shard split depth |
| `max_split` | uint8 | Maximum shard split depth |
| `basic` | bit | Whether this is a basic workchain |
| `active` | Bool | Whether the workchain is active |
| `accept_msgs` | Bool | Whether the workchain accepts messages |
| `zerostate_root_hash` | bits256 | Root hash of the workchain's zero state |
| `zerostate_file_hash` | bits256 | File hash of the workchain's zero state |

### ConfigParam 13 — Complaint Pricing

| Field | Type | Description |
|-------|------|-------------|
| `deposit` | Tomis | Deposit required to file a complaint |
| `bit_price` | Tomis | Cost per bit of complaint data |
| `cell_price` | Tomis | Cost per cell of complaint data |

### ConfigParam 14 — Block Creation Fees

| Field | Type | Description |
|-------|------|-------------|
| `masterchain_block_fee` | Tomis | Reward for producing a masterchain block |
| `basechain_block_fee` | Tomis | Reward for producing a basechain block |

### ConfigParam 15 — Election Timing

| Field | Type | Description |
|-------|------|-------------|
| `validators_elected_for` | uint32 | Duration (seconds) a validator set is active |
| `elections_start_before` | uint32 | How long before set expiry elections begin (seconds) |
| `elections_end_before` | uint32 | How long before set expiry elections must end (seconds) |
| `stake_held_for` | uint32 | How long stakes are frozen after a validator set ends (seconds) |

### ConfigParam 16 — Validator Count Limits

| Field | Type | Description |
|-------|------|-------------|
| `max_validators` | uint32 | Maximum total validators that can be elected |
| `max_main_validators` | uint32 | Maximum main (masterchain) validators |
| `min_validators` | uint32 | Minimum validators required for the network to operate |

### ConfigParam 17 — Stake Limits

| Field | Type | Description |
|-------|------|-------------|
| `min_stake` | Tomis | Minimum stake to participate in elections |
| `max_stake` | Tomis | Maximum stake per validator |
| `min_total_stake` | Tomis | Minimum total stake across all validators |
| `max_stake_factor` | uint32 | Maximum ratio of largest to smallest stake (fixed-point, 65536 = 1x) |

### ConfigParam 18 — Storage Prices

| Field | Type | Description |
|-------|------|-------------|
| `utime_since` | uint32 | Timestamp when these prices take effect |
| `bit_price_ps` | uint64 | Price per bit per second (basechain) |
| `cell_price_ps` | uint64 | Price per cell per second (basechain) |
| `mc_bit_price_ps` | uint64 | Price per bit per second (masterchain) |
| `mc_cell_price_ps` | uint64 | Price per cell per second (masterchain) |

### ConfigParam 19 — Global ID

| Field | Type | Description |
|-------|------|-------------|
| `global_id` | int32 | Chain identity. Must match the global_id in every block header. |

TOS values: **1** (mainnet), **2** (testnet), **3** (dev). Must never change after genesis — wallet signatures include this value for anti-replay protection.

### ConfigParam 20 — Masterchain Gas Prices

### ConfigParam 21 — Basechain Gas Prices

Both use the `GasLimitsPrices` type:

| Field | Type | Description |
|-------|------|-------------|
| `gas_price` | uint64 | Gas price in nanotomi per 2^16 gas units |
| `gas_limit` | uint64 | Maximum gas per ordinary transaction |
| `special_gas_limit` | uint64 | Maximum gas for special/system transactions |
| `gas_credit` | uint64 | Free gas credit for external messages (to cover signature check) |
| `block_gas_limit` | uint64 | Maximum total gas per block |
| `freeze_due_limit` | uint64 | Balance threshold (nanotomi) below which account is frozen |
| `delete_due_limit` | uint64 | Balance threshold (nanotomi) below which account is deleted |
| `flat_gas_limit` | uint64 | Gas amount covered by the flat fee |
| `flat_gas_price` | uint64 | Flat fee in nanotomi for gas up to flat_gas_limit |

### ConfigParam 22 — Masterchain Block Limits

### ConfigParam 23 — Basechain Block Limits

Both use the `BlockLimits` type, with three tiers per metric:

| Field | Type | Description |
|-------|------|-------------|
| `bytes.underload` | uint32 | Byte count below which shard is considered underloaded (triggers merge) |
| `bytes.soft_limit` | uint32 | Normal target byte limit |
| `bytes.hard_limit` | uint32 | Absolute maximum bytes per block |
| `gas.underload` | uint32 | Gas below which shard is underloaded |
| `gas.soft_limit` | uint32 | Normal target gas limit |
| `gas.hard_limit` | uint32 | Absolute maximum gas per block |
| `lt_delta.underload` | uint32 | Logical time delta below which shard is underloaded |
| `lt_delta.soft_limit` | uint32 | Normal target lt delta |
| `lt_delta.hard_limit` | uint32 | Absolute maximum lt delta per block |

### ConfigParam 24 — Masterchain Message Forwarding Prices

### ConfigParam 25 — Basechain Message Forwarding Prices

Both use the `MsgForwardPrices` type:

| Field | Type | Description |
|-------|------|-------------|
| `lump_price` | uint64 | Fixed fee per message (nanotomi) |
| `bit_price` | uint64 | Fee per bit of message body (nanotomi per 2^16 bits) |
| `cell_price` | uint64 | Fee per cell of message body (nanotomi per 2^16 cells) |
| `ihr_factor` | uint32 | IHR (instant hypercube routing) fee multiplier (fixed-point, 65536 = 1x) |
| `first_frac` | uint16 | Fraction of fee paid by the first transit hop (fixed-point, 65536 = 1) |
| `next_frac` | uint16 | Fraction of remaining fee paid by each subsequent hop |

### ConfigParam 28 — Catchain Config

| Field | Type | Description |
|-------|------|-------------|
| `mc_catchain_lifetime` | uint32 | Masterchain catchain session lifetime (seconds). After expiry, a new session starts. |
| `shard_catchain_lifetime` | uint32 | Shard catchain session lifetime (seconds) |
| `shard_validators_lifetime` | uint32 | How long a shard validator group stays assigned to a shard (seconds) |
| `shard_validators_num` | uint32 | Number of validators assigned per shard. More = more security, fewer parallel shards. |
| `shuffle_mc_validators` | Bool | Whether to shuffle masterchain validator ordering each round |

### ConfigParam 29 — Consensus Config

| Field | Type | Description |
|-------|------|-------------|
| `flags` | uint6-7 | Bit flags (0 = default) |
| `use_quic` | Bool | Use QUIC transport for consensus (v4 only) |
| `new_catchain_ids` | Bool | Use new-style catchain session IDs |
| `round_candidates` | uint8 | Block candidates proposed per consensus round (>= 1) |
| `next_candidate_delay_ms` | uint32 | Delay (ms) before next block candidate if first fails |
| `consensus_timeout_ms` | uint32 | Maximum time (ms) per consensus round. **Primary factor in block time.** |
| `fast_attempts` | uint32 | Fast consensus attempts before fallback to slower mode |
| `attempt_duration` | uint32 | Duration of each consensus attempt (catchain time units) |
| `catchain_max_deps` | uint32 | Maximum catchain DAG block dependencies |
| `max_block_bytes` | uint32 | Maximum block size (bytes) |
| `max_collated_bytes` | uint32 | Maximum collated data size (bytes) |
| `proto_version` | uint16 | Consensus protocol version |
| `catchain_max_blocks_coeff` | uint32 | Catchain blocks-per-round limiter. 0 = unlimited (dev only). |

### ConfigParam 30 — New Consensus Config (Simplex)

| Field | Type | Description |
|-------|------|-------------|
| `mc` | Maybe ^NewConsensusConfig | Masterchain simplex consensus params (if used) |
| `shard` | Maybe ^NewConsensusConfig | Shard simplex consensus params (if used) |

### ConfigParam 31 — Fundamental Smart Contract Addresses

| Field | Type | Description |
|-------|------|-------------|
| `fundamental_smc_addr` | HashmapE 256 True | Set of special/system smart contract addresses |

### ConfigParam 32–37 — Validator Sets

| Param | Description |
|-------|-------------|
| 32 | Previous validator set |
| 33 | Previous temporary validator set |
| 34 | **Current validator set** (active validators) |
| 35 | Current temporary validator set |
| 36 | Next validator set (elected, not yet active) |
| 37 | Next temporary validator set |

Each `ValidatorSet` contains:

| Field | Type | Description |
|-------|------|-------------|
| `utime_since` | uint32 | Start time of this validator set |
| `utime_until` | uint32 | End time of this validator set |
| `total` | uint16 | Total number of validators |
| `main` | uint16 | Number of main (masterchain) validators |
| `total_weight` | uint64 | Sum of all validator weights |
| `list` | HashmapE 16 ValidatorDescr | Map of validator index to descriptor |

Each `ValidatorDescr` contains:

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | SigPubKey | Ed25519 public key |
| `weight` | uint64 | Validator weight (proportional to stake) |
| `adnl_addr` | bits256 | ADNL address (optional, for routing) |

### ConfigParam 39 — Validator Temporary Keys

| Field | Type | Description |
|-------|------|-------------|
| (dict) | HashmapE 256 ValidatorSignedTempKey | Map of validator key hash to signed temporary key |

Each entry contains a temporary key and its Ed25519 signature.

### ConfigParam 40 — Misbehaviour Punishment

| Field | Type | Description |
|-------|------|-------------|
| `default_flat_fine` | Tomis | Fixed fine for misbehaviour |
| `default_proportional_fine` | uint32 | Proportional fine (fraction of stake, fixed-point) |
| `severity_flat_mult` | uint16 | Multiplier for severe violations |
| `severity_proportional_mult` | uint16 | Multiplier for severe violations |
| `unpunishable_interval` | uint32 | Grace period (seconds) before punishment applies |
| `long_interval` | uint32 | Interval for repeated offence detection |
| `long_flat_mult` | uint16 | Multiplier for repeated offences |
| `long_proportional_mult` | uint16 | Multiplier for repeated offences |
| `medium_interval` | uint32 | Medium interval for offence detection |
| `medium_flat_mult` | uint16 | Multiplier for medium-frequency offences |
| `medium_proportional_mult` | uint16 | Multiplier for medium-frequency offences |

### ConfigParam 43 — Size Limits

| Field | Type | Description |
|-------|------|-------------|
| `max_msg_bits` | uint32 | Maximum message size in bits |
| `max_msg_cells` | uint32 | Maximum message size in cells |
| `max_library_cells` | uint32 | Maximum library cells |
| `max_vm_data_depth` | uint16 | Maximum depth of VM data structures |
| `max_ext_msg_size` | uint32 | Maximum external message size (bytes) |
| `max_ext_msg_depth` | uint16 | Maximum external message cell depth |
| `max_acc_state_cells` | uint32 | Maximum account state size in cells (v2) |
| `max_mc_acc_state_cells` | uint32 | Maximum masterchain account state size (v2) |

### ConfigParam 44 — Suspended Addresses

| Field | Type | Description |
|-------|------|-------------|
| `addresses` | HashmapE 288 Unit | Set of suspended addresses (workchain + addr = 288 bits) |
| `suspended_until` | uint32 | Suspension end timestamp |

### ConfigParam 45 — Precompiled Contracts

| Field | Type | Description |
|-------|------|-------------|
| `list` | HashmapE 256 PrecompiledSmc | Map of code hash to precompiled contract config |

Each entry: `gas_usage: uint64` — fixed gas charged for the precompiled contract.

### ConfigParam 71–73 — Oracle Bridge Parameters

| Param | Bridge |
|-------|--------|
| 71 | Ethereum |
| 72 | Binance Smart Chain |
| 73 | Polygon |

Each `OracleBridgeParams` contains:

| Field | Type | Description |
|-------|------|-------------|
| `bridge_address` | bits256 | Bridge smart contract address |
| `oracle_multisig_address` | bits256 | Oracle multisig address |
| `oracles` | HashmapE 256 uint256 | Map of oracle IDs to public keys |
| `external_chain_address` | bits256 | Contract address on the external chain |

### ConfigParam 79, 81, 82 — Jetton Bridge Parameters

| Param | Bridge |
|-------|--------|
| 79 | ETH->TOS |
| 81 | BNB->TOS |
| 82 | Polygon->TOS |

Each `JettonBridgeParams` contains:

| Field | Type | Description |
|-------|------|-------------|
| `bridge_address` | bits256 | Bridge contract address |
| `oracles_address` | bits256 | Oracles contract address |
| `oracles` | HashmapE 256 uint256 | Oracle set |
| `state_flags` | uint8 | Bridge state flags |
| `prices` | JettonBridgePrices | Fee schedule (v1 only) |
| `external_chain_address` | bits256 | External chain contract (v1 only) |

### Negative (Internal) Parameters

| Param | Description |
|-------|-------------|
| -13 | Restriction timer for restricted wallets |
| -999 | Reserved for internal use |
| -1000 | Reserved for internal use |
| -1001 | Reserved for internal use |

## Inspecting Parameters

```bash
tos-lite-client -C /data/tos-global.json
```

Inside lite-client:

```
> getconfig 8        # global version and capabilities
> getconfig 15       # election timing
> getconfig 17       # stake limits
> getconfig 19       # global_id
> getconfig 20       # gas prices (masterchain)
> getconfig 21       # gas prices (basechain)
> getconfig 22       # block limits (masterchain)
> getconfig 28       # catchain config
> getconfig 29       # consensus config
> getconfig 34       # current validator set
> allconfig          # dump all config parameters
```

## How Parameters Are Set

### At genesis (zero state)

Initial values are set in the zero state Fift script (`gen-zerostate.fif` / `gen-zerostate-test.fif`). See [Zerostate.md](Zerostate.md) for details.

### At runtime (governance)

Config changes require a proposal submitted to the config smart contract (ConfigParam 0) and approval through the on-chain voting mechanism (ConfigParam 11 rules).

1. Build the new parameter value as a Cell (via Fift or code)
2. Submit a config proposal via validator console or transaction to the config contract
3. Validators vote on the proposal
4. If accepted (per ConfigParam 11 rules), the new value takes effect

Critical parameters (listed in ConfigParam 10) require a higher approval threshold.

## Safety Rules

- Never change a param without understanding its exact TL-B shape in [block.tlb](../crypto/block/block.tlb).
- ConfigParam 8 (global version) and validator params (15-17, 28-29, 34) are high-risk.
- ConfigParam 19 (global_id) should **never** change after genesis — it would break all wallet signatures.
- Always record the previous value and hash before proposing a change.
- Test in a local testnet first (see [Validator-Local.md](Validator-Local.md)).

## Recommended Settings

The following values are the recommended baseline for TOS networks.

### Core Identity

| Param | Field | Value |
|-------|-------|-------|
| 0 | config_addr | `-1:555...555` |
| 1 | elector_addr | `-1:333...333` |
| 8 | version | 13 |
| 8 | capabilities | 494 |
| 19 | global_id | **1** (mainnet), **2** (testnet), **3** (dev) |

### Election and Validators

| Param | Field | Value |
|-------|-------|-------|
| 15 | validators_elected_for | 65,536s (18.2h) |
| 15 | elections_start_before | 32,768s (9.1h) |
| 15 | elections_end_before | 8,192s (2.2h) |
| 15 | stake_held_for | 32,768s (9.1h) |
| 16 | max_validators | 400 |
| 16 | max_main_validators | 100 |
| 16 | min_validators | 13 |
| 17 | min_stake | 10,000 TOS |
| 17 | max_stake | 10,000,000 TOS |
| 17 | min_total_stake | 500,000 TOS |
| 17 | max_stake_factor | 196,608 (3x) |

### Gas Prices

| Field | Masterchain (20) | Basechain (21) |
|-------|-----------------|----------------|
| gas_price | 655,360,000 | 26,214,400 |
| gas_limit | 1,000,000 | 1,000,000 |
| special_gas_limit | 70,000,000 | 1,000,000 |
| gas_credit | 10,000 | 10,000 |
| block_gas_limit | 2,500,000 | 10,000,000 |
| freeze_due_limit | 0.1 TOS | 0.1 TOS |
| delete_due_limit | 1.0 TOS | 1.0 TOS |
| flat_gas_limit | 100 | 100 |
| flat_gas_price | 1,000,000 | 40,000 |

### Block Limits

| Field | Masterchain (22) | Basechain (23) |
|-------|-----------------|----------------|
| bytes: underload / soft / hard | 128 KB / 512 KB / 1 MB | 256 KB / 1 MB / 2 MB |
| gas: underload / soft / hard | 500K / 1M / 2.5M | 2M / 10M / 20M |
| lt: underload / soft / hard | 1,000 / 5,000 / 10,000 | 1,000 / 5,000 / 10,000 |

### Message Forwarding Prices

| Field | Masterchain (24) | Basechain (25) |
|-------|-----------------|----------------|
| lump_price | 10,000,000 | 400,000 |
| bit_price | 655,360,000 | 26,214,400 |
| cell_price | 65,536,000,000 | 2,621,440,000 |
| ihr_factor | 98,304 (1.5x) | 98,304 (1.5x) |
| first_frac | 21,845 (1/3) | 21,845 (1/3) |
| next_frac | 21,845 (1/3) | 21,845 (1/3) |

### Storage Prices (ConfigParam 18)

| Field | Value |
|-------|-------|
| bit_price_ps | 1 |
| cell_price_ps | 500 |
| mc_bit_price_ps | 1,000 |
| mc_cell_price_ps | 500,000 |

### Catchain (ConfigParam 28)

| Field | Value | Notes |
|-------|-------|-------|
| mc_catchain_lifetime | 250 | Seconds per masterchain catchain session |
| shard_catchain_lifetime | 250 | Seconds per shard catchain session |
| shard_validators_lifetime | 1,000 | Seconds a shard validator group stays assigned |
| shard_validators_num | 7 | Scale to 23 as validator count grows |
| shuffle_mc_validators | true | Randomize masterchain validator ordering |

### Consensus (ConfigParam 29)

| Field | Value | Notes |
|-------|-------|-------|
| round_candidates | 3 | Block candidates per round |
| next_candidate_delay_ms | 2,000 | Delay before next candidate (ms) |
| consensus_timeout_ms | 16,000 | Round timeout — primary block time factor |
| fast_attempts | 3 | Fast attempts before fallback |
| attempt_duration | 8 | Per-attempt duration (catchain units) |
| catchain_max_deps | 4 | Max catchain DAG dependencies |
| max_block_bytes | 2,097,152 | 2 MB |
| max_collated_bytes | 2,097,152 | 2 MB |
| proto_version | 5 | Consensus protocol version |
| catchain_max_blocks_coeff | 10,000 | 0 = unlimited (dev only) |
| new_catchain_ids | true | New-style catchain session IDs |

Block time: ~3-4s on local testnet, ~5s on production network.

### Block Creation Fees (ConfigParam 14)

| Field | Value |
|-------|-------|
| masterchain_block_fee | 1.7 TOS |
| basechain_block_fee | 1.0 TOS |

### Complaint Pricing (ConfigParam 13)

| Field | Value |
|-------|-------|
| deposit | 100 TOS |
| bit_price | 1 |
| cell_price | 500 |

> **Note:** TOS wallet contracts include global_id in message signatures for anti-replay protection. ConfigParam 19 must never change after genesis.

## Related Docs

- [block.tlb](../crypto/block/block.tlb) — Canonical TL-B schema
- [Zerostate.md](Zerostate.md) — How initial config values are set at genesis
- [GlobalVersions.md](GlobalVersions.md) — ConfigParam 8 version history
- [Currency.md](Currency.md) — TOS currency units (Tomi/nanotomi)
- [Validator.md](Validator.md) — Validator operation
- [Validator-Local.md](Validator-Local.md) — Local testnet setup
- [LiteClient.md](LiteClient.md) — Querying config values
