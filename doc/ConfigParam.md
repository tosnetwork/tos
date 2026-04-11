# TOS Configuration Parameters

Configuration parameters are protocol values stored in the masterchain state. They control validator behavior, fees, limits, smart contract addresses, feature flags, and network policy. All validators read the same config from the chain; changes require on-chain governance.

The canonical TL-B schema is in [block.tlb](../crypto/block/block.tlb). Initial values are set during [zero state generation](Zerostate.md).

## Complete Parameter Reference

### Core Addresses

| Param | Type | Description |
|-------|------|-------------|
| 0 | `bits256` | Config smart contract address |
| 1 | `bits256` | Elector smart contract address |
| 2 | `bits256` | Minter address (falls back to param 0) |
| 3 | `bits256` | Fee collector address (falls back to param 1) |
| 4 | `bits256` | DNS root resolver address |

### Protocol Control

| Param | Type | Description |
|-------|------|-------------|
| 5 | `BurningConfig` | Fee burning configuration |
| 6 | `Tomis Tomis` | Minting prices (mint_new, mint_add) |
| 7 | `ExtraCurrencyCollection` | Extra currencies to mint |
| 8 | `GlobalVersion` | Global version and capability flags (see [GlobalVersions.md](GlobalVersions.md)) |
| 9 | `Hashmap 32 True` | Mandatory config parameters (must always be present) |
| 10 | `Hashmap 32 True` | Critical config parameters (require supermajority to change) |
| 11 | `ConfigVotingSetup` | Proposal/voting rules for config changes |
| 19 | `int32` | **global_id** — chain identity (mainnet=1, testnet=2, dev=3) |

### Workchains and Sharding

| Param | Type | Description |
|-------|------|-------------|
| 12 | `HashmapE 32 WorkchainDescr` | Active workchain descriptions |

### Fees and Pricing

| Param | Type | Description |
|-------|------|-------------|
| 13 | `ComplaintPricing` | Validator complaint pricing |
| 14 | `BlockCreateFees` | Block creation reward fees |
| 18 | `Hashmap 32 StoragePrices` | Storage fee schedule (per cell/bit per second) |
| 20 | `GasLimitsPrices` | Masterchain gas prices and limits |
| 21 | `GasLimitsPrices` | Basechain gas prices and limits |
| 24 | `MsgForwardPrices` | Masterchain message forwarding prices |
| 25 | `MsgForwardPrices` | Basechain message forwarding prices |

`GasLimitsPrices` fields: `gas_price`, `gas_limit`, `special_gas_limit`, `gas_credit`, `block_gas_limit`, `freeze_due_limit`, `delete_due_limit`, `flat_gas_limit`, `flat_gas_price`.

`MsgForwardPrices` fields: `lump_price`, `bit_price`, `cell_price`, `ihr_factor`, `first_frac`, `next_frac`.

### Block Limits

| Param | Type | Description |
|-------|------|-------------|
| 22 | `BlockLimits` | Masterchain block limits (bytes, gas, lt) |
| 23 | `BlockLimits` | Basechain block limits |

Each `BlockLimits` contains `underload`, `soft_limit`, `hard_limit` for bytes, gas, and logical time.

### Validators

| Param | Type | Description |
|-------|------|-------------|
| 15 | `uint32 uint32 uint32` | Election timing: `validators_elected_for`, `elections_start_before`, `elections_end_before`, `stake_held_for` |
| 16 | `uint32 uint32 uint32` | Validator count limits: `max_validators`, `max_main_validators`, `min_validators` |
| 17 | `Tomis Tomis Tomis uint32` | Stake limits: `min_stake`, `max_stake`, `min_total_stake`, `max_stake_factor` |
| 28 | `CatchainConfig` | Catchain parameters (see detailed breakdown below) |
| 29 | `ConsensusConfig` | BFT consensus parameters (see detailed breakdown below) |
| 30 | `NewConsensusConfigAll` | Simplex consensus parameters (if used) |

**ConfigParam 28 — CatchainConfig fields:**

| Field | Type | Description |
|-------|------|-------------|
| `mc_catchain_lifetime` | uint32 | Masterchain catchain session lifetime (seconds). After this time, a new catchain group is formed. |
| `shard_catchain_lifetime` | uint32 | Shard catchain session lifetime (seconds). |
| `shard_validators_lifetime` | uint32 | How long a shard validator group stays assigned to a shard (seconds). |
| `shard_validators_num` | uint32 | Number of validators assigned to each shard. Higher = more security per shard, but fewer shards can run in parallel. |
| `shuffle_mc_validators` | bool | Whether to shuffle masterchain validator ordering each round. |

**ConfigParam 29 — ConsensusConfig fields:**

| Field | Type | Description |
|-------|------|-------------|
| `flags` | uint8 | Bit flags (0 = default). |
| `new_catchain_ids` | bool | Use new-style catchain session IDs. |
| `round_candidates` | uint8 | Number of block candidates proposed per consensus round. More candidates = more redundancy but more network traffic. |
| `next_candidate_delay_ms` | uint32 | Delay (ms) before proposing the next block candidate if the first one fails. |
| `consensus_timeout_ms` | uint32 | Maximum time (ms) for a single consensus round before timeout. This is the primary parameter affecting block time. |
| `fast_attempts` | uint32 | Number of fast consensus attempts before falling back to slower mode. |
| `attempt_duration` | uint32 | Duration of each consensus attempt (in catchain time units). |
| `catchain_max_deps` | uint32 | Maximum number of catchain block dependencies. Controls how "wide" the catchain DAG can be. |
| `max_block_bytes` | uint32 | Maximum size of a block in bytes. |
| `max_collated_bytes` | uint32 | Maximum size of collated data (proofs + data sent to validators for verification). |
| `proto_version` | uint16 | Consensus protocol version. |
| `catchain_max_blocks_coeff` | uint32 | Coefficient limiting catchain blocks per round. 0 = unlimited, 10000 = production default. |
| 31 | `HashmapE 256 True` | Fundamental (special) smart contract addresses |
| 32 | `ValidatorSet` | Previous validator set |
| 33 | `ValidatorSet` | Previous temporary validator set |
| 34 | `ValidatorSet` | **Current validator set** (active validators) |
| 35 | `ValidatorSet` | Current temporary validator set |
| 36 | `ValidatorSet` | Next validator set (elected, not yet active) |
| 37 | `ValidatorSet` | Next temporary validator set |
| 39 | `HashmapE 256 ValidatorSignedTempKey` | Validator temporary key signatures |
| 40 | `MisbehaviourPunishmentConfig` | Punishment config for misbehaving validators |

### System Limits

| Param | Type | Description |
|-------|------|-------------|
| 43 | `SizeLimitsConfig` | Size limits (max msg bits/cells, max account state, etc.) |
| 44 | `SuspendedAddressList` | Suspended/frozen addresses |
| 45 | `PrecompiledContractsConfig` | Precompiled contract gas usage overrides |

### Bridges

| Param | Type | Description |
|-------|------|-------------|
| 71 | `OracleBridgeParams` | Ethereum oracle bridge |
| 72 | `OracleBridgeParams` | Binance Smart Chain oracle bridge |
| 73 | `OracleBridgeParams` | Polygon oracle bridge |
| 79 | `JettonBridgeParams` | ETH->TOS token bridge |
| 81 | `JettonBridgeParams` | BNB->TOS token bridge |
| 82 | `JettonBridgeParams` | Polygon->TOS token bridge |

### Negative (Internal) Parameters

| Param | Description |
|-------|-------------|
| -999 | (reserved for internal use) |
| -1000 | (reserved for internal use) |
| -1001 | (reserved for internal use) |
| -13 | Restriction timer for restricted wallets |

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
> getconfig 34       # current validator set
> allconfig          # dump all config parameters
```

## How Parameters Are Set

### At genesis (zero state)

Initial values are set in the zero state Fift script (`gen-zerostate.fif` / `gen-zerostate-test.fif`). See [Zerostate.md](Zerostate.md) for details.

Example calls in the zero state script:

```fift
3 setglobalid                                    // ConfigParam 19
13 cap... config.version!                        // ConfigParam 8
1000 100 13 config.validator_num!                 // ConfigParam 16
TM$10000 TM$10000000 TM$500000 sg~3              // ConfigParam 17
  config.validator_stake_limits!
65536 32768 8192 32768 config.election_params!    // ConfigParam 15
1 500 1000 500000 config.storage_prices!          // ConfigParam 18
1000 sg* 1 *M dup 10000 10 *M TM$0.1 TM$1.0     // ConfigParam 21
  1000 1000000 config.gas_prices!
```

### At runtime (governance)

Config changes require a proposal submitted to the config smart contract (address in ConfigParam 0) and approval through the on-chain voting mechanism (ConfigParam 11 rules).

The workflow:

1. Build the new parameter value as a Cell (via Fift or code)
2. Submit a config proposal via validator console or a transaction to the config contract
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

The following values are the recommended baseline for TOS networks. Adjust as needed.

### Core Identity

| Param | Field | Value |
|-------|-------|-------------|-----------------|
| 0 | Config address | `-1:555...555` (same convention) |
| 1 | Elector address | `-1:333...333` (same convention) |
| 8 | Global version | 13 |
| 8 | Capabilities | 494 |
| 19 | global_id | **1** (mainnet), **2** (testnet), **3** (dev) |

### Validator Parameters

| Param | Field | Value |
|-------|-------|-------------|-----------------|
| 15 | validators_elected_for | 65,536s |
| 15 | elections_start_before | 32,768s |
| 15 | elections_end_before | 8,192s |
| 15 | stake_held_for | 32,768s |
| 16 | max_validators | 400 |
| 16 | max_main_validators | 100 |
| 16 | min_validators | 13 (start small) |
| 17 | min_stake | 10,000 TOS |
| 17 | max_stake | 10,000,000 TOS |
| 17 | min_total_stake | 500,000 TOS |
| 17 | max_stake_factor | 196,608 (3x) |

### Gas Prices (ConfigParam 20 = masterchain, 21 = basechain)

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

`gas_price` is in nanoTOS per 2^16 gas units. Masterchain is ~25x more expensive than basechain.

### Block Limits (ConfigParam 22 = masterchain, 23 = basechain)

Each limit has three tiers: underload (triggers shard merge), soft (normal target), hard (absolute maximum).

| Field | Masterchain (22) | Basechain (23) |
|-------|-----------------|----------------|
| bytes: underload / soft / hard | 128 KB / 512 KB / 1 MB | 256 KB / 1 MB / 2 MB |
| gas: underload / soft / hard | 500,000 / 1,000,000 / 2,500,000 | 2,000,000 / 10,000,000 / 20,000,000 |
| lt: underload / soft / hard | 1,000 / 5,000 / 10,000 | 1,000 / 5,000 / 10,000 |

### Message Forwarding Prices (ConfigParam 24 = masterchain, 25 = basechain)

| Field | Masterchain (24) | Basechain (25) |
|-------|-----------------|----------------|
| lump_price | 10,000,000 | 400,000 |
| bit_price | 655,360,000 | 26,214,400 |
| cell_price | 65,536,000,000 | 2,621,440,000 |
| ihr_factor | 98,304 (1.5x) | 98,304 (1.5x) |
| first_frac | 21,845 (1/3) | 21,845 (1/3) |
| next_frac | 21,845 (1/3) | 21,845 (1/3) |

### Storage Prices

| Param | Field | Value |
|-------|-------|-------------|-----------------|
| 18 | bit_price_ps | 1 |
| 18 | cell_price_ps | 500 |
| 18 | mc_bit_price_ps | 1,000 |
| 18 | mc_cell_price_ps | 500,000 |

### Catchain (ConfigParam 28)

| Field | Value | Notes |
|-------|-------|-------|
| mc_catchain_lifetime | 250 | Masterchain catchain session lifetime (seconds) |
| shard_catchain_lifetime | 250 | Shard catchain session lifetime (seconds) |
| shard_validators_lifetime | 1,000 | How long a shard validator group stays assigned (seconds) |
| shard_validators_num | 7 | Validators per shard. Production networks with many validators use 23. Scale up as validator count grows. |
| shuffle_mc_validators | true | Shuffle masterchain validator ordering |

### Consensus (ConfigParam 29)

| Field | Value | Notes |
|-------|-------|-------|
| round_candidates | 3 | Block candidates per round |
| next_candidate_delay_ms | 2,000 | Delay before next candidate (ms) |
| consensus_timeout_ms | 16,000 | Round timeout (ms). Primary factor in block time. |
| fast_attempts | 3 | Fast consensus attempts before fallback |
| attempt_duration | 8 | Duration per attempt (catchain time units) |
| catchain_max_deps | 4 | Max catchain DAG dependencies |
| max_block_bytes | 2,097,152 | 2 MB max block size |
| max_collated_bytes | 2,097,152 | 2 MB max collated data |
| proto_version | 5 | Consensus protocol version |
| catchain_max_blocks_coeff | 10,000 | Catchain blocks-per-round limit. 0 = unlimited (dev only). |
| new_catchain_ids | true | Use new-style catchain session IDs |

**Effect on block time:** With `consensus_timeout_ms=16000` and 3 validators on a local network, typical block time is ~3-4 seconds. On a production network with more validators and network latency, block time is typically ~5 seconds.

### Block Creation Fees

| Param | Field | Value |
|-------|-------|-------------|-----------------|
| 14 | masterchain_block_fee | 1.7 TOS |
| 14 | basechain_block_fee | 1.0 TOS |


> **Note:** TOS wallet contracts include global_id in message signatures for cross-chain anti-replay protection. ConfigParam 19 (global_id) should never change after genesis — it would invalidate all existing wallet signatures.

## Related Docs

- [block.tlb](../crypto/block/block.tlb) — Canonical TL-B schema
- [Zerostate.md](Zerostate.md) — How initial config values are set at genesis
- [GlobalVersions.md](GlobalVersions.md) — ConfigParam 8 details
- [Validator.md](Validator.md) — Validator operation
- [Validator-Local.md](Validator-Local.md) — Local testnet setup
- [LiteClient.md](LiteClient.md) — Querying config values
