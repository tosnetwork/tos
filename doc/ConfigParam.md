# TOS Configuration Parameters

Configuration parameters are protocol values stored in the masterchain state. They control validator behavior, fees, limits, smart contract addresses, feature flags, and network policy. All validators read the same config from the chain; changes require on-chain governance.

The canonical TL-B schema is in [block.tlb](../crypto/block/block.tlb). Initial values are set during [zero state generation](Zerostate.md).

## ConfigParam 0 — Config Smart Contract Address

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `config_addr` | bits256 | `-1:555...555` | Config smart contract address in masterchain |

## ConfigParam 1 — Elector Smart Contract Address

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `elector_addr` | bits256 | `-1:333...333` | Elector smart contract address in masterchain |

## ConfigParam 2 — Minter Address

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `minter_addr` | bits256 | `-1:000...000` | Minter address. Falls back to ConfigParam 0 if absent. |

## ConfigParam 3 — Fee Collector Address

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `fee_collector_addr` | bits256 | (same as param 1) | Collects transaction fees. Falls back to ConfigParam 1 if absent. |

## ConfigParam 4 — DNS Root Address

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `dns_root_addr` | bits256 | (set at launch) | Root TOS DNS resolver address |

## ConfigParam 5 — Fee Burning

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `fee_burn_num` | uint32 | 0 | Numerator of fee burn fraction |
| `fee_burn_denom` | uint32 | 1 | Denominator (must be >= 1, num <= denom). Fraction burned = num/denom. |

## ConfigParam 6 — Minting Prices

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `mint_new_price` | Tomis | 0 | Price to mint a new extra currency |
| `mint_add_price` | Tomis | 0 | Price to add to existing extra currency supply |

## ConfigParam 7 — Extra Currencies to Mint

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `to_mint` | ExtraCurrencyCollection | (see zerostate) | Dictionary of extra currency IDs and amounts to mint each block |

## ConfigParam 8 — Global Version

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `version` | uint32 | **13** | Protocol version. Controls which TVM features are enabled. |
| `capabilities` | uint64 | **494** | Bit flags for protocol capabilities (see below) |

Capability bit table:

| Bit | Value | Name | Enabled |
|-----|-------|------|---------|
| 1 | 2 | capCreateStats | Yes |
| 2 | 4 | capBounceMsgBody | Yes |
| 3 | 8 | capReportVersion | Yes |
| 4 | 16 | capSplitMergeTransactions | No |
| 5 | 32 | capShortDequeue | Yes |
| 6 | 64 | capStoreOutMsgQueueSize | Yes |
| 7 | 128 | capMsgMetadata | Yes |
| 8 | 256 | capDeferMessages | Yes |

494 = 2+4+8+32+64+128+256. See [GlobalVersions.md](GlobalVersions.md) for version history.

## ConfigParam 9 — Mandatory Parameters

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `mandatory_params` | Hashmap 32 True | `{0,1,9,10,12,14,15,16,17,18,20,21,22,23,24,25,28,34}` | Config param IDs that must always be present |

## ConfigParam 10 — Critical Parameters

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `critical_params` | Hashmap 32 True | `{-999,-1000,-1001,0,1,9,10,12,14,15,16,17,32,34,36}` | Params requiring supermajority to change |

## ConfigParam 11 — Voting Rules

`normal_params` (ordinary proposals):

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `min_tot_rounds` | uint8 | 2 | Minimum total voting rounds |
| `max_tot_rounds` | uint8 | 3 | Maximum total voting rounds |
| `min_wins` | uint8 | 2 | Wins required to pass |
| `max_losses` | uint8 | 2 | Losses before rejection |
| `min_store_sec` | uint32 | 1,000,000 | Minimum proposal storage time (seconds) |
| `max_store_sec` | uint32 | 10,000,000 | Maximum proposal storage time (seconds) |
| `bit_price` | uint32 | 1 | Cost per bit of proposal data |
| `cell_price` | uint32 | 500 | Cost per cell of proposal data |

`critical_params` (critical proposals):

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `min_tot_rounds` | uint8 | 4 | Minimum total voting rounds |
| `max_tot_rounds` | uint8 | 7 | Maximum total voting rounds |
| `min_wins` | uint8 | 4 | Wins required to pass |
| `max_losses` | uint8 | 2 | Losses before rejection |
| `min_store_sec` | uint32 | 5,000,000 | Minimum proposal storage time (seconds) |
| `max_store_sec` | uint32 | 20,000,000 | Maximum proposal storage time (seconds) |
| `bit_price` | uint32 | 2 | Cost per bit |
| `cell_price` | uint32 | 1,000 | Cost per cell |

## ConfigParam 12 — Workchain Descriptions

Each `WorkchainDescr` entry (keyed by workchain ID):

| Field | Type | Value (wc 0) | Description |
|-------|------|-------------|-------------|
| `enabled_since` | uint32 | (genesis time) | When workchain was enabled |
| `monitor_min_split` | uint8 | 0 | Minimum split depth for monitoring |
| `min_split` | uint8 | 0 | Minimum shard split depth |
| `max_split` | uint8 | 0 | Maximum shard split depth |
| `basic` | bit | 1 | Basic workchain flag |
| `active` | Bool | true | Workchain is active |
| `accept_msgs` | Bool | true | Accepts messages |
| `zerostate_root_hash` | bits256 | (computed) | Root hash of workchain zero state |
| `zerostate_file_hash` | bits256 | (computed) | File hash of workchain zero state |

## ConfigParam 13 — Complaint Pricing

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `deposit` | Tomis | 100 TOS | Deposit required to file a validator complaint |
| `bit_price` | Tomis | 1 | Cost per bit of complaint data |
| `cell_price` | Tomis | 500 | Cost per cell of complaint data |

## ConfigParam 14 — Block Creation Fees

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `masterchain_block_fee` | Tomis | **1.7 TOS** | Reward for producing a masterchain block |
| `basechain_block_fee` | Tomis | **1.0 TOS** | Reward for producing a basechain block |

## ConfigParam 15 — Election Timing

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `validators_elected_for` | uint32 | **65,536** (18.2h) | How long a validator set is active (seconds) |
| `elections_start_before` | uint32 | **32,768** (9.1h) | How early elections begin before set expiry |
| `elections_end_before` | uint32 | **8,192** (2.3h) | How early elections must end before set expiry |
| `stake_held_for` | uint32 | **32,768** (9.1h) | How long stakes are frozen after set ends |

## ConfigParam 16 — Validator Count Limits

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `max_validators` | uint32 | **400** | Maximum total validators |
| `max_main_validators` | uint32 | **100** | Maximum masterchain validators |
| `min_validators` | uint32 | **13** | Minimum validators for network to operate |

## ConfigParam 17 — Stake Limits

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `min_stake` | Tomis | **10,000 TOS** | Minimum stake to participate in elections |
| `max_stake` | Tomis | **10,000,000 TOS** | Maximum stake per validator |
| `min_total_stake` | Tomis | **500,000 TOS** | Minimum total stake across all validators |
| `max_stake_factor` | uint32 | **196,608** (3x) | Max ratio of largest to smallest stake. Fixed-point: 65536 = 1x. |

## ConfigParam 18 — Storage Prices

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `utime_since` | uint32 | (genesis time) | When these prices take effect |
| `bit_price_ps` | uint64 | **1** | Basechain: price per bit per second |
| `cell_price_ps` | uint64 | **500** | Basechain: price per cell per second |
| `mc_bit_price_ps` | uint64 | **1,000** | Masterchain: price per bit per second |
| `mc_cell_price_ps` | uint64 | **500,000** | Masterchain: price per cell per second |

## ConfigParam 19 — Global ID

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `global_id` | int32 | **1** (mainnet) / **2** (testnet) / **3** (dev) | Chain identity. Must match every block header. **Never change after genesis** — wallet signatures depend on it. |

## ConfigParam 20 — Masterchain Gas Prices

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `gas_price` | uint64 | **655,360,000** | Gas price (nanotomi per 2^16 gas units). ~25x basechain. |
| `gas_limit` | uint64 | **1,000,000** | Max gas per ordinary transaction |
| `special_gas_limit` | uint64 | **70,000,000** | Max gas for special/system transactions |
| `gas_credit` | uint64 | **10,000** | Free gas for external messages (covers signature check) |
| `block_gas_limit` | uint64 | **2,500,000** | Max total gas per block |
| `freeze_due_limit` | uint64 | **100,000,000** (0.1 TOS) | Balance below which account is frozen |
| `delete_due_limit` | uint64 | **1,000,000,000** (1.0 TOS) | Balance below which account is deleted |
| `flat_gas_limit` | uint64 | **100** | Gas amount covered by flat fee |
| `flat_gas_price` | uint64 | **1,000,000** | Flat fee (nanotomi) for gas up to flat_gas_limit |

## ConfigParam 21 — Basechain Gas Prices

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `gas_price` | uint64 | **26,214,400** | Gas price (nanotomi per 2^16 gas units) |
| `gas_limit` | uint64 | **1,000,000** | Max gas per ordinary transaction |
| `special_gas_limit` | uint64 | **1,000,000** | Max gas for special/system transactions |
| `gas_credit` | uint64 | **10,000** | Free gas for external messages |
| `block_gas_limit` | uint64 | **10,000,000** | Max total gas per block |
| `freeze_due_limit` | uint64 | **100,000,000** (0.1 TOS) | Balance below which account is frozen |
| `delete_due_limit` | uint64 | **1,000,000,000** (1.0 TOS) | Balance below which account is deleted |
| `flat_gas_limit` | uint64 | **100** | Gas amount covered by flat fee |
| `flat_gas_price` | uint64 | **40,000** | Flat fee (nanotomi) for gas up to flat_gas_limit |

## ConfigParam 22 — Masterchain Block Limits

Three tiers: underload (triggers shard merge), soft (normal target), hard (absolute max).

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `bytes.underload` | uint32 | **131,072** (128 KB) | Below this → shard merge candidate |
| `bytes.soft_limit` | uint32 | **524,288** (512 KB) | Normal target |
| `bytes.hard_limit` | uint32 | **1,048,576** (1 MB) | Absolute maximum |
| `gas.underload` | uint32 | **500,000** | Below this → shard merge candidate |
| `gas.soft_limit` | uint32 | **1,000,000** | Normal target |
| `gas.hard_limit` | uint32 | **2,500,000** | Absolute maximum |
| `lt_delta.underload` | uint32 | **1,000** | Logical time delta underload |
| `lt_delta.soft_limit` | uint32 | **5,000** | Normal target |
| `lt_delta.hard_limit` | uint32 | **10,000** | Absolute maximum |

## ConfigParam 23 — Basechain Block Limits

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `bytes.underload` | uint32 | **262,144** (256 KB) | Below this → shard merge candidate |
| `bytes.soft_limit` | uint32 | **1,048,576** (1 MB) | Normal target |
| `bytes.hard_limit` | uint32 | **2,097,152** (2 MB) | Absolute maximum |
| `gas.underload` | uint32 | **2,000,000** | Below this → shard merge candidate |
| `gas.soft_limit` | uint32 | **10,000,000** | Normal target |
| `gas.hard_limit` | uint32 | **20,000,000** | Absolute maximum |
| `lt_delta.underload` | uint32 | **1,000** | Logical time delta underload |
| `lt_delta.soft_limit` | uint32 | **5,000** | Normal target |
| `lt_delta.hard_limit` | uint32 | **10,000** | Absolute maximum |

## ConfigParam 24 — Masterchain Forwarding Prices

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `lump_price` | uint64 | **10,000,000** | Fixed fee per message (nanotomi) |
| `bit_price` | uint64 | **655,360,000** | Fee per bit (nanotomi per 2^16 bits) |
| `cell_price` | uint64 | **65,536,000,000** | Fee per cell (nanotomi per 2^16 cells) |
| `ihr_factor` | uint32 | **98,304** (1.5x) | IHR fee multiplier (65536 = 1x) |
| `first_frac` | uint16 | **21,845** (1/3) | Fraction paid by first transit hop |
| `next_frac` | uint16 | **21,845** (1/3) | Fraction paid by each subsequent hop |

## ConfigParam 25 — Basechain Forwarding Prices

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `lump_price` | uint64 | **400,000** | Fixed fee per message (nanotomi) |
| `bit_price` | uint64 | **26,214,400** | Fee per bit (nanotomi per 2^16 bits) |
| `cell_price` | uint64 | **2,621,440,000** | Fee per cell (nanotomi per 2^16 cells) |
| `ihr_factor` | uint32 | **98,304** (1.5x) | IHR fee multiplier |
| `first_frac` | uint16 | **21,845** (1/3) | Fraction paid by first hop |
| `next_frac` | uint16 | **21,845** (1/3) | Fraction paid by subsequent hops |

## ConfigParam 28 — Catchain Config

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `mc_catchain_lifetime` | uint32 | **250** | Masterchain catchain session lifetime (seconds) |
| `shard_catchain_lifetime` | uint32 | **250** | Shard catchain session lifetime (seconds) |
| `shard_validators_lifetime` | uint32 | **1,000** | How long a shard validator group stays assigned (seconds) |
| `shard_validators_num` | uint32 | **7** | Validators per shard. Scale to 23 as network grows. |
| `shuffle_mc_validators` | Bool | **true** | Shuffle masterchain validator ordering each round |

## ConfigParam 29 — Consensus Config

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `flags` | uint6 | **0** | Bit flags (0 = default) |
| `use_quic` | Bool | **true** | Use QUIC transport for consensus (v4+) |
| `new_catchain_ids` | Bool | **true** | Use new-style catchain session IDs |
| `round_candidates` | uint8 | **3** | Block candidates proposed per round |
| `next_candidate_delay_ms` | uint32 | **2,000** | Delay (ms) before next candidate if first fails |
| `consensus_timeout_ms` | uint32 | **16,000** | Round timeout (ms). **Primary block time factor.** |
| `fast_attempts` | uint32 | **3** | Fast consensus attempts before fallback |
| `attempt_duration` | uint32 | **8** | Per-attempt duration (catchain time units) |
| `catchain_max_deps` | uint32 | **4** | Max catchain DAG dependencies |
| `max_block_bytes` | uint32 | **2,097,152** (2 MB) | Maximum block size |
| `max_collated_bytes` | uint32 | **2,097,152** (2 MB) | Maximum collated data size |
| `proto_version` | uint16 | **5** | Consensus protocol version |
| `catchain_max_blocks_coeff` | uint32 | **10,000** | Catchain blocks-per-round limit. 0 = unlimited (dev only). |

Block time: ~3-4s on local testnet (3 validators), ~5s on production network.

## ConfigParam 30 — Simplex Consensus (Optional)

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `mc` | Maybe ^NewConsensusConfig | null | Masterchain simplex params (if used) |
| `shard` | Maybe ^NewConsensusConfig | null | Shard simplex params (if used) |

## ConfigParam 31 — Fundamental Addresses

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `fundamental_smc_addr` | HashmapE 256 True | (elector, config, minter) | Set of special/system smart contract addresses |

## ConfigParam 32–37 — Validator Sets

| Param | Value | Description |
|-------|-------|-------------|
| 32 | (auto) | Previous validator set |
| 33 | (auto) | Previous temporary validator set |
| **34** | **(active set)** | **Current validator set** |
| 35 | (auto) | Current temporary validator set |
| 36 | (auto) | Next validator set (elected, not yet active) |
| 37 | (auto) | Next temporary validator set |

Each `ValidatorSet` contains:

| Field | Type | Description |
|-------|------|-------------|
| `utime_since` | uint32 | Start time of this set |
| `utime_until` | uint32 | End time of this set |
| `total` | uint16 | Total number of validators |
| `main` | uint16 | Number of main (masterchain) validators |
| `total_weight` | uint64 | Sum of all validator weights |
| `list` | HashmapE 16 ValidatorDescr | Validator index → descriptor |

Each `ValidatorDescr`:

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | SigPubKey | Ed25519 public key |
| `weight` | uint64 | Validator weight (proportional to stake) |
| `adnl_addr` | bits256 | ADNL address (optional) |

## ConfigParam 39 — Validator Temporary Keys

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| (dict) | HashmapE 256 ValidatorSignedTempKey | (auto) | Signed temporary keys for validators |

## ConfigParam 40 — Misbehaviour Punishment

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `default_flat_fine` | Tomis | (set by governance) | Fixed fine for misbehaviour |
| `default_proportional_fine` | uint32 | (set by governance) | Proportional fine (fraction of stake) |
| `severity_flat_mult` | uint16 | (set by governance) | Multiplier for severe violations |
| `severity_proportional_mult` | uint16 | (set by governance) | Multiplier for severe violations |
| `unpunishable_interval` | uint32 | (set by governance) | Grace period (seconds) |
| `long_interval` | uint32 | (set by governance) | Interval for repeated offence detection |
| `long_flat_mult` | uint16 | (set by governance) | Multiplier for repeated offences |
| `long_proportional_mult` | uint16 | (set by governance) | Multiplier for repeated offences |
| `medium_interval` | uint32 | (set by governance) | Medium interval |
| `medium_flat_mult` | uint16 | (set by governance) | Medium-frequency multiplier |
| `medium_proportional_mult` | uint16 | (set by governance) | Medium-frequency multiplier |

## ConfigParam 43 — Size Limits

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `max_msg_bits` | uint32 | (default) | Maximum message size in bits |
| `max_msg_cells` | uint32 | (default) | Maximum message size in cells |
| `max_library_cells` | uint32 | (default) | Maximum library cells |
| `max_vm_data_depth` | uint16 | (default) | Maximum depth of VM data structures |
| `max_ext_msg_size` | uint32 | (default) | Maximum external message size (bytes) |
| `max_ext_msg_depth` | uint16 | (default) | Maximum external message cell depth |
| `max_acc_state_cells` | uint32 | (default) | Maximum account state size in cells |
| `max_mc_acc_state_cells` | uint32 | (default) | Maximum masterchain account state size |

## ConfigParam 44 — Suspended Addresses

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `addresses` | HashmapE 288 Unit | (empty) | Suspended addresses (workchain+addr = 288 bits) |
| `suspended_until` | uint32 | 0 | Suspension end timestamp |

## ConfigParam 45 — Precompiled Contracts

| Field | Type | Value | Description |
|-------|------|-------|-------------|
| `list` | HashmapE 256 PrecompiledSmc | (empty) | Map of code hash → `gas_usage:uint64` |

## ConfigParam 71–73 — Oracle Bridge

| Param | Bridge | Field | Type | Description |
|-------|--------|-------|------|-------------|
| 71 | Ethereum | `bridge_address` | bits256 | Bridge contract |
| 71 | | `oracle_multisig_address` | bits256 | Oracle multisig |
| 71 | | `oracles` | HashmapE 256 uint256 | Oracle set |
| 71 | | `external_chain_address` | bits256 | External chain contract |
| 72 | BSC | (same fields) | | |
| 73 | Polygon | (same fields) | | |

## ConfigParam 79, 81, 82 — Jetton Bridge

| Param | Bridge | Field | Type | Description |
|-------|--------|-------|------|-------------|
| 79 | ETH→TOS | `bridge_address` | bits256 | Bridge contract |
| 79 | | `oracles_address` | bits256 | Oracles contract |
| 79 | | `oracles` | HashmapE 256 uint256 | Oracle set |
| 79 | | `state_flags` | uint8 | Bridge state |
| 79 | | `prices` | JettonBridgePrices | Fee schedule |
| 79 | | `external_chain_address` | bits256 | External chain contract |
| 81 | BNB→TOS | (same fields) | | |
| 82 | Polygon→TOS | (same fields) | | |

## Negative (Internal) Parameters

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

```
> getconfig 8        # global version and capabilities
> getconfig 15       # election timing
> getconfig 17       # stake limits
> getconfig 19       # global_id
> getconfig 20       # masterchain gas prices
> getconfig 21       # basechain gas prices
> getconfig 22       # masterchain block limits
> getconfig 23       # basechain block limits
> getconfig 28       # catchain config
> getconfig 29       # consensus config
> getconfig 34       # current validator set
> allconfig          # dump all
```

## How Parameters Are Set

### At genesis

Initial values set in `gen-zerostate.fif` / `gen-zerostate-test.fif`. See [Zerostate.md](Zerostate.md).

### At runtime

Config changes require proposal to the config contract (ConfigParam 0) and voting per ConfigParam 11 rules. Critical parameters (ConfigParam 10) need supermajority.

## Safety Rules

- Never change a param without understanding its TL-B shape in [block.tlb](../crypto/block/block.tlb).
- ConfigParam 8, 15-17, 28-29, 34 are high-risk.
- ConfigParam 19 (global_id) must **never** change after genesis — wallet signatures depend on it.
- Always record the previous value before proposing a change.
- Test in a local testnet first (see [Validator-Local.md](Validator-Local.md)).

## Related Docs

- [block.tlb](../crypto/block/block.tlb) — Canonical TL-B schema
- [Zerostate.md](Zerostate.md) — Genesis config values
- [GlobalVersions.md](GlobalVersions.md) — ConfigParam 8 history
- [Currency.md](Currency.md) — TOS currency units (Tomi/nanotomi)
- [Validator.md](Validator.md) — Validator operation
- [Validator-Local.md](Validator-Local.md) — Local testnet setup
- [LiteClient.md](LiteClient.md) — Querying config values
