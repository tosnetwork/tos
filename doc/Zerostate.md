# TOS Zero State (Genesis Block)

The zero state is the initial state of the blockchain — block 0 of the masterchain and workchain 0. It contains the initial smart contracts, configuration parameters, validator set, and balance distribution. Every node must have the same zero state to agree on the same chain.

## What the Zero State Contains

| Component | Description |
|-----------|-------------|
| **Workchain 0 state** (`basestate0.boc`) | Empty initial state for the base workchain |
| **Masterchain state** (`zerostate.boc`) | Full initial state including all items below |
| **Smart contract #1** | Main wallet (holds initial TOS supply) |
| **Smart contract #3** | Tick-tock test contract |
| **Smart contract #4** | Elector (manages validator elections) |
| **Smart contract #5** | Config (stores and governs config parameters) |
| **Configuration parameters** | All ConfigParam values (see [ConfigParam.md](ConfigParam.md)) |
| **Initial validator set** | Public keys and weights of genesis validators |
| **Special addresses** | Elector, config, minter addresses |

## Generation Process

### Source files

| File | Purpose |
|------|---------|
| `crypto/smartcont/gen-zerostate.fif` | Mainnet template (`global_id = 1`) |
| `crypto/smartcont/gen-zerostate-test.fif` | Testnet template (`global_id = 2`) |
| `test/tostester/src/tostester/zerostate.py` | Python wrapper for test/dev generation |
| `crypto/smartcont/CreateState.fif` | Fift library with `setglobalid`, `register_smc`, `create_state`, etc. |

### Build tool

The `create-state` binary (`build/crypto/create-state`) is a Fift interpreter that executes the zero state script and produces the output files.

```bash
cd /path/to/output
create-state -I crypto/fift/lib -I crypto/smartcont -s gen-zerostate.fif
```

### Output files

| File | Content |
|------|---------|
| `zerostate.boc` | Masterchain genesis state (Bag of Cells) |
| `basestate0.boc` | Workchain 0 genesis state |
| `zerostate.rhash` | 32-byte root hash (binary) |
| `zerostate.fhash` | 32-byte file hash (binary) |
| `basestate0.rhash` | 32-byte root hash (binary) |
| `basestate0.fhash` | 32-byte file hash (binary) |
| `main-wallet.pk` | Private key for the main wallet |
| `main-wallet.addr` | Address of the main wallet |
| `config-master.pk` | Private key for the config contract |
| `config-master.addr` | Address of the config contract |
| `elector.addr` | Address of the elector contract |

The root hash and file hash are used in the global config (`validator.zero_state`) to identify the genesis block. Every node verifies that the zero state .boc files match these hashes.

## Zero State Script Structure

The Fift script (`gen-zerostate-test.fif`) follows this structure:

### 1. Setup

```fift
"TosUtil.fif" include
"Asm.fif" include
"Lists.fif" include

wc_master setworkchain
3 setglobalid               // global_id for this network
```

`setglobalid` sets ConfigParam 19. This value is embedded in every block header and used for [anti-replay protection](../crypto/smartcont/wallet3-code.fc) in wallet signatures.

| Network | global_id |
|---------|-----------|
| Mainnet | 1 |
| Testnet | 2 |
| Dev/local | 3 |

### 2. Workchain 0 state

```fift
0 mkemptyShardState           // create empty workchain 0 state

// ... serialize to basestate0.boc ...

basestate0_rhash basestate0_fhash now 0 0 dup 0
  add-std-workchain-v2        // register workchain 0 descriptor
config.workchains!            // set ConfigParam 12
```

### 3. Smart contracts

Each contract is registered with `register_smc`:

```fift
<code_cell>
<data_cell>
<libraries>
<balance>          // initial balance in nanotomis
<split_depth>
<ticktock>         // 0=none, 2=tick, 3=tick+tock
<address>          // or AllOnes * N for well-known addresses
<mode>             // 2=create, 6=create+setaddr
register_smc
```

**Well-known addresses:**

| Contract | Address (masterchain) | Formula |
|----------|----------------------|---------|
| Main wallet | `-1:000...000` | `AllOnes 0 *` |
| Elector | `-1:333...333` | `AllOnes 3 *` |
| Config | `-1:555...555` | `AllOnes 5 *` |
| Test giver | `-1:666...666` | `AllOnes 6 *` |

### 4. Configuration parameters

All initial config values are set via Fift helper words:

```fift
// ConfigParam 8: version + capabilities
13 capCreateStats capBounceMsgBody or ... config.version!

// ConfigParam 16: validator counts
1000 100 13 config.validator_num!
// max_validators max_main_validators min_validators

// ConfigParam 17: stake limits
TM$10000 TM$10000000 TM$500000 sg~3 config.validator_stake_limits!
// min_stake max_stake min_total_stake max_stake_factor

// ConfigParam 15: election timing
65536 32768 8192 32768 config.election_params!
// elected_for start_before end_before stake_held_for

// ConfigParam 0, 1: contract addresses
config_addr config.config_smc!
elector_addr config.elector_smc!

// ConfigParam 18: storage prices
1 500 1000 500000 config.storage_prices!

// ConfigParam 21: basechain gas prices
1000 sg* 1 *M dup 10000 10 *M TM$0.1 TM$1.0 1000 1000000
  config.gas_prices!
// gas_price gas_limit special_gas_limit gas_credit block_gas_limit
//   freeze_due_limit delete_due_limit flat_gas_limit flat_gas_price

// ConfigParam 20: masterchain gas prices
10000 sg* 1 *M 10 *M 10000 10 *M TM$0.1 TM$1.0 1000 10000000
  config.mc_gas_prices!

// ConfigParam 25: basechain forwarding prices
1000000 1000 sg* 100000 sg* 3/2 sg*/ 1/3 sg*/ 1/3 sg*/
  config.fwd_prices!
// lump_price bit_price cell_price ihr_factor first_frac next_frac

// ConfigParam 24: masterchain forwarding prices
10000000 10000 sg* 1000000 sg* 3/2 sg*/ 1/3 sg*/ 1/3 sg*/
  config.mc_fwd_prices!

// ConfigParam 28: catchain params
250 250 1000 3 true config.catchain_params!
// mc_lifetime shard_lifetime shard_validators_count shard_val_num mc_shuffle

// ConfigParam 29: consensus params
3 2000 16000 3 8 4 2 *Mi 2 *Mi true config.consensus_params!

// ConfigParam 22, 23: block limits
// bytes: underload soft hard
// gas: underload soft hard
// lt: underload soft hard

// ConfigParam 14: block creation fees
TM$1.7 TM$1 config.block_create_fees!

// ConfigParam 9, 10: mandatory and critical params
( 0 1 9 10 12 14 15 16 17 18 20 21 22 23 24 25 28 34 )
  config.mandatory_params!
( -999 -1000 -1001 0 1 9 10 12 14 15 16 17 32 34 36 )
  config.critical_params!
```

### 5. Validator keys

Validator public keys are loaded from `validator-keys.pub` (concatenated 32-byte Ed25519 public keys):

```fift
"validator-keys.pub" file>B
{ dup Blen } { 32 B| swap dup ."Validator public key = " Bx. cr
  17 add-validator } while drop

now dup 3600 + <num_validators> config.validators!
```

The `17` in `add-validator` is the validator weight. `config.validators!` sets ConfigParam 34 (current validator set) with validity window `[now, now + 3600]`.

For dev/local testnet, keys can be generated inline:

```fift
newkeypair nip 17 add-validator    // generates a fresh keypair
```

### 6. Create state

```fift
create_state
dup 31 boc+>B dup "zerostate.boc" B>file
Bhashu dup =: zerostate_fhash 256 u>B "zerostate.fhash" B>file
hashu dup =: zerostate_rhash 256 u>B "zerostate.rhash" B>file
```

## How Zero State Links to Global Config

The global config references the zero state by its hashes:

```json
{
  "validator": {
    "@type": "validator.config.global",
    "zero_state": {
      "workchain": -1,
      "shard": -9223372036854775808,
      "seqno": 0,
      "root_hash": "<base64 of zerostate.rhash>",
      "file_hash": "<base64 of zerostate.fhash>"
    }
  }
}
```

When a validator starts, it:
1. Reads `root_hash` and `file_hash` from the global config
2. Looks for a matching .boc file in its `static/` directory (filename = uppercase hex of file_hash)
3. Verifies the file's actual hash matches
4. Uses it as the genesis block

## How Nodes Get the Zero State

The .boc files must be placed in the node's `static/` directory before first start:

```bash
# Symlink by file hash
ln -s /data/zerostate/zerostate.boc /data/tos1/static/<ZEROSTATE_FHASH_HEX>
ln -s /data/zerostate/basestate0.boc /data/tos1/static/<BASESTATE0_FHASH_HEX>
```

If the file is missing, the node will attempt to download it from peers (slow for genesis; always better to pre-place it).

## Customizing the Zero State

To create a custom network:

1. Copy `gen-zerostate-test.fif` and modify:
   - `setglobalid` — unique chain ID
   - `config.validator_num!` — validator count limits
   - `config.election_params!` — election timing
   - `config.gas_prices!` / `config.mc_gas_prices!` — fee structure
   - Validator keys
2. Run `create-state` to generate .boc files
3. Build global config with the output hashes
4. Distribute .boc files to all nodes

**Important:** Once the network starts producing blocks, the zero state is immutable. Config parameters can only be changed through the on-chain governance mechanism after genesis.

## Recommended Genesis Settings

The following table maps Fift calls in the zero state script to their recommended values for TOS networks. See [ConfigParam.md](ConfigParam.md) for the full parameter reference.

| Fift call | ConfigParam | Recommended Value |
|-----------|-------------|-------------------|
| `setglobalid` | 19 | **1** (mainnet), **2** (testnet), **3** (dev) |
| `config.version!` | 8 | version=13, capabilities=494 |
| `config.validator_num!` | 16 | max=400, main=100, min=3 |
| `config.validator_stake_limits!` | 17 | min=300K TOS, max=10M TOS, total=900K TOS, factor=3x |
| `config.election_params!` | 15 | 65536 / 32768 / 8192 / 32768 |
| `config.storage_prices!` | 18 | 1 / 500 / 1000 / 500000 |
| `config.gas_prices!` | 21 | gas_price=26M, limit=1M, block=10M |
| `config.mc_gas_prices!` | 20 | gas_price=655M, limit=1M, block=2.5M |
| `config.fwd_prices!` | 25 | lump=400K, bit=26M, cell=2.6G |
| `config.mc_fwd_prices!` | 24 | lump=10M, bit=655M, cell=65G |
| `config.catchain_params!` | 28 | mc=250, shard=250, val=1000, num=7 |
| `config.consensus_params!` | 29 | cand=3, timeout=16s, blocks=2MB |
| `config.block_create_fees!` | 14 | mc=1.7 TOS, base=1.0 TOS |

**Design notes:**
- **global_id**: TOS uses positive values (1/2/3) to clearly distinguish from other networks. Wallet contracts include global_id in signatures for [anti-replay protection](../crypto/smartcont/wallet3-code.fc).
- **Validator thresholds**: `min_validators=13` and `min_stake=10K TOS` allow bootstrapping with a smaller initial validator set, then increase via governance as the network grows.
- **ConfigParam 19 is permanent** — global_id should never change after genesis, as it would invalidate all existing wallet signatures.

All fee and gas parameters can be adjusted through on-chain governance after the network is running.

## Related Docs

- [ConfigParam.md](ConfigParam.md) — Complete parameter reference
- [GlobalVersions.md](GlobalVersions.md) — ConfigParam 8 (version/capabilities)
- [Validator-Local.md](Validator-Local.md) — Local testnet setup (generates zero state automatically)
- [block.tlb](../crypto/block/block.tlb) — TL-B schema for all config types
