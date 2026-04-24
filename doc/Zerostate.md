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
| `crypto/smartcont/gen-zerostate-test.fif` | Testnet template (`global_id = -3`) |
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
  add-std-workchain-v2        // register workchain 0 descriptor (TVM)

// EVM workchain 1 (optional, see crypto/block/evm-workchain/evm-config-param.cpp)
1 mkemptyShardState           // create empty workchain 1 (EVM) state
// ... serialize evmstate1.boc ...
evmstate1_rhash evmstate1_fhash now 0 0 dup 1
  add-evm-workchain           // register workchain 1 descriptor (EVM, vm_version=0x45564D)

config.workchains!            // set ConfigParam 12 with all registered workchains
```

If the `add-evm-workchain` Fift word is not present in the local toolchain, omit the EVM workchain block to produce a TVM-only zerostate, then enable the EVM workchain later via a ConfigParam 12 governance proposal.

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
| `setglobalid` | 19 | **1** (mainnet), **-3** (testnet), **3** (dev) |
| `config.version!` | 8 | version=13, capabilities=494 |
| `config.validator_num!` | 16 | max=40, main=20, min=3 |
| `config.validator_stake_limits!` | 17 | min=300K TOS, max=10M TOS, total=900K TOS, factor=3x |
| `config.election_params!` | 15 | 65536 / 32768 / 8192 / 32768 |
| `config.storage_prices!` | 18 | 1 / 500 / 1000 / 500000 |
| `config.gas_prices!` | 21 | gas_price=26M, limit=1M, block=10M |
| `config.mc_gas_prices!` | 20 | gas_price=655M, limit=1M, block=2.5M |
| `config.fwd_prices!` | 25 | lump=400K, bit=26M, cell=2.6G |
| `config.mc_fwd_prices!` | 24 | lump=10M, bit=655M, cell=65G |
| `config.catchain_params!` | 28 | mc=250, shard=250, val=1000, num=5 |
| `config.consensus_params!` | 29 | cand=3, timeout=16s, blocks=2MB (Catchain fallback) |
| `config.new_consensus_params_all!` | 30 | Simplex: target_rate=400ms, slots=4, timeout=1000ms |
| `config.block_create_fees!` | 14 | mc=1.7 TOS, base=1.0 TOS |

**Design notes:**
- **global_id**: TOS uses distinct values (1/-3/3) to distinguish networks. Wallet contracts include global_id in signatures for [anti-replay protection](../crypto/smartcont/wallet3-code.fc).
- **Validator thresholds**: `min_validators=13` and `min_stake=10K TOS` allow bootstrapping with a smaller initial validator set, then increase via governance as the network grows.
- **ConfigParam 19 is permanent** — global_id should never change after genesis, as it would invalidate all existing wallet signatures.

All fee and gas parameters can be adjusted through on-chain governance after the network is running.

## Initial Token Supply (per-workchain issuance)

TOS ships **two** native tokens — **TOS** (shared across wc=0 TVM and wc=1 EVM) and **UNO** (independent on wc=2). **Initial supply is NOT a ConfigParam** — it is set at zero-state construction time and cannot be changed by on-chain governance after genesis.

| Token | Lives on | Decimals | Target Supply | Role | Where configured | Determinism |
|---|---|---|---|---|---|---|
| **TOS** | master (`-1`) + wc=0 (TVM) **+ wc=1 (EVM)** via cross-WC routing | 9 nano-tomi (TVM) ↔ 18 wei (EVM); 1 nano-tomi = 10⁹ wei | **200,000,000 TOS** total cap | L1 platform gas + staking + EVM dapp gas | `crypto/smartcont/gen-zerostate.fif` line 94 (`TM$200000000 allocated-balance -`); 100% lives in wc=0 main wallet at genesis | Baked into `zerostate.boc` at genesis; wc=1 starts empty (apart from dev seed) and is funded by cross-WC routing from wc=0 |
| **UNO** | wc=2 (STARK) | 9 nano-UNO | **21,000,000 UNO** total cap | Privacy "digital gold" (peer of Bitcoin / Zcash) | `uno/core/genesis.h` `kGenesisTotalSupplyNano` constexpr, split 60 / 25 / 15 = 12.6 M / 5.25 M / 3.15 M | Baked into `unostate2.boc` via `build_zerostate_state_cell(GenesisDistribution)`; **independent of TOS** — no bridge between wc=2 and wc=0/wc=1 (privacy-preservation requirement, uno-workchain.md §1.5) |

### TOS (shared, wc=0 + wc=1)

TOS is the single native token across both the TVM workchain (wc=0) and the EVM workchain (wc=1). At genesis:

- **wc=0 TVM**: main wallet on masterchain absorbs the residual supply after subtracting `allocated-balance` (running total of stage allocations + system contracts):
  ```fif
  TM$200000000 allocated-balance - // balance = target - already-allocated
  register_smc                     // adds this to allocated-balance
  ```
  To change the target, edit the `TM$<N>` literal on `gen-zerostate.fif` line 94.

- **wc=1 EVM**: starts empty at genesis (`mkemptyShardState`). For dev/test convenience, the runtime `hydrate_global_state_if_empty` seeds 10 Hardhat/Anvil EOAs with 10,000 TOS each (100 K total — see `evm/core/init.cpp::kSeedAmountTos`). **This is NOT genesis supply** — it is a dev convenience that materialises balances "out of thin air" on first boot. For mainnet, gate this off (set `kSeedAmountTos` to 0 or guard with a `--dev` flag) so wc=1 starts truly empty and is funded entirely via cross-WC routing.

#### Cross-workchain TOS routing (TODO — separate epic)

For TOS to actually flow between wc=0 and wc=1, the network needs a deterministic mechanism that:
- Translates wc=0 → wc=1 internal messages into EVM account `balance += value × 10⁹` (nano-tomi → wei conversion);
- Lets wc=1 EVM contracts call a precompile (e.g., `0x0...0100`) that burns wei and emits a wc=0 outbound message;
- Rejects sub-nano-tomi precision (any wei value not a multiple of 10⁹) at the precompile boundary.

The existing `evm/core/bridge.{cpp,h}` is a placeholder scaffold predating this design and is **not** the production routing layer. See `doc/cross-workchain-tos-routing-design.md` (TODO) for the full design.

Until cross-WC routing is wired, mainnet wc=1 will only have whatever balances are present from the dev seed (or zero in production builds where the seed is gated off).

### UNO (privacy workchain, wc=2)

UNO uses a Zcash-style shielded commitment model — supply exists as note commitments in the initial commitment tree. **The 21 M cap matches Bitcoin / Zcash** — UNO is positioned as the privacy-coin peer of ZEC/XMR and inherits the "digital scarcity" narrative (uno-workchain.md Decision #36). The supply is constexpr-pinned at three sites that **must stay in sync**:

- C++: `uno/core/genesis.h` (`kGenesisTotalSupplyNano`, `kGenesisAirdropNano`, `kGenesisTreasuryNano`, `kGenesisTeamNano`)
- Rust: `tosctl/uno/src/genesis_build.rs` (`GENESIS_TOTAL_SUPPLY_NANO`, `GENESIS_AIRDROP_NANO`, `GENESIS_TREASURY_NANO`, `GENESIS_TEAM_NANO`)
- Golden fixture: `uno/test/golden/genesis-distribution-v1.json` (regenerate via `UNO_GENESIS_REGEN=1 cargo test --release --test genesis_build_golden -p tosctl-uno`)

The 60 / 25 / 15 split lands on clean integer boundaries (12.6 M / 5.25 M / 3.15 M). Changing the total forces a `scheme_id` bump on the UNO side because the zerostate cm-set root is consensus-binding.

**Wiring status:** `add-uno-workchain` Fift word is in `Workchain.fif` and `gen-zerostate.fif` registers wc=2 with an empty initial `unostate2.boc`. The distribution-building pipeline (`GenesisDistributionInputs{airdrop, treasury, team}` → `build_zerostate_state_cell` → `unostate2.boc`) is not yet wired into the Fift script — mainnet launch requires either a `create-uno-state` standalone tool or an extension to `create-state` that consumes `zerostate-genesis-notes.json`. Until that tool exists, wc=2 boots with an empty commitment tree (no UNO in circulation).

## Related Docs

- [ConfigParam.md](ConfigParam.md) — Complete parameter reference
- [GlobalVersions.md](GlobalVersions.md) — ConfigParam 8 (version/capabilities)
- [Validator-Local.md](Validator-Local.md) — Local testnet setup (generates zero state automatically)
- [block.tlb](../crypto/block/block.tlb) — TL-B schema for all config types
