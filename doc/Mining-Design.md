# TOS Network — Mining Design (Three-Coin Specification)

## Status

**Design locked. Implementation pending.**

Implementation tasks tracked separately:
- Task #11 — TOS PoW Giver (wc=0 TVM)
- Task #10 — eTOS PoW Giver (wc=1 EVM)
- Task #12 — UNO MineUno AIR extension (wc=2 STARK)

## Three-Coin Narrative

The TOS network ships three economically independent native tokens, each
with its own mining mechanism deliberately mapped to a different
established cryptocurrency archetype:

| Coin | Maps to | Hash family | Mining hardware | Distribution speed |
|---|---|---|---|---|
| **TOS** | TON | SHA-256 | GPU / ASIC | ~1.9 years (fast) |
| **eTOS** | Ethereum (pre-Merge) | keccak-256 | GPU | ~1.9 years (fast) |
| **UNO** | Bitcoin (privacy variant) | Poseidon2 | CPU only | ~30 years (slow, halving) |

This gives each chain a familiar miner mental model + matching hardware
ecosystem, while avoiding a single point of mining-economy failure.

---

## TOS Mining (wc=0 TVM)

### Mechanism

**PoW Giver smart contract**, inherited verbatim from TON. Code at
`crypto/smartcont/pow-testgiver-code.fc` (FunC). Instantiated via
`crypto/smartcont/new-pow-testgiver.fif` (Fift).

### Parameters

| Parameter | Value |
|---|---|
| Total supply | 100,000,000 TOS |
| Number of Givers | 10 |
| Per-Giver supply | 10,000,000 TOS |
| Hash algorithm | SHA-256 (TON-inherited) |
| Reward per solve | **10 TOS** |
| Target solve interval (per Giver) | **60 seconds** |
| Difficulty min log2 (`min_cpl`) | 24 |
| Difficulty max log2 (`max_cpl`) | 42 |
| Difficulty adjustment | Auto (factor ∈ [7/8, 9/8] per solve, TON formula) |
| Halving | None (flat distribution) |

### Distribution math

```
solves per Giver  = 10,000,000 ÷ 10           = 1,000,000 solves
time per Giver    = 1,000,000 × 60s           = 60,000,000 sec
                                              = 694 days
                                              ≈ 1.9 years
total network time (10 Givers in parallel)    ≈ 1.9 years
network throughput                            = 10 × (10 TOS / 60s)
                                              = 100 TOS / minute
                                              = 144,000 TOS / day
```

### Mining workflow

1. Miner runs `pow-miner` (TON-inherited C++ client at `crypto/util/pow-miner-*.cpp`)
2. Client polls Giver contract for `(seed, target_complexity)`
3. Multi-thread SHA-256 search for `nonce` such that `sha256(msg(nonce)) < target_complexity`
4. On success: client constructs `mine` external message, submits to wc=0
5. Giver contract verifies PoW + sends 10 TOS to miner's address
6. Repeat (with new seed)

### Genesis wiring

`crypto/smartcont/gen-zerostate.fif` modifications (Task #11):
- Reduce `TM$100000000 allocated-balance -` (line 94) to leave 100M for
  Giver pool instead of main wallet
- Instantiate 10 PoW Givers via `new-pow-testgiver.fif` pattern, each
  pre-funded with 10M TOS

### Miner ecosystem

Inherited from TON's mining tooling. Binary clients available; mining
pools can be operated identically to TON.

---

## eTOS Mining (wc=1 EVM)

### Mechanism

**PoW Giver Solidity contract** (new), deployed at genesis to wc=1.
Mirrors TON's `pow-testgiver-code.fc` logic but for the EVM execution
environment.

### Parameters

| Parameter | Value |
|---|---|
| Total supply | 100,000,000 eTOS |
| Number of Givers | 10 |
| Per-Giver supply | 10,000,000 eTOS |
| Hash algorithm | keccak-256 (ETH ecosystem) |
| Reward per solve | **2 eTOS** |
| Target solve interval (per Giver) | **12 seconds** (= ETH PoW pace) |
| Difficulty adjustment | Auto (factor ∈ [7/8, 9/8] per solve) |
| Halving | None (flat distribution) |
| ASIC resistance | None (keccak256 is ASIC-friendly; matches ETH) |

### Distribution math

```
solves per Giver  = 10,000,000 ÷ 2            = 5,000,000 solves
time per Giver    = 5,000,000 × 12s           = 60,000,000 sec
                                              = 694 days
                                              ≈ 1.9 years
total network time (10 Givers in parallel)    ≈ 1.9 years
network throughput                            = 10 × (2 eTOS / 12s)
                                              = 100 eTOS / minute
                                              = 144,000 eTOS / day
```

(Throughput identical to TOS by design — different reward × delta
combinations balance out.)

### Mining workflow

1. Miner runs ethminer / T-Rex / lolMiner (any standard ETH PoW miner)
2. Configure stratum pool to point at TOS RPC
3. Miner pool sends jobs based on `eTOSPoWGiver.sol`'s current `seed` and `target`
4. Worker GPUs run keccak-256 search
5. On success: send `mine(nonce, recipient, ...)` EVM transaction
6. Contract verifies PoW + transfers 2 eTOS to `recipient`

### Genesis wiring

EVM zerostate via `evm-zerostate-from-alloc` Fift word (already exists in
`crypto/block/create-state.cpp`). Provides Hive-style allocation
specifying:
- 10 Giver contract addresses (deterministic from genesis seed)
- Each Giver's deployed bytecode (compiled `eTOSPoWGiver.sol`)
- Each Giver's storage initial values (seed, target, etc.)
- Each Giver's balance (10M eTOS)

### Solidity contract sketch

```solidity
// EToSPoWGiver.sol (Task #10)
contract EToSPoWGiver {
    bytes16  public seed;
    uint256  public target;        // 256-bit difficulty
    uint256  public lastSuccess;
    uint256  public targetDelta;   // = 12s
    uint256  public reward;        // = 2e18 wei
    uint8    public minCpl;        // = 30
    uint8    public maxCpl;        // = 64

    event Mined(address indexed whom, uint256 nonce);

    function mine(
        uint256 nonce,
        address whom,
        uint32  expire,
        bytes16 rseed,
        bytes32 rdata1,
        bytes32 rdata2  // anti-replay pair
    ) external {
        require(block.timestamp < expire, "expired");
        require(rseed == seed, "seed mismatch");
        require(rdata1 == rdata2, "rdata mismatch");
        bytes32 h = keccak256(abi.encode(
            uint32(0x706f7754), nonce, whom, expire, rseed, rdata1
        ));
        require(uint256(h) < target, "PoW not solved");

        _adjustDifficulty();
        seed = bytes16(blockhash(block.number - 1));
        lastSuccess = block.timestamp;

        emit Mined(whom, nonce);
        (bool ok,) = whom.call{value: reward}("");
        require(ok, "transfer failed");
    }

    function _adjustDifficulty() internal { /* TON formula */ }
}
```

### Miner ecosystem

Reuses Ethereum mining infrastructure: ethminer, T-Rex, lolMiner,
Phoenix Miner. Pool software (NiceHash, Ethermine fork) can be adapted
with minor stratum-protocol tweaks.

---

## UNO Mining (wc=2 STARK / Privacy)

### Mechanism

**AIR extension** — adds a new transaction type `MineUno` to the Plonky3
STARK circuit alongside the existing `Transfer`. Mining is performed
inside the cryptographic protocol itself, not via smart contract.

### Parameters

| Parameter | Value |
|---|---|
| Total supply | **21,000,000 UNO** (= Bitcoin cap) |
| Distribution model | Single global mining pool (no Giver split) |
| Hash algorithm | Poseidon2 over Goldilocks (PQ-native) |
| Reward per solve (initial era) | **50 UNO** (= Bitcoin initial reward) |
| Target solve interval | **600 seconds (10 minutes)** (= Bitcoin block time) |
| Halving period | **210,000 solves** (= Bitcoin halving period, ~4 years) |
| Distribution category split | None (no airdrop/treasury/team — pure mining) |
| Mining hardware | CPU only (Goldilocks Poseidon2 not ASIC/GPU friendly) |
| ASIC resistance | Native (small-field arithmetic resists batching) |
| Pre-mine | **0%** |

**This is a 1:1 Bitcoin clone in distribution mathematics**, with the
sole difference being the hash function (Poseidon2 vs SHA-256) and
hardware target (CPU vs ASIC).

### Distribution math (Bitcoin halving formula)

```
era 0 (years 0–4)        : 50 UNO/solve × 210K solves = 10.5M UNO
era 1 (years 4–8)        : 25 UNO/solve × 210K solves =  5.25M
era 2 (years 8–12)       : 12.5                       = 2.625M
era 3 (years 12–16)      : 6.25                       = 1.3125M
...
total = Σ (50 / 2^k) × 210K  for k=0..∞
      = 50 × 210K × 2
      = 21,000,000 UNO  ✓ (matches Bitcoin's geometric sum)

Cumulative supply at year N (approximate):
  year 4:   10.5M  (50%)
  year 8:   15.75M (75%)
  year 12:  18.375M (87.5%)
  year 16:  19.6875M (93.75%)
  year 20:  20.34M (96.875%)
  year 24:  20.67M (98.4%)
  year 28:  20.84M (99.2%)
  year 32:  20.92M (99.6%)
  year 64:  20.999M (99.99%)
  year ∞:   21M (cap)
```

### Why Bitcoin-clone parameters

1. **Narrative alignment**: "UNO is the PQ-native Bitcoin" — instantly
   recognizable to anyone familiar with Bitcoin economics.
2. **Tested distribution curve**: Bitcoin's halving math is empirically
   validated over 16 years; we don't need to invent new economics.
3. **Long tail = scarcity**: 30+ year distribution creates "digital gold"
   psychology (early miners benefit; long-term holders win).
4. **Proof time absorbed**: With 600s solve interval and ~30-60s STARK
   prove time, the proof overhead is only 5-10% of the cycle —
   miners' work isn't wasted by race conditions.

### Mining workflow

```
Phase 0 — Setup (one-time per miner):
  $ tosctl uno keygen --name alice
  → produces alice.{spend.priv, ivk, pk_mlkem.priv, address.json}

Phase 1 — Mining loop:
  1. Query wc=2 chain state: (mine_epoch, mine_target, mine_remaining)
  2. Compute recipient_cm from your address + current epoch reward
  3. CPU multi-thread search:
       for nonce in 0..∞:
         h = Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ recipient_cm)
         if h < target: WIN
  4. On win: invoke Plonky3 prover (~30-60s) to generate STARK proof:
       proves: PoW + commitment well-form + halving + conservation
  5. Submit MineUnoTx (proof + public inputs) to wc=2

Phase 2 — Block production (TOS validators handle):
  1. Validators verify STARK proof (millisecond fast-verify)
  2. Check: remaining_pre matches current chain state (race resolution)
  3. Include in next wc=2 block (TOS Simplex 400ms cadence)
  4. State updates: commitment_tree.append, mine_remaining -= reward,
     epoch/target may advance per halving schedule

Phase 3 — Spend (anytime later):
  1. Miner's wallet detects own note via ivk scan of commitment tree
  2. Spendable as any UNO note via Transfer tx (local prove)
```

### AIR constraints (proven in MineUno tx)

The MineUno STARK proof must enforce all of:

1. **PoW**: `Poseidon2("uno-mine-v1" ‖ epoch ‖ nonce ‖ output_cm) < target(epoch)`
2. **Commitment well-form**: `output_cm = Poseidon2_commit(d, pk_d, ivk_commitment, value, rseed)` (matches recipient address)
3. **Halving table**: `value` matches the deterministic schedule for `epoch` (look-up table baked into AIR)
4. **Conservation**: `remaining_pre - value = remaining_post`
5. **Cap**: `remaining_post ≥ 0` (no minting beyond 21M)
6. **Address well-form**: recipient address fields (d/pk_d/ivk_commitment/pk_mlkem) are valid sizes

Full constraint specification (mathematical formulations, edge cases, and
Phase 2 implementation plan): **[doc/uno-mine-air-constraints.md](uno-mine-air-constraints.md)**

Witness:
- Private: `nonce`, `recipient address (1259 B)`, `rseed (32 B)`
- Public: `epoch`, `target`, `value`, `output_cm`, `remaining_pre`, `remaining_post`

Proof size: ~200 KB (Plonky3 + FRI).
Prove time: ~30-60s on modern CPU (estimated; benchmarked during impl).
Verify time: milliseconds.

### Race protection

If multiple miners win in the same epoch, only the first to commit on-
chain succeeds. Later miners' tx fails because their `remaining_pre`
input no longer matches chain state.

### Genesis wiring

UNO zerostate (Task #12 + ongoing UNO genesis wiring):
```
mine_remaining   = 21,000,000 × 10⁹ nano-UNO  (= 2.1e16)
mine_epoch       = 0
mine_target      = (initial difficulty TBD via simulation)
halving_table    = [50, 25, 12.5, 6.25, ...] UNO per era
era_size         = 210,000 solves
```

### Miner ecosystem

New custom client (`tosctl uno mine`) — there is no existing CPU-based
Poseidon2 mining ecosystem to inherit. The client is part of the tosctl
deliverable (Task #12). Reference design: Monero's xmrig (CPU-mining
client architecture), but with Poseidon2 substitution.

---

## Implementation Roadmap

### Phase A: TOS PoW Giver (Task #11) — ~3-5 days

1. Modify `gen-zerostate.fif` line 94 area to deploy 10 Givers
   (10M each, 10 TOS reward, 60s delta) instead of monolithic main wallet
2. Verify TON-inherited `pow-testgiver-code.fc` works without changes
3. Add documentation pointing miners at the existing TON pow-miner client
4. Integration test on local testnet

### Phase B: eTOS PoW Giver (Task #10) — ~1-2 weeks

1. Write `EToSPoWGiver.sol` (mirror TON contract logic in Solidity)
2. Compile + deploy 10 instances at genesis via `evm-zerostate-from-alloc`
3. Write reference miner client (or document existing ethminer
   configuration)
4. Unit tests: PoW verification, difficulty adjustment, anti-replay
5. Integration test on local testnet

### Phase C: UNO MineUno AIR (Task #12) — ~4-6 weeks

1. Add MineUno tx kind to AIR (~2-3 weeks)
2. Witness/prover integration (~1 week)
3. Verifier + chain-state checks (~3 days)
4. `tosctl uno mine` CPU-multi-thread client (~1 week)
5. Zerostate wiring (mine_remaining init, halving table) (~2 days)
6. End-to-end testnet test (~1 week)

### Total elapsed time

Phases can run in parallel:
- A + B parallel = max(3-5d, 1-2w) ≈ **2 weeks**
- C alone = **4-6 weeks**
- All three deliverable in **~6 weeks** with parallel execution

## Pre-Mine Policy

**0% team / foundation pre-mine across all three coins.** Public
positioning: "TOS network has zero pre-mine; all coins must be mined."

Sole exception: a **negligible system bootstrap reserve** on TOS for
protocol-required smart contracts (elector, config, stage wallets).
These are functional necessities, not allocations to humans/teams:

| TOS system reserve | Purpose | Amount |
|---|---|---|
| Elector contract | Validator election | 500 TOS |
| Config contract | Governance container | ~0 (symbolic) |
| Stage 1/2/3 wallets | Bootstrap operational accounts | ~2,000 TOS |
| Main wallet residue | Storage rent dust | < 100 TOS |
| **Total** | | **~3,000 TOS = 0.003 %** of 100M cap |

eTOS and UNO have **zero** system reserve — EVM contract deployments
don't pre-fund accounts; UNO's mine pool starts at full 21M.

For comparison: Zcash had 20% Founders' Reward; Litecoin had ~0%
pre-mine; Monero had ~0.6%; Bitcoin had 0%. TOS network at 0.003%
system reserve is essentially Bitcoin-equivalent.

## Initial Difficulty Calibration

These are the values to write into the genesis configuration. They
assume a small initial network at launch (5-30 miners). Auto-
retargeting will converge to actual hashrate within minutes (TOS/eTOS)
or ~1 hour (UNO).

### TOS (SHA-256, target_delta = 60s)

Hardware baseline:
- Modern CPU: ~50 MH/s
- Mid-range GPU (RTX 3060): ~5 GH/s
- ASIC (rare for SHA-256 small hashrate): up to 10 TH/s

Assume 5-10 GPU miners at launch (~25 GH/s total).

```
hashes per solve = 25 GH/s × 60s = 1.5 × 10¹²
log₂(1.5e12)     ≈ 40.4
init_cpl         = 40
```

Genesis configuration (parameters to `new-pow-testgiver.fif`):

| Parameter | Value | Justification |
|---|---|---|
| `min_cpl` | **24** | Lower bound (2²⁴ hashes ≈ < 1s on one CPU; prevents dust attack) |
| `init_cpl` | **40** | Initial complexity (2⁴⁰ ≈ 1.1T hashes; 5-10 GPU miners → ~60s solves) |
| `max_cpl` | **64** | Upper bound (2⁶⁴ ≈ 18 EH; allows ASIC-scale future) |

Convergence: 5-10 solves (~5-10 minutes after launch).

### eTOS (keccak-256, target_delta = 12s)

Hardware baseline:
- CPU: ~5-10 MH/s keccak
- Mid GPU: ~30 MH/s keccak per worker
- High-end GPU (RTX 4090): ~80 MH/s
- ETH PoW ASIC (Innosilicon A11): ~1.5 GH/s

Assume 20-30 ETH miners migrating at launch (~1.5 GH/s total).

```
hashes per solve = 1.5 GH/s × 12s = 1.8 × 10¹⁰
log₂(1.8e10)     ≈ 34
init_target      = 2^(256-34) = 2^222
```

Genesis configuration (Solidity constructor):

| Parameter | Value |
|---|---|
| `target` | `type(uint256).max >> 34` (= 2²²² shifted) |
| `minCpl` | 28 |
| `maxCpl` | 64 |
| `targetDelta` | 12 (seconds) |
| `reward` | 2 ether (= 2 × 10¹⁸ wei) |

Convergence: ~10 solves (~120 seconds after launch).

### UNO (Poseidon2 over Goldilocks, target_delta = 600s)

Hardware baseline (Plonky3 reference implementation):
- Single-thread Poseidon2: ~1 M ops/sec
- 32-thread Threadripper / Ryzen 9: ~25 M ops/sec
- 64-core EPYC: ~50 M ops/sec
- **No GPU advantage** (Goldilocks small-field arithmetic resists batching)
- **No ASIC** (none exist; small-field hardware impractical)

Assume 5-10 CPU miners at launch (each 32-thread Ryzen ~20 M/s → ~150 M/s total).

```
hashes per solve = 150 M/s × 600s = 9 × 10¹⁰
log₂(9e10)       ≈ 36.4
init_target      = 2^(256 - 37) = 2^219
```

Genesis configuration (UNO zerostate):

| Constant | Value | Notes |
|---|---|---|
| `kInitMineTarget` | `2²¹⁹` | Initial target (CPU at ~150 M/s → ~600s/solve) |
| `kHalvingEra` | 210,000 solves | Bitcoin-clone (≈ 4 years per era) |
| `kInitReward` | 50 × 10⁹ nano-UNO (50 UNO) | Bitcoin-clone initial subsidy |

**Important**: UNO retargeting should be MORE aggressive than TOS/eTOS
because CPU network hashrate is more volatile (a single EPYC server
joining can double network rate):

```
TOS/eTOS retargeting factor ∈ [7/8, 9/8]   ← TON / TOS standard
UNO   retargeting factor ∈ [3/4, 4/3]      ← faster convergence
```

Convergence: ~5 solves (~50 min) after launch. First hour is volatile
but acceptable.

### Difficulty calibration risk + mitigation

If initial values are too low: first miners sweep multiple solves
before retargeting catches up (TON's actual launch experience —
industrial pools dominated first hour). Mitigation: difficulty should
be **slightly conservative** (i.e., harder than estimated).

If initial values are too high: nothing mines for hours; community
panic. Mitigation: launch announcement explicitly notes "first 1 hour
is calibration window; difficulty will auto-adjust."

The values above lean **conservative** (slightly harder than baseline
estimate) to favor robustness over speed.

## Miner Binary Distribution

CI-driven via GitHub Releases. Three workflows in
`.github/workflows/`:

### `release-tos-pow-miner.yml`

Builds TON-inherited `pow-miner` (`crypto/util/pow-miner-*.cpp`).

| Platform | Built artifact |
|---|---|
| linux-x86-64 | `tos-pow-miner-linux-x64-{version}.tar.gz` |
| linux-arm64 | `tos-pow-miner-linux-arm64-{version}.tar.gz` |
| macos-x86-64 | `tos-pow-miner-macos-x64-{version}.tar.gz` |
| macos-arm64 | `tos-pow-miner-macos-arm64-{version}.tar.gz` |
| windows-x86-64 | `tos-pow-miner-windows-x64-{version}.zip` |

### `release-tosctl.yml`

Builds full `tosctl` Rust binary including `tosctl uno mine` subcommand
(Task #12 deliverable). Same platform matrix.

### `release-etos-config.yml`

Does NOT build a new miner (we reuse ethminer / T-Rex / lolMiner).
Packages stratum config templates + adapter scripts:

```
etos-miner-config-{version}/
├── README.md                  # quick start
├── ethminer-stratum.conf      # config for ethminer
├── trex-stratum.conf          # config for T-Rex
├── stratum-adapter.py         # bridges TOS RPC ↔ standard stratum
└── etos-pool-example.toml     # template for pool operators
```

### Release process

1. Tag `v0.1.0-rc1` → CI builds for all platforms
2. Each binary signed with cosign (sigstore)
3. SBOM (Software Bill of Materials) attached
4. Changelog auto-generated from git log
5. Release page links to:
   - Mining-Design.md (this doc) for parameters
   - Quick-start guide for each coin
   - Discord / community for support

### Reproducible builds

Where feasible:
- Pin Rust toolchain version
- Pin C++ compiler + flags
- Pin third-party dep versions
- Document exact build commands so independent verifiers can reproduce
  the published binaries from source

## Open Questions (post-design)

1. **Empirical difficulty validation**: theoretical calibration above
   should be validated by simulating launch on a private testnet
   before mainnet. Plan: 1-week testnet with realistic miner count
   to verify retargeting converges as expected.

2. **Mining pool software**: TOS and eTOS will spawn pools naturally
   (Bitcoin/ETH ecosystem already supports this). UNO might not get
   pools quickly because it's CPU-only and pool overhead may outweigh
   solo mining benefits — fine, more democratic.

3. **Re-tuning post-launch**: difficulty auto-adjusts, but reward
   amounts and halving schedules are baked into AIR / contracts.
   Modifying them requires hard-fork (TVM/EVM) or scheme_id bump (UNO).
   Treat as consensus-critical; no governance pathway in v1.

4. **eTOS binary signing for ETH ecosystem trust**: the major ETH
   miner clients we recommend (ethminer, T-Rex) should be installed
   via their own official sources for security. Our packaged config
   templates explicitly point users to upstream miner downloads.

## Related Docs

- [Zerostate.md §Initial Token Supply](Zerostate.md#initial-token-supply-per-workchain-issuance) — supply caps confirmed in genesis layer
- [Validator-Local.md](Validator-Local.md) — local testnet runbook (will need post-implementation update)
- [uno-workchain.md](uno-workchain.md) — UNO design and §10 economics
- TON's `crypto/smartcont/pow-testgiver-code.fc` — TOS Giver code (inherited verbatim)
- Bitcoin whitepaper — UNO's distribution mathematics reference
