# Uno Proof Aggregation — Design (v2 research path; v1 uses per-Tx direct)

> **⚠️ DECISION REVERSAL (April 2026).** This document was originally
> written to promote **block-level recursive aggregation** from v2+
> to v1 launch. After A4 measurements and a strategic review of
> validator-hardware / UX tradeoffs, UNO v1 has been re-scoped to
> **per-Tx direct proofs with `BLOCK_TX_CAP = 4`** — no consensus-
> level aggregation at launch.
>
> Sections §0–§4 below describe the **v2 research path** (monolithic
> AIR aggregation) that phases A1 through A6 have built toward.
> That work is NOT deleted; it stays as v2+ research infrastructure
> to be revived when upstream PCS primitives (WHIR / BaseFold)
> mature and specialized prover hardware becomes mainstream.
>
> §-1 below states the v1 launch decision and the rationale for the
> pivot. Read §-1 for the current shipping plan; read §0–§4 for the
> aggregation research history.

## §-1. v1 launch decision (April 2026)

**UNO v1 ships without block-level proof aggregation.** Each on-chain
Transfer carries its own Plonky3 per-Tx STARK proof (the "Option B
shape" we had before A3-5c aggregation landed). `BLOCK_TX_CAP = 4`.

### Why we flipped

A4 benchmarks gave concrete numbers for block-level prover time:

| shape                         | prover time (192-core) | extrapolated to 16-core |
|-------------------------------|-----------------------:|------------------------:|
| 1 Tx = 52 bundles             |                 ~2 s   |              ~25 s      |
| **4 Txs = 208 bundles (§4.1)** |                ~65 s   |             **~13 min** |
| N=30 extrapolation            |               ~4 min   |             **~48 min** |

Block-level aggregation would have forced UNO validators to run
**~13 minutes of 16-core CPU per 1-second block** at steady state —
equivalent to ~780× concurrent prove tasks always in flight. That's
only tractable on **64+ core data-center hardware**, which pushes UNO
into "professional-staking only" territory in 2026.

Strategic framing:
1. **2026 PQ threat model is forward-looking, not urgent.** Shor
   won't materially threaten ECC before 2030+. Paying a heavy
   hardware tax today for 4-year-ahead threat coverage trades the
   wrong thing.
2. **Validator participation is the actual near-term need.** 4-core
   home hardware with consumer broadband is what gives UNO real
   decentralization in 2026.
3. **Zcash shielded ~0.9 TPS observed; Monero ~0.3 TPS.** UNO does
   not need 30 TPS to be competitive. 4 TPS shielded already beats
   observed Zcash 10×.

### v1 architecture

```
Wallet (per-Tx prove, ~3-10 s, unchanged)
    │ emits Transfer TLV with zk_proof:^Cell attached (Option-B-era shape)
    ▼
Mempool / collator (unchanged §4.3 admission)
    │ for each accepted Transfer: full per-Tx STARK verify runs at admission
    ▼
Block (4 Tx × ~520 KB proof ≈ 2 MB typical / ~3.7 MB worst-case 4/4)
    │
    ▼
Validator (non-block-producing): batch-verify 4 per-Tx STARKs per block
    │ ~100 ms × 4 = ~400 ms of single-core CPU; parallel across cores
    ▼
Finality: complete in 1 s (Simplex consensus round) — no soft/hard split
```

### Quantitative UX contract

| Metric                       | v1 target           | Notes                          |
|------------------------------|---------------------|--------------------------------|
| Shielded TPS per wc=2 chain  | **4**               | Zcash Orchard theoretical = 3  |
| Send → receiver sees pending | **1-2 s**           | block cadence                  |
| Block finality               | **1 s**             | Simplex 2-round BFT            |
| Per-block bandwidth          | **2-4 MB** (16-32 Mbps) | consumer broadband          |
| Validator hardware           | **4 core / 16 GB**  | commodity PC                   |
| Archive growth               | ~172 GB/day         | pruned-mode validators do less |

### What gets deferred to v2

- **Block-level monolithic AIR aggregation** (the A3-5c path)
- **Soft-finality window K** (the §2.6 "proof-pending → finalized" model)
- **`AggregatedProofDelivery` message type**
- **`UnoBlockExtra.aggregated_proof` field** (wire-format gets the
  framing but no proof content at v1)
- **Witness broadcast / prover failover** roles

All of these come back in v2 **IF AND ONLY IF**:
1. **WHIR / BaseFold** (smaller PCS proofs) is production-ready in
   Plonky3 upstream; measurements show per-Tx proof size drops from
   ~520 KB to ~100 KB AND prover time halves. See
   `doc/uno-aggregation-metrics.md` for tracking.
2. A **specialized prover role** becomes economically reasonable for
   the UNO operator ecosystem (similar to Polygon zkEVM's prover
   service model).
3. TPS pressure justifies the complexity (current projections say
   4 TPS is plenty through 2028).

### Strategic positioning

> **UNO v1 (2026) = Ethereum 2030 PQ privacy roadmap, delivered four
> years early.**

Mapping UNO's choices onto Vitalik's April 2025 privacy roadmap
(9 items, `vitalik.eth.limo/general/2025/04/14/privacy.html`):

| Vitalik 2030 item                                       | UNO v1 alignment |
|---------------------------------------------------------|------------------|
| #1 Shielded balance default (Railgun-class)             | ✅ native        |
| #2 Stealth address per dApp (ERC-5564)                  | ✅ TOS compatible|
| #3 Self-to-self default private                         | ✅               |
| #4 FOCIL + EIP-7701 decentralized relay                 | ✅ compatible    |
| #5 TEE RPC → PIR migration                              | ⚠️ v2           |
| #6 Mixnet P2P routing                                   | ⚠️ v2           |
| #7 **Proof aggregation** (many private txs share proof) | ⚠️ **v2**       |
| #8 Cross-L1/L2 keystore wallets                         | ⚠️ v2           |
| #9 **Hash-based STARK + lattice** (PQ migration 2029-30)| ✅ **already**  |

**#9 is the key alignment.** Ethereum's stated 2029-2030 target is to
replace pairing-based SNARKs and BLS signatures with hash-based
STARKs and lattice signatures. UNO on Plonky3 FRI + Goldilocks +
Poseidon2 is exactly that stack, four years early. Item #7
(aggregation) is an optimization on that path; we defer it, not the
cryptographic foundation.

### v2 trigger conditions (tracked quarterly)

- [ ] Plonky3 upstream `MultilinearPcs` trait ships (currently
      github.com/Plonky3/Plonky3 PR #1523, in progress)
- [ ] WHIR or BaseFold production-ready in Plonky3 for `uni-stark` /
      `batch-stark` prover paths
- [ ] Measured per-Tx proof size drops below 150 KB at Option B
      soundness
- [ ] TPS demand exceeds 4 per wc=2 shardchain for sustained periods
- [ ] Prover-service ecosystem maturity (third-party operators)

When all 5 land, revive the A3-5c aggregation path as a v2 feature
with a soft-finality window (see §2.6 below for the precursor spec).

---

## 0. Executive summary (v2 research path)

> **This executive summary describes the v2 aggregation research
> path, NOT the v1 launch plan.** See §-1 above for the v1 decision.
> Content below is retained because A1 through A6 actually built this
> infrastructure; re-reviving it in v2 requires this design to be
> accurate.

§3.4 originally targeted a ~100 KB worst-case `zk_proof` field per
Transfer. After the K-air-col-share + K-air-col-step2 + FRI-Option-B
landings, we reached ~915 KB — 9× over target. Paths (i), (ii), (iii)
from `doc/uno-p2-path-research.md` cannot close that gap while holding
§0.2 (PQ-native), §1.5 (bridgeless), and §16 decisions #1, #2
(no trusted setup, STARK).

**First-principles analysis** (documented in the last planning round)
identified recursive proof aggregation as the only path that respects
all v1 invariants. §14 already lists "Proof aggregation" as a v2+ item;
this document **originally** promoted it to v1 — since reversed by §-1
above.

**What aggregation would buy (v2)**:
- On-chain block proof ≈ **~420 KB** (A4 measurement), vs ~2-15 MB
  per block for per-Tx direct. 5-30× bandwidth saving.
- Wallet-side prove cost **unchanged** (prove-per-Transfer is still
  client-side; no privacy loss).

**What it would cost (and why v1 defers)**:
- **Collator CPU**: ~4 min per block prover time at N=30, ~65 s at N=4
  (192-core). On 16-core validator hardware: 13 min to 48 min per
  block. This is the load-bearing reason v1 opted out.
- New subsystem: a `verifier-as-AIR` that re-proves the Plonky3
  Transfer-AIR verifier as a STARK circuit. ~800–1,500 LoC of Rust
  (already landed A1 through A6-2; stays as research code).
- §4.1 wire format: Transfer's `zk_proof: ^Cell` would be redefined
  as a witness commitment; a block-level `aggregated_proof` field
  would be added. A6-4a started this — **reverted for v1**.
- Soft-finality window (§2.6): introduces ~5 minute gap between
  block production and STARK-verified finality. Acceptable for v2
  if prover hardware / WHIR deliver, unacceptable for v1 launch.

---

## 1. Architecture

### 1.1 Two proof levels

```
┌────────────────────────────────────────────────────────────────┐
│  Wallet                                                         │
│    builds per-Transfer proof (same AIR as today, same FRI Opt-B)│
│    emits: Transfer TLV (with proof) → mempool                   │
└──────────────┬─────────────────────────────────────────────────┘
               │
               │  per-Tx proof ~520 KB (1/2) / ~915 KB (4/4)
               │  (only in the wallet → collator leg)
               ▼
┌────────────────────────────────────────────────────────────────┐
│  Collator (block producer on wc=2)                              │
│    1. drains mempool for the block                              │
│    2. for each Transfer: run full §4.3 verify (incl. Plonky3)   │
│    3. accepted Tx list T = [tx_1, …, tx_N]                      │
│    4. run aggregation prover over (tx_1.proof, …, tx_N.proof)   │
│       → emits one recursive proof π_block                       │
│    5. strip per-Tx proofs; commit block with π_block only       │
└──────────────┬─────────────────────────────────────────────────┘
               │
               │  block contents: Transfer_list (proof-less) + π_block
               │  block-level proof size: ~100 KB regardless of N
               │
               ▼
┌────────────────────────────────────────────────────────────────┐
│  Validator (all wc=2 validators)                                │
│    verify π_block against public-inputs vector                  │
│    (= committed Merkle root of per-Transfer public inputs)      │
│    one verify-call per block, not per Transfer                  │
└────────────────────────────────────────────────────────────────┘
```

### 1.2 What the aggregation proof attests

The block aggregator proves, as a STARK over a new "aggregator AIR",
the single top-level claim:

> For every `i ∈ [0, N)`, the i-th per-Transfer Plonky3 proof `π_i`
> verifies against the i-th per-Transfer public inputs `pi_i`, under
> the §2.1 Option B FRI configuration.

Formally: for each slot `i`, the aggregator AIR contains the circuit
implementing `verify_transfer_plonky3(pi_i, π_i) == true` as an AIR
claim. This is the **verifier-as-AIR** — the Plonky3 STARK verifier's
algorithm expressed as a set of polynomial identities.

The aggregator AIR does NOT verify:
- Signatures (those are still verified off-AIR by the collator, step 3)
- Nullifier set membership (ditto)
- Cheap syntax checks (ditto)
- Anchor window membership (ditto)

**Rationale**: the per-Transfer AIR already binds all consensus
semantics into its public inputs. The aggregator's job is only to prove
"these N proofs all verified" — so every Transfer in the block is
correctly proven, but the signatures / anchor / nullifier checks remain
an off-AIR responsibility of the collator.

This keeps the aggregator AIR small (only the Plonky3 verifier
circuit) and the recursive proof size low (~100 KB).

### 1.3 Aggregator AIR complexity estimate

The Plonky3 uni-stark verifier does:
1. Reconstruct the challenger state (Poseidon2 hashes over the
   commitments and public inputs).
2. Check the opening proof at the FRI challenge points:
   a. FRI folding (`log_blowup` rounds).
   b. Low-degree check at each query.
3. Verify the quotient polynomial constraint at the out-of-domain point.

In column-count terms, expressing this as an AIR claim costs roughly:
- **Hash-chain columns**: ~50–80 cols (a few Poseidon2 instances for
  the challenger reconstruction).
- **FRI folding**: 52 queries × `log_blowup=3` × log₂(trace_domain=64) = 52 × 3 × 9 =
  ~1,404 column-positions, but amortized row-wise they live in ~100
  dedicated cols.
- **Quotient constraint check**: degree-3 polynomial evaluation at a
  single point: ~30 cols.
- **Per-slot ancillary**: ~20 cols per aggregated Transfer (to carry
  the per-Tx PI into the verifier state).

Total estimated aggregator AIR width: **~200 + 20·N** columns,
where N is the number of Transfers aggregated per block.

At N = 30 (targeted block-production throughput): 200 + 600 = 800 cols.
Under FRI Option B and the calibrated C1 (~325 B/col), that gives
**~135 KB proof** for the aggregator — close to the §3.4 100 KB
target. Further optimization (e.g. hash-chain with shared Poseidon2
row-loop à la K-air-col-share) can bring it under 100 KB.

### 1.4 Claim over the aggregated state

Let `PI_block` be the per-block aggregator public inputs:

```
PI_block = (
    block_chain_id : u32,
    block_seqno    : u64,
    merkle_root_of_tx_public_inputs : bits256,   // root of a Merkle commitment
                                                  // over the N per-Tx PI vectors
    n_transfers    : u16,                        // ≤ BLOCK_TX_CAP (see §2.3)
    anchor_seqno   : u64                         // common anchor window lower bound
)
```

The aggregator AIR proves:

> ∃ `(pi_1, π_1, pi_2, π_2, …, pi_N, π_N)` such that
> `merkle_root(hash(pi_1) ‖ … ‖ hash(pi_N)) == PI_block.merkle_root_of_tx_public_inputs`
> AND for each i, `verify(pi_i, π_i) == Ok`.

The per-Transfer PI vectors themselves remain in the block's `Transfer`
fields (fee, anchor, rk, nf, cm, epk, filter_tag) — they're consumed
by wallets for scanning + by validators for off-AIR signature / nullifier
/ anchor checks. The aggregator's PI only binds the hash-commitment to
them.

---

## 2. Protocol changes

### 2.1 §4.1 wire format delta

**Current `Transfer` struct (Option B era)**:

```
Transfer :=
  version, scheme_id, chain_id, anchor, expiry_block, fee
  spend_count, output_count
  spends: Array<SpendDescription>
  outputs: Array<OutputDescription>
  zk_proof: ^Cell           // Plonky3 STARK proof, ~520 KB typical
```

**v1 `Transfer` struct (per §-1)** — Option-B-era shape retained:

```
Transfer :=
  version (= 1), scheme_id (= 0x01)
  chain_id, anchor, expiry_block, fee
  spend_count, output_count
  spends: Array<SpendDescription>
  outputs: Array<OutputDescription>
  zk_proof: ^Cell           // Plonky3 STARK proof chunk chain, ~520 KB typical
```

A6-4a had bumped `version = 2`, removed `zk_proof`, and added a 32 B
`witness_commitment` field. That change is **reverted for v1**; v1
ships the Option-B shape above with the per-Tx proof on-chain.

**v2 aggregation-era `Transfer` struct** (frozen research path):

```
Transfer :=
  version (= 2 at v2 launch), scheme_id (= 0x01)
  chain_id, anchor, expiry_block, fee
  spend_count, output_count
  spends: Array<SpendDescription>
  outputs: Array<OutputDescription>
  witness_commitment: bits256   // 32 B, BLAKE3 over postcard(proof) || PI
  // zk_proof field removed — proof aggregated at block level
```

**v2 block-level field** (frozen research path):

```
UnoBlockExtra :=
  aggregator_scheme_id : u8       = 0x01     // crypto-agility
  aggregator_version   : u8       = 1
  n_transfers          : u16
  tx_pi_merkle_root    : bits256              // matches PI_block.merkle_root_of_tx_public_inputs
  aggregated_proof     : ^Cell                // the recursive proof, ~420 KB measured
```

v2 wire format is already implemented in
`uno/plonky3-ffi/src/block_wire_format.rs` and exported via A6-1 FFI;
it stays as v2-research shipped-but-unused code.

### 2.2 Mempool / RPC contract

`uno_sendTransfer` still accepts a `Transfer` + its Plonky3 proof
bytes (to be admitted + verified by the collator at the mempool tier).
The on-wire RPC message carries the proof; this is the same bandwidth
cost as today.

**Mempool admission** (§4.3a): unchanged except the full Plonky3
verify (step 5 of §4.3, previously "deferred to compute phase") runs
earlier, during collator block-candidate assembly, so rejected
Transfers don't make it into the aggregator input list.

**Block assembly**: the collator:
1. Drains the mempool for up to `BLOCK_TX_CAP` Transfers (see §2.3).
2. For each: full §4.3 verify (steps 1–5 including Plonky3 verify).
3. Accepted list → feed into aggregator prover.
4. Emits block with Transfer list (proof-less) + `aggregated_proof`.

### 2.3 Block-level throughput envelope

```
v1 launch:  BLOCK_TX_CAP := 4     // per §-1 pivot
v2 target:  BLOCK_TX_CAP := 30    // restored when aggregation returns
```

**v1 rationale**: per §-1, no block-level aggregation; each Tx
carries its own ~520 KB per-Tx Plonky3 proof. `BLOCK_TX_CAP = 4`
gives 4 TPS shielded (10× observed Zcash, 2× theoretical Sapling)
with **~2-4 MB block size / ~16-32 Mbps validator bandwidth** —
comfortably within consumer broadband for 2026.

**v2 rationale**: aggregation collapses N-Tx's proofs into ONE block
proof (~420 KB by A4 measurement, independent of N). The ~30 cap
matched §1.4 success criterion #7 ("15–30 TPS sustained"); revisit
when v2 triggers (§-1) light up.

Scaling beyond `BLOCK_TX_CAP` per wc=2 chain uses **additional UNO
shardchains** (wc=2a, wc=2b, …) — TOS architecture supports this
natively. Not a v1 concern.

### 2.4 §4.3 compute-phase order update

**v1 (per §-1) — per-Tx proofs, no block-level aggregation**:

```
1.  Syntax checks
2.  Anchor window
3.  Nullifier uniqueness across block
4.  Per-Transfer signatures
5.  Per-Transfer Plonky3 verify (runs at EVERY validator, not just collator)
6.  Accept Transfer → add to block / apply state
(no step 7 — no aggregated_proof)
```

ALL validators (producing or not) run steps 1-6. Parallelism across
cores makes step 5 cheap: `BLOCK_TX_CAP = 4` × ~100 ms/verify = ~400 ms
single-core, sub-100 ms across 4+ cores. The §4.3a mempool pre-filter
(below) is unchanged.

**v2 (aggregation — frozen)** would have gone:

```
1-4. (unchanged)
5.  Per-Transfer Plonky3 verify (runs ONLY at collator tier for filtering)
6.  Accept Transfer → feed into aggregator
7.  NEW: block-level aggregated_proof verify (ONE verify per block)
```

Validators (non-block-producing) would skip step 5 entirely; they'd
only need step 7 to confirm "all Transfers in this block had valid
proofs". This was the v2 design — see historical §2.6 below for the
soft-finality window that would have been needed.

Collator CPU cost would be: +3–10 s per block for the aggregation
prove step.
At 1 s block cadence, aggregation runs in parallel with the next block's
mempool drain (pipelined); per-block wall-clock impact bounded by the
aggregator prove time.

### 2.5 §4.3a admission pre-filter

Unchanged from Option B. The full Plonky3 verify is deferred to the
collator (step 5 above), so admission still does the cheap checks only.

### 2.6 Block-proposal sequencing decision (prover-latency architecture — v2 spec; v1 skips)

> **v1 skips this section.** With per-Tx proofs (per §-1), there is no
> ~4-minute aggregation prover job; block finalization is a single
> ~1 s Simplex round and every committed block is fully STARK-verified
> at commit time. The soft-finality / delay-finalize machinery below
> was designed for the v2 aggregation path and is frozen as research
> spec; revive it when the v2 triggers in §-1 light up.

A4 measurements (`doc/uno-aggregation-metrics.md` §A4) gave real
numbers for block-level prover time:

| shape                 | prover time  | proof size |
|-----------------------|-------------:|-----------:|
| 4-Tx / 208 bundles    | ~65 s        | ~420 KB    |
| N=30 extrapolation    | ~4 min       | ~550-650 KB |

At the 1-second TOS block cadence this is **3-4 orders of magnitude
longer than the block cadence**, which raises a first-class design
question: **is the aggregated proof a HARD prerequisite for block
proposal, or can it be pipelined / delay-finalized?**

This section pins UNO's answer. Two options were considered:

**Option A — hard prerequisite (synchronous)**: collator MUST have a
valid aggregated proof before broadcasting the block candidate. Pros:
simplest consensus rule; every committed block has full crypto
validity attested by the time validators see it. Cons: block cadence
is bounded below by prover time → UNO wc=2 cannot produce a block
every 1 s; cadence drops to ~1 min at N=30. That's incompatible with
wc=2 sharing the mainchain tempo.

**Option B — pipelined / delay-finalize (asynchronous)**: collator
broadcasts a *proof-pending* block immediately; the aggregated proof
lands K blocks later and retroactively attests validity of the
pending-window blocks. Pros: matches the 1 s cadence; prover cost is
an amortized background job. Cons: a window of K blocks is
"soft-finalized" (signatures / anchors / nullifiers checked, but no
STARK cover yet); adds a new finality depth concept to the rule-set;
complicates rollback if the delayed proof fails.

**Decision**: **Option B at v1 launch.** Specifically:

1. **Soft-finality window**: the last K blocks on wc=2 are `PROOF_PENDING`
   until their aggregated proof lands. `K` defaults to `ceil(prover_time /
   block_cadence) + safety_margin` ≈ **300 blocks at 1 s cadence**
   (5 min worst-case at N=30; 2× safety). Pinned as a consensus
   parameter.

2. **Pending block contents**: include everything EXCEPT
   `UnoBlockExtra.aggregated_proof`. Instead they carry
   `UnoBlockExtra.proof_commitment: bits256` — a BLAKE3 hash over the
   block's `tx_pi_merkle_root` + expected-PI vector — so the prover
   CANNOT change the set of Transfers the proof attests to between
   soft-finality and hard-finality.

3. **Hard-finality**: a future block carries the aggregated proof for
   a prior height via a new message type `AggregatedProofDelivery`.
   That delivery cross-checks `proof_commitment` of the target block
   and promotes it from `PROOF_PENDING` → `FINALIZED`.

4. **Rollback rule**: if a pending block's proof fails to land within
   the `K`-block window OR if the delivered proof rejects STARK verify,
   the pending block and all its descendants are rolled back. This is
   already the TOS masterchain's failed-shardchain convention, reused.

5. **Wallet / user UX**: a receiver SHALL treat a UTXO as
   PROOF_PENDING until its parent block is FINALIZED. The masterchain
   shows block state ∈ {PROOF_PENDING, FINALIZED} via a new RPC
   field. Default wallet policy: treat only FINALIZED as spendable;
   treat PROOF_PENDING as "visible, cannot respend" (same UX as
   Ethereum's "12-block confirmation" pattern, at 1 s per block →
   ~5 min confirmation delay at worst).

**Consequence for the implementation plan**: A6-5 (validator wiring)
MUST treat `BlockProofVerifier::verify` as a delivery-time check for
a prior block, not a proposal-time check. This affects the
compute-phase order in §2.4 — the step 7 ("NEW: block-level
aggregated_proof verify") moves to `AggregatedProofDelivery` message
handling, not the block-body compute-phase. §4.3 and §2.4 text
will be revised when A6-5 lands.

**Out-of-scope for v1**: adaptive `K` based on load; commit-chain
merging (batching several pending blocks into one aggregated proof
delivery). Both are v2 optimizations.

---

## 3. Aggregator AIR specification

### 3.1 Public inputs

```
PI_block[0]  = block_chain_id (u32)
PI_block[1]  = block_seqno (u64, low 8 bytes)
PI_block[2]  = anchor_seqno (u64)
PI_block[3]  = n_transfers (u16)
PI_block[4]  = tx_pi_merkle_root[0]  // 4 limbs of 8 bytes each
PI_block[5]  = tx_pi_merkle_root[1]
PI_block[6]  = tx_pi_merkle_root[2]
PI_block[7]  = tx_pi_merkle_root[3]
```

Length: 8 field elements, 64 bytes.

### 3.2 Witness

```
AggregatorWitness := {
    per_tx: Vec<(PublicInputs, ProofBytes)>,   // length n_transfers
}
```

For the full PoC, the witness builder (in the collator) receives the
list of `(pi_i, π_i)` pairs and reconstructs the FRI verifier state
per slot.

### 3.3 Trace layout (rough sketch — refined in implementation)

```
Row 0:
  [AGGREGATOR_SCHEME_ID], [AGGREGATOR_VERSION], [N_TRANSFERS],
  [TX_PI_MERKLE_ROOT 0..3],   ← 7 PI slots
  [RUNNING_ROOT_SCRATCH 0..3] ← 4 cols for ongoing Merkle root rebuild
  [<per-Tx block of verifier-circuit rows>, cycled by selector]
```

For the detailed row layout — per-Tx verifier instance columns,
selector banks, Merkle root recomputation path — see the
accompanying implementation in `uno/plonky3-ffi/src/aggregator.rs`
(landed in subsequent PRs).

### 3.4 Soundness

The aggregator AIR uses the **same §2.1 Option B FRI pin**
`(log_blowup=3, num_queries=52, query_pow_bits=24)`, giving 180
conjectured / 102 proven bits of soundness. The composition of (per-Tx
soundness) ∧ (aggregator soundness) is still ≥ min of the two — both
are at 180 bits, so the aggregated chain is 180 bits.

**No trusted setup** — aggregator AIR inherits Plonky3's hash-based
FRI directly.

**Crypto-agility**: `aggregator_scheme_id = 0x01` is reserved in the
same way `scheme_id = 0x01` is for the per-Tx AIR. Future upgrades
(e.g. WHIR-based verifier-as-AIR when Plonky3's `p3-whir` matures) bump
this to `0x02`.

### 3.5 Anti-replay + block binding

The aggregator PI includes `block_chain_id` and `block_seqno`. The
per-Transfer PI already binds `chain_id`, `expiry_block`, `anchor`. The
aggregator AIR additionally asserts that every `pi_i.chain_id ==
PI_block.block_chain_id`, so an aggregated proof from block B cannot
be replayed on chain B'.

Cross-block replay: the `tx_pi_merkle_root` is over per-Tx PIs that
include `expiry_block` and `anchor`, which constrain the transfer to
a specific block range and ancestor state root; replaying the proof
into a different block fails at the compute phase anchor-window check
(step 2), NOT at the aggregator (which only re-verifies Plonky3
soundness).

---

## 4. Implementation plan

> UNO has not launched. "Migration" in earlier drafts meant "from
> Option B to aggregation"; in practice v1 ships with aggregation
> built-in. Phases below are **implementation milestones** leading
> up to the v1 launch, not consensus migrations of a running chain.

### 4.1 Phase structure

> **v1-scope status (post-§-1 pivot).** All A1-A6 work on block-level
> aggregation is **frozen research infrastructure** for v2+. v1
> launch uses the Option-B-era per-Tx proof shape — no new phases
> required on the Rust/C++ side beyond the existing per-Tx verifier
> (already shipping prior to A1). The v1 remaining work is wallet
> + testnet validation only (A7', A8' below).

**v1 launch phase table** (per §-1):

| Phase   | Status        | Scope                                  | Landmark                                          |
|---------|---------------|----------------------------------------|---------------------------------------------------|
| V1-PRE  | ✅ DONE       | Revert A6-4a Transfer struct delta     | commit `42fdb46a7` — zk_proof restored; BLOCK_TX_CAP = 4 |
| V1-1    | ✅ DONE       | Reinstate per-Tx verify in §4.3 step 4 | commit `42fdb46a7` — parallel-verify.cpp un-stubbed |
| V1-2    | ✅ DONE       | Update doc set for v1 positioning      | commits `b2d601a09` (top-level TPS posture) + V1-2b batch (filter / bandwidth / fees / burn rate recalibrated to 4 TPS) |
| V1-3a   | ✅ DONE       | tosctl-uno send docs / gap flagged     | tosctl-uno send pipeline + real Plonky3 prove (K-P6-wire, commit `465419764`) |
| V1-3b   | ✅ DONE       | tosctl-uno daemon wire-encoding parity | `boc_encode.rs` emits BoC Cell tree matching `encode_transfer`; `run_send` routes through it; daemon's `kChunkChainMaxChunks` raised 2048 → 8192 to cover 915 KB worst-case zk_proof. Commit `465419764`. Cross-language byte-parity test deferred to V1-3c (needs FFI bridge). |
| V1-4a   | ✅ DONE       | Testnet 60-day burn-in plan            | `doc/uno-v1-testnet-plan.md` — objectives / gates / scenarios / exit criteria |
| V1-4b   | ⬜ TODO       | Testnet burn-in execution              | 60-day run per V1-4a plan; 4 TPS sustained; validator decentralization healthy |
| V1-audit| ✅ DONE       | Audit scope handoff doc                | `doc/uno-v1-audit-scope.md` — 9 in-scope components + 12 audit queries; v2 research explicitly out-of-scope |
| V1-ops  | ✅ DONE       | Validator ops runbook                  | `doc/uno-v1-validator-ops.md` — hardware profile / opt-in / monitoring / incident playbooks |

**v2 research path phase table** (historical; code kept in tree):

| Phase | Status | Scope | Landmark |
|------|--------|------|----------|
| A1   | ✅ DONE       | Design + scaffolding | This doc + `aggregator.rs` / `verifier_air.rs` skeleton |
| A2   | ✅ DONE       | Proof-of-concept: 1-Tx "aggregation" | End-to-end prove+verify for N=1 (9-STARK bundle on 1/1 Transfer proof) |
| A3   | ✅ DONE       | Monolithic VerifierAir — all cross-binding gaps closed | A3-PRE..A3-5c: single AIR composing α + Merkle + fold across N bundles; 40 passing tests (see §4.1.2) |
| A4   | ✅ DONE       | Multi-bundle scaling measurements vs §3.4 | 208-bundle §4.1 landmark measured: ~420 KB proof, ~65 s prover; §3.4 100 KB envelope NOT achievable with plain FRI (see `doc/uno-aggregation-metrics.md` §A4) |
| A5   | 🟡 PARTIAL    | §4.1 wire format lands | ✅ `UnoBlockExtra` encode/decode landed in `block_wire_format.rs` (40 B header + opaque proof payload; 11 tests); ⬜ `Transfer` struct delta + validator wiring (A6) still pending |
| A6   | 🟡 PARTIAL    | Validator compute-phase wiring | A6-1 / A6-1.5 / A6-1.6 / A6-2 / A6-3 / A6-3b all landed; A6-4a landed but **REVERTED** for v1; A6-4b/c/d/e and A6-5 **DEFERRED** to v2 |
| A7   | ⬜ DEFERRED   | Wallet / tosctl integration | Was "per-Tx prove path unchanged" — rolls into V1-3 above |
| A8   | ⬜ DEFERRED   | Testnet validation | Was 60-day aggregated run — rolls into V1-4 above with per-Tx target |

Phases A1–A4 are Rust-side prover/verifier work (frozen as v2
research). A5–A6 partly landed then frozen. A7/A8 folded into V1-3 /
V1-4 for v1 launch. None of V1-* are "consensus-binding upgrades" —
they are the initial consensus parameters at genesis.

#### 4.1.1 Phase A2 sub-decomposition (implementation-side)

During A2 implementation the verifier-as-AIR work was split into
auditable sub-phases. These are tracked here because each lands its
own commit and set of adversarial tests.

| Sub-phase | Status | Scope | Tests | Commit (on branch `uno`) |
|-----------|--------|-------|-------|--------------------------|
| A2-1      | ✅ DONE | RefChallenger reference + upstream parity + AIR layout spec | 11 parity | `f80994712` |
| A2-2a     | ✅ DONE | ChallengerAir trace builder + pure-Rust constraint checker | 13 trace/checker | `6187106ec` |
| A2-2b     | ✅ DONE | ChallengerAirV1 `Air<AB>` impl + real STARK prove/verify | 8 STARK prove+verify | `47c620af7` |
| A2-2c     | ✅ DONE | Poseidon2-w8 duplex identity wired into ChallengerAir | +1 forged-state-next adversarial | `33bd9cd1b` |
| A2-3a     | ✅ DONE | Out-of-circuit Fiat-Shamir driver + byte-parity vs upstream | 6 (3 shapes × parity + replay + tamper + decode) | `a0bf0bc18` |
| A2-3b     | ✅ DONE | OOD constraint identity driver (skip-PCS) | 8 (3 positive + 4 adversarial + 1 upstream-agree) | `1fd4ed4d0` |
| A2-3c-i   | ✅ DONE | Full transcript driver — pre-PCS + FRI prefix (`alpha, zeta, fri_alpha, betas, query_indices`) | 6 (3 shapes parity + prefix invariant + 2 structural) | `bfe8cc821` |
| A2-3c-ii  | ✅ DONE | FRI arithmetic primitives — `fold_row`, `eval_final_poly_horner`, `final_eval_x` | 11 (fold-row × 4 + final-poly × 4 + final-x × 2 + helper × 1) | `a6e652afe` |
| A2-3c-iii | ✅ DONE | Merkle-path reference — `hash_leaf_row`, `compress_pair`, `verify_merkle_path` | 10 (hash × 4 + compress × 2 + verify × 4) | `9b0795533` |
| A2-3c-iv-a | ✅ DONE | Multi-matrix Merkle (reference) — quot-commit leaf shape | 6 | `dad26a269` |
| A2-3c-iv-b | ✅ DONE | `open_input` arithmetic — query_x + α-batched quotient | 12 | `f00bdf575` |
| A2-3c-iv-c | ✅ DONE | Full pure-Rust FRI verifier + query-PoW Fiat-Shamir fix | 11 (positive+adversarial+regression) | `3c5f6a17f` |
| A2-3c-iv-d-1 | ✅ DONE | Merkle-path AIR (narrow leaf) — trace+checker | 12 | `3f8915c7e` |
| A2-3c-iv-d-2 | ✅ DONE | MerklePathAirV1 `Air<AB>` + real STARK | 10 STARK | `0d51b4846` |
| A2-3c-iv-d-3 | ✅ DONE | Poseidon2 identity in MerklePathAirV1 | +2 forged-digest | `470b6af02` |
| A2-3c-iv-d-4 | ✅ DONE | FoldAir trace+checker (binary Lagrange fold) | 15 | `d6e4da973` |
| A2-3c-iv-d-4-2 | ✅ DONE | FoldAirV1 `Air<AB>` + STARK | 13 | `b265fb5fd` |
| A2-3c-iv-d-5 | ✅ DONE | α-reduction AIR trace+checker | 17 | `ff796c35b` |
| A2-3c-iv-d-5-2 | ✅ DONE | AlphaReductionAirV1 `Air<AB>` + STARK | 12 | `99b9cf3b5` |
| A2-3c-iv-d-6 | ✅ DONE | Single-query orchestration (α + fold cross-binding) | 8 | `da3180a7e` |
| A2-3c-iv-d-7-a | ✅ DONE | Wide-leaf hash AIR trace+checker (W = RATE·k) | 18 | `021611d83` |
| A2-3c-iv-d-7-b | ✅ DONE | LeafHashAirV1 `Air<AB>` + P2 + STARK | 11 | `e8a4127e7` |
| A2-3c-iv-d-7-c | ✅ DONE | Partial-last-block (widths 4k+r; trace-commit W=1305) | 4 net | `d9394cb20` |
| A2-3c-iv-d-7-d | ✅ DONE | `compression_path_air` (digest → root) | 10 | `6461f34da` |
| A2-3c-iv-d-8-a | ✅ DONE | query_verifier + trace-commit Merkle chain | 4 | `2e039648a` |
| A2-3c-iv-d-8-b | ✅ DONE | query_verifier + quotient-commit Merkle chain | 2 | `a5f02db2c` |
| A2-3c-iv-d-8-c | ✅ DONE | query_verifier + per-round commit-phase Merkle | 3 | `b20a3ce66` |
| A2-4      | ✅ DONE | Column-budget / feasibility measurement → `doc/uno-aggregation-metrics.md` | — | *this sub-phase* |

**Crate test count at end of A2-4:** 303 Rust tests, all green
(128-core parallelism: ~3m38s full suite). 16 C++ §12 tests still
pass. Consensus-binding FRI pin unchanged.

#### 4.1.2 Phase A3 sub-decomposition (monolithic VerifierAir)

A2 landed orchestrated per-query STARKs (6+N per query; ~12 MB/slot
naive extrapolation). A3 collapses that orchestration into ONE AIR
with K-air-col-share (see `doc/uno-aggregation-path-decision.md` for
rationale). Each sub-phase is its own auditable PR + commit.

| Sub-phase | Status | Scope | Tests | Commit (on branch `uno`) |
|-----------|--------|-------|-------|--------------------------|
| A3-PRE    | ✅ DONE | Feasibility path decision + `MonolithicVerifierAirV1` scaffold + 272-col layout pin | 3 (column-layout pinned + trivial IDLE round-trip + broken-one-hot reject) | `ccefafff9` |
| A3-1      | ✅ DONE | ABSORB + COMPRESS banks + in-circuit leaf-digest bridge (closes A2 "trusted construction" gap #1) | +5 (leaf-to-root × 2 + tampered-leaf + wrong-root + forged-bridge) | `749d40f26` |
| A3-2      | ✅ DONE | FOLD + ALPHA banks with K-air-col-share (STATE_IN = PAIR_LEFT/RIGHT; shared INDEX_BIT / SIBLING cols) | +10 (α-chain × 2 + fold-chain × 2 + adversarial × 5 + regression × 1) | `ade311647` |
| A3-3      | ✅ DONE | α↔fold cross-bindings — direct α→FOLD bridge + non-α ALPHA_RO_OUT / non-fold FOLD_OUT persistence | +5 (unified α+fold + 3 adversarial + regression) | `5a746851e` |
| A3-4      | ✅ DONE | Scaling measurements on unified α+fold shape → `doc/uno-aggregation-metrics.md` §A3-4 | +4 `#[ignore]`'d benches (α, fold, unified, sweep) | `d283e6fc1` |
| A3-5a     | ✅ DONE | Multi-path Merkle — per-path TCR check at COMPRESS → non-COMPRESS transition | +4 (2-path same-root + 2-path diff-root + adversarial × 2) | `75f77fa9f` |
| A3-5b     | ✅ DONE | Full per-query bundle — α + Merkle paths + fold in ONE AIR; **no new constraints needed** | +5 (1-Merkle + 2-Merkle positive + 3 adversarial) | `ded580564` |
| A3-5c     | ✅ DONE | Multi-bundle stacking — bundle-boundary constraints let PI proxies change across bundles | +5 (2-bundle positive + 3 adversarial + regression) | `30bbfc449` |

**Crate test count at end of A3:** 343 Rust tests passing, 4
`#[ignore]`'d A3-4 measurement tests. 40 monolithic-AIR tests in
`monolithic_verifier_air.rs` alone. Consensus-binding FRI pin
unchanged.

#### 4.1.3 Phase A4 landmark — scaling measurements against §3.4

A4 stacked the A3-5c multi-bundle shape at progressive scales to
characterize prover time and proof size. Full numbers in
`doc/uno-aggregation-metrics.md` §A4; headline:

| Shape                             | Prover time | Proof size |
|-----------------------------------|------------:|-----------:|
| 1 Tx = 52 bundles                 | ~2 s        | **356 KB** |
| 4 Txs = 208 bundles (§4.1 mark)   | ~65 s       | **420 KB** |
| N=30 extrapolation (1 560 bundles) | ~4 min     | ~550-650 KB |

**Decision**: §3.4's original 100 KB envelope is **NOT achievable**
with plain monolithic FRI at Option B parameters — FRI opening-proof
overhead (52 queries × log-height siblings × ~10 B/sibling) puts a
floor at ~250 KB that doesn't go away with trace packing. Per §4.3
fallback: accept the realistic 500-800 KB block-proof budget.

Sub-phase table:

| Sub-phase | Status | Scope | Tests | Commit |
|-----------|--------|-------|-------|--------|
| A4        | ✅ DONE | Multi-bundle measurement harness (52q, 208b, scaling sweep, 2/2-shape) | +4 `#[ignore]`'d measurement tests | `f472e4ad1` |

#### 4.1.4 Phase A5 sub-decomposition (wire format)

| Sub-phase | Status | Scope | Tests | Commit |
|-----------|--------|-------|-------|--------|
| A5 part 1 | ✅ DONE | `UnoBlockExtra` encode/decode + version framing (40 B header, opaque proof payload, 16 MB cap) | +11 (round-trip × 3 + byte-layout × 1 + 5 decode-error paths + stability + 512 KB realistic) | `5a9d942a3` |
| A5 part 2 | ⬜ PENDING | `Transfer` struct delta (add `witness_commitment`, drop `zk_proof`) + validator/mempool integration → folded into A6 | — | — |

**Crate test count at end of A5:** **354** Rust tests passing
(343 pre-A5 + 11 A5 wire-format). 8 `#[ignore]`'d measurement tests.

### 4.2 Landed work

**Phase A1** (PR merged into `uno` — commit `f7d077d0b`):
- This design document (`doc/uno-aggregation-design.md`).
- Module scaffolding: `uno/plonky3-ffi/src/aggregator.rs` with stub
  `AggregatorAir`, `AggregatorWitness`, and public entry points.
- Module scaffolding: `uno/plonky3-ffi/src/verifier_air.rs` —
  skeleton of the verifier-as-AIR, written to the same style as the
  Transfer AIR.
- Cargo.toml entries for the new modules.
- No changes to §4.1 wire format.
- No changes to `compute-phase.cpp`.
- All 16 §12 C++ tests and 43 Rust FFI tests continued to pass.

**Phase A2** (✅ DONE — see §4.1.1 for sub-phase breakdown):
- All A2 sub-phases merged into `uno`. Cumulative ~12 KLoC Rust across
  `fiat_shamir.rs`, `ood_eval.rs`, `fri_arith.rs`, `merkle_path.rs`,
  `open_input.rs`, `fri_verify.rs`, the AIR modules (`challenger_air`,
  `merkle_path_air`, `fold_air`, `alpha_reduction_air`, `leaf_hash_air`,
  `compression_path_air`, `query_verifier_air`), and supporting tests.
- A2-4 capped the phase with column-budget metrics (303 Rust tests
  green) establishing the feasibility input for A3.

**Phase A3** (✅ DONE — see §4.1.2 for sub-phase breakdown):
- Monolithic `MonolithicVerifierAirV1` at 272 columns collapses A2's
  orchestration into ONE AIR. All sub-banks (ABSORB, COMPRESS, FOLD,
  ALPHA, IDLE) share the Poseidon2-w8 block via K-air-col-share.
- Cross-binding gaps closed in-circuit: leaf-digest bridge (A3-1),
  α→fold bridge + persistence rules (A3-3), multi-path Merkle root
  check (A3-5a), multi-bundle stacking (A3-5c).
- Trace builders: `build_leaf_to_root_trace`,
  `build_multi_path_leaf_to_root_trace`, `build_alpha_chain_trace`,
  `build_fold_chain_trace`, `build_alpha_to_fold_unified_trace`,
  `build_alpha_merkle_fold_bundle_trace`, `build_multi_bundle_trace`.
- 40 tests pass in `monolithic_verifier_air.rs` alone; 343 total.
- No new bank constraints needed after A3-2; the composition story is
  entirely carried by persistence + cross-bank row-kind gating.

**Phase A4** (✅ DONE — see §4.1.3):
- Measurement harness at realistic scales (1 Tx = 52 bundles through
  4 Txs = 208 bundles); results in `doc/uno-aggregation-metrics.md`
  §A4.
- Decision: §3.4's 100 KB envelope is unreachable with plain FRI at
  Option B; §4.3 fallback selected (accept ~500-800 KB budget).

**Phase A5 part 1** (✅ DONE — see §4.1.4):
- `uno/plonky3-ffi/src/block_wire_format.rs` — `UnoBlockExtra` v1
  (40 B header + opaque proof payload), canonical encode/decode,
  versioning, decode-error surface.
- `block_wire_format` public consts picked up in cbindgen-regenerated
  `include/uno_plonky3_ffi.h` for C++ consumers.
- 11 tests (total suite: 354).

**Phases A5 part 2, A6–A8** are separate future PRs.

## 5. A6-4 Transfer struct delta and activation plan (v2 research — v1 reverts)

> **v1 reverts the Transfer struct change described below.** A6-4a
> originally bumped `version=2`, removed `zk_proof`, and added a
> `witness_commitment` field. Per §-1 pivot, v1 keeps the Option-B
> shape (with `zk_proof: ^Cell`). The plan below stays as the v2
> activation template for when aggregation returns.

A6-4 is the sub-phase that finalizes the on-chain `Transfer` layout for
the aggregation-era wire format. A5 part 1 landed `UnoBlockExtra`
(the block-level container for `aggregated_proof` + `tx_pi_merkle_root`);
A6-1 landed the FFI wire-format entry points (`uno_block_extra_encode_v1`
/ `_decode` / `_owned_free`); A6-1.5 landed `prove_block` /
`verify_block` end-to-end; A6-2 landed the `UnoBlockVerifierHandle`
FFI + the `uno_block_verifier_{init,free,verify}` entry points; A6-3
landed the `BlockProofVerifier` C++ RAII wrapper consuming them; A3-5c
landed the monolithic VerifierAir that fronts all of the above. A6-4
closes the last wire-format gap: the per-Tx `Transfer` struct itself
still carries a legacy `zk_proof: ^Cell` field that must be replaced
by a 32-byte `witness_commitment` before genesis.

### 5.1 Scope

Three atomic changes to `Transfer`:

1. **Remove `zk_proof: ^Cell`** — the per-Tx Plonky3 proof is no
   longer an on-chain payload. It still flows wallet → mempool → collator
   (see §5.3), but it is stripped before the collator commits the block.
2. **Add `witness_commitment: bits256`** — a 32-byte BLAKE3 hash
   computed by the wallet over the canonical bytes defined below.
3. **Bump `version = 2`** (per §2.1; this is the v1-launch value — the
   "2" reflects the original Option-B-era draft, not a post-launch
   upgrade).

**What the commitment binds** (recommended canonical encoding):

```
canonical_bytes := postcard(proof) || public_input_encoding(tx)
witness_commitment := BLAKE3(canonical_bytes)
```

Binding the PI (not just the proof) gives the collator/validator a way
to reconstruct each slot's PI hash deterministically from the `Transfer`
struct alone and match it against the per-slot PI the aggregator
consumed. Proof-only binding would still close the tampering gap at the
proof level but would force validators to re-derive PI from a different
source, duplicating serialization code. The 32 B cost is negligible
compared to the clarity win.

The commitment flows:

```
Wallet (computes BLAKE3) →
  mempool (carries {Transfer, proof} pair; commitment is inside Transfer) →
  collator (consumes proof for aggregator witness; commitment stays in Transfer) →
  block (Transfer list, each with its commitment, as leaves in tx_pi_merkle_root)
```

### 5.2 Wire-format diff

**Pre-A6-4 `Transfer` layout** (Option-B era, aspirational — UNO never
shipped this):

```
offset  size           field
   0    1              version
   1    1              scheme_id
   2    4              chain_id
   6    32             anchor
  38    4              expiry_block
  42    8              fee
  50    2              spend_count (S)
  52    2              output_count (O)
  54    S * 128        spends
   …    O * 146        outputs
   …    ^Cell ref      zk_proof            ← ~520 KB at 1/2, ~915 KB at 4/4
```

**Post-A6-4 `Transfer` layout** (A6-4 target, genesis-ready):

```
offset  size           field
   0    1              version = 2
   1    1              scheme_id = 0x01
   2    4              chain_id
   6    32             anchor
  38    4              expiry_block
  42    8              fee
  50    2              spend_count (S)
  52    2              output_count (O)
  54    S * 128        spends
   …    O * 146        outputs
   …    32             witness_commitment  ← fixed 32 B, replaces ^Cell
```

**Size delta**: at 1/2 shape (1 spend, 2 outputs), the Transfer payload
shrinks from ~520 KB to ~434 B — a ~1200× on-chain reduction (matches
§6 risks-item-4 in the existing doc). The chunk-chain / `^Cell`
indirection for `zk_proof` is fully removed.

**Hash stability**: `Transfer` serialization changes its byte image, so
all existing per-Tx hashes in fixtures, golden files, and C++
roundtrip tests become stale. A6-4 must refresh:
- `uno/test/fixtures/valid_transfer_fixture.h`
- Every C++ test that roundtrips a `Transfer` (~10 tests in the §12
  suite) needs regenerated golden hashes.
- Any Rust-side FFI fixture that embeds a serialized Transfer.

### 5.3 RPC / mempool impact

`uno_sendTransfer` is extended (backward-compat doesn't apply — UNO is
pre-launch):

| Arg          | Before A6-4          | After A6-4                             |
|--------------|----------------------|----------------------------------------|
| `transfer`   | `Transfer` (w/ proof)| `Transfer` (w/o proof, w/ commitment)  |
| `proof`      | —                    | Plonky3 proof bytes, separate arg      |

The wallet produces a `(Transfer, proof)` tuple; the RPC body carries
both, but the `Transfer` struct's proof field is gone. The collator
retains both halves in mempool storage until block assembly:

1. Pre-filter admits the tuple after cheap checks + per-Tx Plonky3
   verify at mempool tier (§4.3a pre-filter).
2. At block-assembly time, the collator pairs `(Transfer, proof)` for
   each admitted Tx and hands the full list to `aggregator::prove_block`.
3. Only the `Transfer` list (without proofs) + the aggregated proof
   land on-chain.

### 5.4 Validator compute-phase impact (§4.3 step 4 delta)

Prior §4.3 had "per-Tx Plonky3 verify" as step 5; A6-4 removes it from
non-collator validators entirely and replaces it with a per-block path:

1. **Per-Tx Plonky3 verify — REMOVED** from the compute-phase for
   non-producing validators. Step 5 remains ONLY at the collator tier.
2. **New step 7**: decode `UnoBlockExtra`, invoke
   `uno_verify_block(PI_block, aggregated_proof)` — ONE verify per block.
3. **New step 8**: for each `Transfer` in the block, recompute
   `BLAKE3(postcard(proof_i) || pi_encoding_i)` and compare against
   `Transfer.witness_commitment`. Compute the Merkle root over these
   commitments and compare against `UnoBlockExtra.tx_pi_merkle_root`.
   This closes the "proof binds the right Tx" gap without a per-Tx
   STARK verify.

**Deterministic rejection** (critical semantic change): malformed
`UnoBlockExtra`, commitment mismatch, Merkle-root mismatch, or STARK
verify failure all reject the **whole block**, not a single Tx. Under
the legacy per-Tx model a bad proof drops the one Tx and the block
continues. Under aggregation the proof is block-scoped, so the failure
unit is the block.

### 5.5 Collator impact

The collator gains one new responsibility:

- After §4.3a admits N Transfers and per-Tx verify runs at mempool
  tier, the collator invokes `aggregator::prove_block(txs, proofs)` to
  produce the block's aggregated proof.
- Per A4 measurements, that is ~1-4 min of prover time on a 128-core
  x86 host (208 bundles ≈ 65 s; 30-Tx extrapolation ≈ 4 min).
- **Block-production budget implication**: the current §1.4a 1 s block
  cadence cannot absorb multi-minute prover time. Two mitigations are
  on the table:
  1. **Slower cadence**: move block cadence from 1 s to ~60 s for the
     aggregated-block epoch; reduces TPS ceiling but halves
     bandwidth/proof dominance.
  2. **Prove-worker pipeline**: run `prove_block` ahead of the deadline
     on a pipelined worker that begins once enough Txs admit, so the
     producer only pays finalization cost at the deadline.
  Decision is deferred to A7 (wallet/testnet integration) once real
  hardware numbers land.

### 5.6 Hardfork activation plan

UNO is pre-launch, so "hardfork" here is shorthand for "versioning
commitments at genesis". No migration of a deployed state is required.

- `Transfer.version = 2` is the **v1-launch value** per §2.1. The "2"
  preserves the Option-B draft numbering; version 1 was never deployed.
- Collators and validators SHALL reject any `Transfer` with
  `version != 2` post-launch (treat as unsupported scheme).
- `aggregator_scheme_id = 0x01` and `scheme_id = 0x01` are the PQ-launch
  values; future crypto-family migrations (e.g. WHIR-based
  verifier-as-AIR) bump these and require a consensus upgrade at that
  time.
- Genesis block ships with the new Transfer shape; there is no
  coexistence period with an earlier format.

### 5.7 Testing plan

A6-4 sub-tasks:

1. **Fixture refresh**: regenerate `uno/test/fixtures/valid_transfer_fixture.h`
   with the new Transfer shape (drop `zk_proof`, add a known-good
   `witness_commitment`).
2. **Encode/decode roundtrip**: update the ~10 C++ tests that
   roundtrip `Transfer` structs (golden hashes become stale; refresh
   them against the new serialization).
3. **Commitment-to-Merkle-root test** (new): construct N synthetic
   Transfers with known proofs, compute each `witness_commitment` via
   BLAKE3, build the Merkle tree, assert the root equals
   `UnoBlockExtra.tx_pi_merkle_root` produced by `prove_block` for the
   same input list.
4. **Validator rejection test** (new): feed a block with a valid
   aggregated proof but a tampered `witness_commitment` on one Tx;
   assert the whole block rejects at compute-phase step 8.
5. **Scheme-id rejection test** (new): feed a block with `version = 1`
   or `scheme_id != 0x01`; assert deterministic reject.

### 5.8 Open questions (defer)

Explicitly out of scope for A6-4; tracked for follow-on PRs:

- **Outputs-only Transfers**: do Transfers with `spend_count = 0` need
  a non-zero `witness_commitment`? If yes, what is the canonical
  encoding when there is no spend-side proof data?
- **PI-column stability**: is the `public_input_encoding(tx)` binding
  canonical under future PI-column additions? Cross-reference to
  A6-1.6 PI binding work.
- **Mempool-carryover behavior**: if a Tx sits in mempool for K blocks
  without being included, does its `witness_commitment` change?
  Expected answer: no — the commitment binds per-Tx data only, and
  block-level PI (e.g. `block_seqno`) is a separate concern handled at
  the `UnoBlockExtra` layer. Confirm by test at A8 testnet tier.

---

### 4.3 Pre-launch fallback posture

UNO has not launched, so "rollback" in the usual consensus sense does
not apply. If the A4 30-Tx measurement misses the envelope, the
pre-launch options are (in order of preference):

1. Tune `BLOCK_TX_CAP` downward — smaller per-block N, smaller
   aggregator AIR, proportionally smaller proof. v1 ships at the
   largest N that meets §3.4.
2. Revisit FRI parameters for the aggregator AIR independently of
   the per-Transfer AIR. Option-B-equivalent pins apply to the
   aggregator only.
3. Abandon aggregation and ship v1 at Option B per-Transfer proofs
   (~915 KB 4/4 worst case), re-scoping §3.4 publicly before
   launch. A1–A4 scaffolding can stay in-tree as v2+ work.

All three options are in-tree decisions pre-launch; none requires a
consensus upgrade. This is why A1 lands as scaffolding-only — the
feasibility measurement in A4 fully informs the v1 launch
configuration.

---

## 6. Risks and open questions

1. **Aggregator AIR column count at N=30**: estimated 200 + 20·30 = 800
   cols; under calibrated C1 that's ~135 KB. If the real AIR ends up
   at 1,500+ cols, the aggregator proof hits ~500 KB and the
   §3.4 target is missed AGAIN.
   **Mitigation**: Phase A2 will measure this with a 1-Tx POC to
   calibrate.

2. **Aggregator prove time**: at 30 Transfers, we're proving 30
   verifier circuits in a single STARK instance. Naively, prove time
   scales linearly with trace width × trace height; we can expect
   3–10 s per block.
   **Mitigation**: `BLOCK_TX_CAP` can be tuned down if prove time
   exceeds block-production budget.

3. **Plonky3 recursion maturity**: the vendored `third-party/plonky3-uno/`
   at v0.5.1 does NOT include a dedicated `recursion` or `verifier-as-AIR`
   crate. We write the verifier AIR ourselves — `uni-stark`'s verifier
   is small, but auditing a hand-written STARK verifier is non-trivial.
   **Mitigation**: the verifier AIR is small enough (~300 cols) that
   it can be independently audited; aim to land Phase A2 with
   extensive unit tests including adversarial cases (tampered π_i,
   wrong PI, etc.).

4. **State bloat**: on-chain block storage is now per-Tx witness
   commitment (32 B) + aggregated_proof (~100 KB). Per-Transfer
   on-chain cost: (128 B header + 128 B spend + 146 B output + 32 B
   witness_commitment) ≈ 434 B at 1/2, vs the previous 520 KB. **Net
   on-chain bandwidth drops by ~1000×.**

5. **Signature verification still per-Tx**: the §4.3 step 3 per-spend
   Schnorr verify remains per-Transfer. On a validator, that's ~1 ms
   × 4 spends × 30 Tx = ~120 ms per block — acceptable in the 1 s
   budget, but worth measuring.

6. **Audit scope impact**: the verifier AIR is a new attack surface
   (hand-written STARK verifier). Audit-vendor SOW must cover:
   - Verifier AIR correctness (≈ match Plonky3 uni-stark verifier line-by-line)
   - Merkle-root commitment over per-Tx PIs (collision soundness)
   - Aggregator soundness composition (per-Tx AIR + verifier AIR)
   - Collator's aggregation prover implementation
   Estimated +2–4 audit-weeks on top of existing scope.

---

## 7. Success criteria (definition of done)

### Phase A1 — ✅ DONE

- [x] Design document lands in `doc/uno-aggregation-design.md`
- [x] Module skeletons in `uno/plonky3-ffi/src/aggregator.rs` and
  `verifier_air.rs` compile cleanly
- [x] `cargo test` still passes all 43 existing tests
- [x] All 16 C++ §12 tests still pass
- [x] A new "hello-aggregator" test: the aggregator scaffolding
  exposes entry points that accept empty input and return a stubbed
  proof byte vector. Not consensus-correct yet — just proves the
  wiring compiles.

### Phase A2 — 🟡 IN PROGRESS

Sub-phases landed:

- [x] **A2-1**: `RefChallenger` reference impl + byte-parity tests
  against upstream `DuplexChallenger`. AIR layout spec pinned.
- [x] **A2-2a**: `ChallengerAir` trace builder + pure-Rust
  constraint checker (the spec A2-2b ports to `Air<AB>`).
- [x] **A2-2b**: `ChallengerAirV1::Air<AB>` impl; real STARK
  prove+verify round-trip; 8 adversarial tests pass.
- [x] **A2-2c**: Poseidon2-w8 duplex identity wired into
  ChallengerAir; forged `state_next` adversarial test rejects.
- [x] **A2-3a**: Out-of-circuit pre-PCS Fiat-Shamir driver
  (`fiat_shamir.rs::derive_pre_pcs_challenges`); byte-parity vs
  upstream on 1/1, 2/2, 4/4 real Transfer proofs.
- [x] **A2-3b**: OOD constraint identity driver (`ood_eval.rs`);
  recomposes `quotient(zeta)` and asserts the identity; 4
  adversarial tamper-path tests reject.
- [x] **A2-3c-i**: Full-transcript Fiat-Shamir driver
  (`fiat_shamir.rs::derive_full_challenges`) extending past zeta
  through the PCS/FRI prefix. Returns `FullChallenges { alpha_stark,
  zeta, fri_alpha, betas, query_indices, log_global_max_height }`
  with byte-parity against upstream on all shape extremes.
- [x] **A2-3c-ii**: FRI arithmetic primitives (`fri_arith.rs`) —
  `fold_row_ref` (Lagrange-at-β over roots-of-unity coset),
  `eval_final_poly_horner`, `final_eval_x`. Line-numbered
  reimplementations of upstream, validated via 11 tests including
  64 randomized + arity-4 sweeps.
- [x] **A2-3c-iii**: Merkle-path reference primitives
  (`merkle_path.rs`) — `hash_leaf_row_ref` (PaddingFreeSponge),
  `compress_pair_ref` (TruncatedPermutation), and
  `verify_merkle_path_ref` for single-matrix / binary / cap_height=0
  trees. 10 tests including upstream-commit / our-verify crossovers.

Remaining:

- [ ] **A2-3c-iv**: In-circuit FRI-AIR — encode the A2-3c-ii
  arithmetic primitives and A2-3c-iii Merkle-path primitives as
  AIR constraint banks, driving a per-query fold-chain row-loop
  bound to `FullChallenges` via public-input wiring.
- [ ] **A2-4**: Single-slot `VerifierAir` end-to-end prove+verify.
  Measurement target: ≤ ~300 cols/slot at the aggregator's
  verifier-replay sub-block.

### Phases A3–A8 — ⬜ PENDING

Each has its own success criteria; see the §4.1 phase table.
A3/A4 in particular must measure the aggregator proof size at
N = 4 and N = 30 against the §3.4 ~100 KB target (the whole
premise of this design — the feasibility result gates v1 launch
configuration).

---

## 8. Related documents

- `doc/uno-workchain.md` §4.1 (Transfer wire format — A5 finalizes it as the v1 launch format)
- `doc/uno-workchain.md` §4.3 (verify order — A6 finalizes the validator compute-phase wiring)
- `doc/uno-workchain.md` §14 (aggregation is listed here as v2+;
  this doc promotes it to v1)
- `doc/uno-workchain.md` §16 (decision log — a new entry #46 will
  record the v1 promotion)
- `doc/uno-air-optimization-log.md` C7 (Plonky3 LogUp constraint;
  tangentially relevant — aggregation doesn't unlock LogUp, but it
  also doesn't require it)
- `doc/uno-p2-path-research.md` Path (iii) (batch-stark migration;
  orthogonal to aggregation — both are options for reaching §3.4,
  aggregation is lower-risk for v1)
- `doc/uno-fri-param-analysis.md` (the Option B decision that
  aggregation builds on; same FRI params apply to the aggregator AIR)
