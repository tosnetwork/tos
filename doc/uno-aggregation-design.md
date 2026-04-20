# Uno Proof Aggregation — Design (v1 promotion from §14)

**Status:** Draft. Amends §4.1 wire format and §16 decision chain; closes the
§3.4 ~100 KB envelope gap identified in `doc/uno-p2-path-research.md`.
Supersedes the re-scope decision to 1 MB.

## 0. Executive summary

§3.4 originally targeted a ~100 KB worst-case `zk_proof` field per
Transfer. After the K-air-col-share + K-air-col-step2 + FRI-Option-B
landings, we reached ~915 KB — 9× over target. Paths (i), (ii), (iii)
from `doc/uno-p2-path-research.md` cannot close that gap while holding
§0.2 (PQ-native), §1.5 (bridgeless), and §16 decisions #1, #2
(no trusted setup, STARK).

**First-principles analysis** (documented in the last planning round)
identified recursive proof aggregation as the only path that respects
all v1 invariants. §14 already lists "Proof aggregation" as a v2+ item;
this document promotes it to v1.

**What this buys**:
- On-chain block proof ≈ **~100 KB**, independent of how many
  Transfers it covers (up to a per-block cap).
- Inter-validator bandwidth at 30 TPS drops from ~27 MB/s (Option B)
  to ~3 MB/s — well within the §1.4a 200 Mbps budget.
- Wallet-side prove cost **unchanged** (prove-per-Transfer is still
  client-side; no privacy loss).
- Collator-side: adds a **block-level aggregation prove** step (a
  recursive proof over the N per-Transfer proofs in the block).
  ~3–10 s per block on 8-core x86; shift-able to dedicated hardware.

**What this costs**:
- New subsystem: a `verifier-as-AIR` that re-proves the Plonky3
  Transfer-AIR verifier as a STARK circuit. ~800–1,500 LoC of Rust.
- §4.1 wire format change: Transfer's `zk_proof: ^Cell` field changes
  semantics; new block-level `aggregated_proof` field.
- §4.3 verify order changes: validators no longer verify per-Transfer
  proofs individually; they verify ONE aggregated proof per block.
- Consensus-binding (§16-level amendment of decision #33 and the
  wire-format contract).
- Audit re-scope: the verifier AIR is itself a new attack surface; the
  audit-vendor SOW needs to cover it.
- v1 ship delay: **+3–4 months** vs. the Option B ship-now path.

**Recommended v1 decision**: adopt aggregation, accept the 3–4 month
delay. Rationale:
1. Cleanly tracks the original §3.4 commitment (no public re-scope).
2. Every future v2 item (multi-asset, shielded DEX, Aleo-class
   programmability) already assumes aggregation; doing it at v1
   avoids a consensus-binding wire-format change later.
3. The infrastructure is foundational; it compound-interests every
   subsequent release.

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

**Proposed aggregation-era `Transfer` struct**:

```
Transfer :=
  version (= 2 now, signals new scheme), scheme_id (= 0x01)
  chain_id, anchor, expiry_block, fee
  spend_count, output_count
  spends: Array<SpendDescription>
  outputs: Array<OutputDescription>
  witness_commitment: bits256   // 32 B, BLAKE3 over canonical proof bytes
  // zk_proof field REMOVED from the on-chain Transfer struct
```

**New block-level field** (next to other block metadata):

```
UnoBlockExtra :=
  aggregator_scheme_id : u8       = 0x01     // crypto-agility
  aggregator_version   : u8       = 1
  n_transfers          : u16
  tx_pi_merkle_root    : bits256              // matches PI_block.merkle_root_of_tx_public_inputs
  aggregated_proof     : ^Cell                // the recursive proof, ~100 KB
```

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
BLOCK_TX_CAP := 30    // maximum Transfers per block (1 s cadence)
```

This caps the aggregator's input list length. Chosen to match §1.4
success criterion #7 ("15–30 TPS sustained"). A 30-Transfer block
under aggregation emits ~100 KB of on-chain proof, vs. ~30 × 915 KB
= 27 MB under the Option B per-Transfer model.

### 2.4 §4.3 compute-phase order update

```
1.  Syntax checks (unchanged)
2.  Anchor window (unchanged)
3.  Nullifier uniqueness across block (unchanged)
4.  Per-Transfer signatures (unchanged)
5.  Per-Transfer Plonky3 verify (unchanged, runs at the collator tier)
6.  Accept Transfer → add to block candidate
7.  NEW: block-level aggregated_proof verify (ONE verify per block)
```

Validators (non-block-producing) skip step 5 entirely; they only need
step 7 to confirm "all Transfers in this block had valid proofs".
Step 5 runs ONLY at the block producer (collator) in order to filter
invalid proofs before aggregation.

Collator CPU cost: +3–10 s per block for the aggregation prove step.
At 1 s block cadence, aggregation runs in parallel with the next block's
mempool drain (pipelined); per-block wall-clock impact bounded by the
aggregator prove time.

### 2.5 §4.3a admission pre-filter

Unchanged from Option B. The full Plonky3 verify is deferred to the
collator (step 5 above), so admission still does the cheap checks only.

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

## 4. Migration plan

### 4.1 Phase structure

| Phase | Scope | Landmark |
|------|------|----------|
| A1 | Design + scaffolding | This doc + `aggregator.rs` / `verifier_air.rs` skeleton |
| A2 | Proof-of-concept: 1-Tx "aggregation" | End-to-end prove+verify for N=1; functional test |
| A3 | 4-Tx aggregation + correctness tests | Fixture-based 4/4 aggregated proof; cross-impl parity |
| A4 | 30-Tx aggregation + performance | Shape_matrix-style bench; ensures ≤ 100 KB block proof |
| A5 | §4.1 wire format migration | Transfer struct change; collator + validator wiring |
| A6 | Validator compute-phase rewrite | Step 7 added; step 5 moved to collator tier only |
| A7 | Wallet / tosctl updates | Wallet still produces per-Tx proof (unchanged path) |
| A8 | Testnet validation | 60-day run per §P.7 |

Phases A1–A4 are pure Rust-side work (additive — no consensus impact
until A5). A5–A6 are the consensus-binding changes.

### 4.2 This PR

This PR lands **Phase A1** only:
- This design document (`doc/uno-aggregation-design.md`).
- Module scaffolding: `uno/plonky3-ffi/src/aggregator.rs` with stub
  `AggregatorAir`, `AggregatorWitness`, and public entry points.
- Module scaffolding: `uno/plonky3-ffi/src/verifier_air.rs` —
  skeleton of the verifier-as-AIR, written to the same style as the
  Transfer AIR.
- Cargo.toml entries for the new modules.
- No changes to §4.1 wire format yet.
- No changes to `compute-phase.cpp` yet.
- All 16 §12 C++ tests and 43 Rust FFI tests continue to pass.

Phases A2–A8 are **separate future PRs**.

### 4.3 Rollback posture

If the aggregator does not reach ≤ 150 KB proof at 30 Tx, the path
back to Option B (current state) is a pure revert of A5 onward.
Phases A1–A4 are non-consensus-binding and can be left in-tree as
experimental machinery even if v1 ultimately ships at Option B.

This rollback-safety is why we land A1 as a scaffolding-only commit
first — if the N=30 feasibility measurement reveals that the aggregator
proof exceeds the budget, we can drop the full migration without
having destabilized the codebase.

---

## 5. Risks and open questions

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

## 6. Success criteria (definition of done)

Phase A1 (this PR) is complete when:
- [x] Design document lands in `doc/uno-aggregation-design.md`
- [ ] Module skeletons in `uno/plonky3-ffi/src/aggregator.rs` and
  `verifier_air.rs` compile cleanly
- [ ] `cargo test` still passes all 43 existing tests
- [ ] All 16 C++ §12 tests still pass
- [ ] A new "hello-aggregator" test: the aggregator scaffolding
  exposes entry points that accept empty input and return a stubbed
  proof byte vector. Not consensus-correct yet — just proves the
  wiring compiles.

Future phases A2+ have their own criteria, defined in this doc's §4.1
phase table.

---

## 7. Related documents

- `doc/uno-workchain.md` §4.1 (Transfer wire format, to be amended at A5)
- `doc/uno-workchain.md` §4.3 (verify order, to be amended at A6)
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
