# Uno Proof Aggregation — Design (v1 promotion from §14)

**Status:** Draft. Defines the v1 Transfer wire format (§4.1) and adds a
new §16 decision; closes the §3.4 ~100 KB envelope gap identified in
`doc/uno-p2-path-research.md`. Supersedes the re-scope decision to 1 MB.
UNO has not launched, so the §4.1 format lands at v1 directly — there is
no prior deployed format to amend.

**Implementation progress:** A1 ✅, A2 ✅ (all sub-phases complete;
single-slot in-circuit FRI verification works end-to-end on real 1/1
Transfer proofs — see `doc/uno-aggregation-metrics.md`). A3–A8 ⬜.
See §4.1 and §6 for the per-phase status table.

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
- §4.1 wire format: Transfer's `zk_proof: ^Cell` field is redefined as
  a witness commitment; a block-level `aggregated_proof` field is
  added. Since UNO has not launched, this is the v1 launch format —
  not a migration from a prior one.
- §4.3 verify order: validators verify ONE aggregated proof per block
  (plus per-Transfer signatures / anchors); they do NOT verify
  per-Transfer STARK proofs individually.
- Audit scope: the verifier AIR is an additional attack surface; the
  audit-vendor SOW must cover it.
- v1 ship timeline: **+3–4 months** vs. a hypothetical Option-B-only
  launch.

**Recommended v1 decision**: adopt aggregation at the v1 launch.
Rationale:
1. Cleanly delivers the original §3.4 ~100 KB envelope.
2. Every future v2 item (multi-asset, shielded DEX, Aleo-class
   programmability) already assumes aggregation; baking it into v1
   avoids a consensus-binding wire-format change post-launch.
3. The infrastructure is foundational; it compound-interests every
   subsequent release.

> **Note on framing**: this document was originally written as a
> "migration plan" from Option B to aggregation. Since UNO has not
> yet launched, there is no deployed state to migrate *from* — v1
> launches directly with aggregation. Phase labels A1…A8 below are
> retained as **implementation milestones**, not migration steps. No
> rollback posture is needed in the traditional sense; the fallback
> (§4.3) is to adjust `BLOCK_TX_CAP` or revisit FRI parameters
> pre-launch if A4 measurements miss the envelope.

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

## 4. Implementation plan

> UNO has not launched. "Migration" in earlier drafts meant "from
> Option B to aggregation"; in practice v1 ships with aggregation
> built-in. Phases below are **implementation milestones** leading
> up to the v1 launch, not consensus migrations of a running chain.

### 4.1 Phase structure

| Phase | Status | Scope | Landmark |
|------|--------|------|----------|
| A1   | ✅ DONE       | Design + scaffolding | This doc + `aggregator.rs` / `verifier_air.rs` skeleton |
| A2   | ✅ DONE       | Proof-of-concept: 1-Tx "aggregation" | End-to-end prove+verify for N=1 (9-STARK bundle on 1/1 Transfer proof) |
| A3   | ⬜ PENDING    | 4-Tx aggregation + correctness tests | Fixture-based 4/4 aggregated proof; cross-impl parity |
| A4   | ⬜ PENDING    | 30-Tx aggregation + performance | Shape_matrix-style bench; ensures ≤ 100 KB block proof |
| A5   | ⬜ PENDING    | §4.1 wire format lands | Transfer struct + `UnoBlockExtra` as the v1 launch format |
| A6   | ⬜ PENDING    | Validator compute-phase wiring | Per-block aggregated-proof verify path; no per-Tx STARK verify |
| A7   | ⬜ PENDING    | Wallet / tosctl integration | Wallet still produces per-Tx proof (unchanged path) |
| A8   | ⬜ PENDING    | Testnet validation | 60-day run per §P.7 before mainnet launch |

Phases A1–A4 are Rust-side prover/verifier work. A5–A6 land the
v1 wire format and validator logic. A7 is the client integration.
A8 is the pre-launch burn-in. None of A5–A6 are "consensus-binding
upgrades" in the sense of amending a deployed chain — they are
the initial consensus parameters at genesis.

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

**Phase A2** (in progress — see §4.1.1 for sub-phase breakdown):
- A2-1 through A2-3c-iii merged into `uno`; cumulative +~8 KLoC Rust,
  +90 new unit tests (11 parity + 13 trace/checker + 8 STARK + 6
  Fiat-Shamir pre-PCS + 6 Fiat-Shamir full-transcript + 8 OOD + 11
  FRI arithmetic + 10 Merkle-path + 17 other assorted).
- Remaining A2 work: in-circuit FRI-AIR (A2-3c-iv — encodes
  `fri_arith` + `merkle_path` as AIR constraints) and single-slot
  end-to-end prove+verify (A2-4).

**Phases A3–A8** are separate future PRs.

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

## 7. Related documents

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
