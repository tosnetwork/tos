# Uno Aggregation — Phase A2 Measurements (A2-4)

This document captures the per-query AIR column widths, trace heights,
and STARK-bundle shapes for the orchestrated in-circuit FRI verifier
landed over A2-3c-iv-d-6 through d-8-c. It is the **measurement input
for A3/A4** — the phases where we decide whether the orchestration
fits the §3.4 ≤100 KB block-proof envelope at N = 30 slots, or
whether to collapse into a monolithic AIR.

## Per-sub-AIR column widths (pinned)

| AIR module | Framing cols | P2 block | Total WIDTH |
|------------|-------------:|---------:|------------:|
| `alpha_reduction_air::AlphaReductionAirV1` | 28 | — | **28** |
| `fold_air::FoldAirV1`                       | 21 | — | **21** |
| `merkle_path_air::MerklePathAirV1`          | 32 | 180 | **212** |
| `leaf_hash_air::LeafHashAirV1`              | 35 | 180 | **215** |
| `compression_path_air::CompressionPathAirV1` | 32 | 180 | **212** |

*Arithmetic AIRs are narrow (no Poseidon2). Hash AIRs carry a shared
180-col Poseidon2-w8 witness block.*

## Per-query STARK count (`query_verifier_air::FullQueryProof`)

One query at Option B (`log_blowup = 3`, `num_queries = 52`,
`query_proof_of_work_bits = 24`):

| STARK | AIR | Typical trace height |
|-------|-----|----------------------|
| α-reduction chain | AlphaReduction | next_pow2(air_width · 2 + num_chunks · 2) |
| fold chain | Fold | next_pow2(num_commit_phase_rounds + pad) |
| trace-commit leaf hash | LeafHash | next_pow2(⌈air_width / 4⌉) |
| trace-commit compression | CompressionPath | next_pow2(log_global_max_height) |
| quotient-commit leaf hash | LeafHash | next_pow2(⌈num_chunks · DIM / 4⌉) = 2 → 16 |
| quotient-commit compression | CompressionPath | next_pow2(log_global_max_height) |
| **per-round**: commit-phase Merkle × `num_commit_phase_rounds` | MerklePath | next_pow2(1 + log_height_r) |

Total = **6 + num_commit_phase_rounds** STARKs per query.

## Per-shape trace heights (measured on real proofs)

| Shape | `air_width` | `degree_bits` | `log_global_max_height` | `num_rounds` | STARKs/query |
|:----:|:----------:|:-------------:|:-----------------------:|:------------:|:------------:|
| 1/1  | ~450       | 3             | 6                       | 3            | **9**        |
| 2/2  | 1305       | 6             | 9                       | 6            | **12**       |
| 4/4  | ~2600      | 9             | 12                      | 9            | **15**       |

*(`air_width(n_s, n_o)` from `transfer_air::air_width`; exact 1/1 and
4/4 values recorded by sanity tests in `transfer_air`.)*

## Per-query cumulative trace area

*Trace area = width × height. Used as a rough proxy for prover cost
and proof size.*

### 2/2 shape (realistic mid-case)

| STARK | Width | Height | Area (k cells) |
|-------|------:|-------:|---------------:|
| α-reduction | 28 | 4096 | ~115 |
| fold | 21 | 16 | ~0.3 |
| trace leaf-hash | 215 | 512 | ~110 |
| trace compression | 212 | 16 | ~3.4 |
| quot leaf-hash | 215 | 16 | ~3.4 |
| quot compression | 212 | 16 | ~3.4 |
| commit-phase × 6 | 212 | 16 each | ~20 |
| **Total per query** | | | **~255 k cells** |

### Block-level cost estimate (52 queries × 30 slots)

- Per block: 52 queries × ~255 k cells = **~13.3 M trace cells per slot**
- Per block (30 slots): **~400 M trace cells**

For comparison, a single Transfer AIR (per-Tx proof) at 2/2 is ~3 M
cells (air_width ≈ 1305 × trace height 2^9 = 512). So the aggregator
trace is ~133× the size of a single per-Tx AIR — this is the cost of
in-circuit verification across 52 queries × 30 slots.

## §3.4 feasibility readout

The empirical proof-size/column calibration from
`doc/uno-fri-param-analysis.md` (C1: ~325 B per trace column at
Option B) suggests:

- Per-query bundle (6+N STARKs) is ~10 proofs × ~25 KB each = **~250 KB**
  raw bytes BEFORE any aggregation.
- ×52 queries = **~13 MB per slot**.
- ×30 slots = **~390 MB per block**.

**This is well above the §3.4 100 KB envelope.**

The PoC orchestration proves every sub-operation in isolation. To hit
~100 KB at the block level, we must EITHER:

1. **Monolithic VerifierAir** that encodes all sub-operations in a
   single trace with SHARED P2 columns (row-loop pattern, like
   `transfer_air`'s shared Cm/IvkCm blocks). This is the recursive
   verifier AIR the `doc/uno-aggregation-design.md` §3.2 envisioned.
2. **STARK recursion** (PCD-style): each query's 6+N STARKs get
   recursively verified by one outer STARK, whose own proof is then
   what ships on-chain. ~100 KB budget applies only to the outermost
   proof.

Either path requires significant additional engineering beyond A2.
Both should be explored in A3 (4-Tx correctness) / A4 (30-Tx measurement).

## A2 phase status

✅ **A2 PoC complete**: in-circuit verification of a single FRI query
works end-to-end on real 1/1 Transfer proofs (9-STARK bundle verifies;
see `full_query_verifier_accepts_all_chains_1_1_query_0`).

✅ **Every arithmetic + every hashing operation** that FRI verification
requires is expressible as an AIR with real STARK prove+verify
round-trip testing.

⬜ **Known gaps** (deferred to A3+):
- Cross-bindings between sub-AIRs are held by CONSTRUCTION at
  the orchestrator level, not by in-circuit assertions on shared
  public-input columns. A malicious prover could forge independent
  STARKs with inconsistent boundary values. Closing this requires a
  monolithic AIR or PCD-style fold.
- `x` and `β` public-input bindings: currently treated as trace
  columns trusted from the orchestrator. In a deployed verifier
  AIR these must be committed via the challenger's transcript.
- Full 52-query × 30-slot aggregation not yet measured; the PoC
  only validates ONE query at a time.

## Pointers

- AIR source modules: `uno/plonky3-ffi/src/{alpha_reduction_air,
  fold_air, leaf_hash_air, compression_path_air, merkle_path_air,
  query_verifier_air}.rs`.
- Out-of-circuit reference: `fiat_shamir.rs` + `ood_eval.rs` +
  `fri_arith.rs` + `merkle_path.rs` + `open_input.rs` +
  `fri_verify.rs`.
- Test fixture entry point: `query_verifier_air::tests::
  full_query_verifier_accepts_all_chains_1_1_query_0`.
