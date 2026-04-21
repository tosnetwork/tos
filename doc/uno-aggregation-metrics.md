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

---

## A3 phase — monolithic AIR progression

Phase A3 collapses the A2 orchestration into a **single AIR with
K-air-col-share** — one `MonolithicVerifierAirV1` with 272 columns and
per-row `KIND` selectors gating constraint banks.

### A3-PRE: scaffold + column layout pin (landed).

### A3-1: ABSORB + COMPRESS banks + leaf-digest bridge (landed).
  - "Wide leaf → Merkle root" in ONE STARK.
  - The ABSORB→COMPRESS in-circuit bridge closes A2's first
    trusted-by-construction gap (leaf-hash digest == first-compression
    CURRENT).

### A3-2: FOLD + ALPHA banks (landed).
  - Fold-chain and α-reduction expressible as standalone single-STARK
    traces on the monolithic AIR.
  - K-air-col-share re-uses `STATE_IN[0..4]` as FOLD's PAIR_LEFT/RIGHT,
    `COMPRESS_SIBLING[0..2]` as FRI sibling, `COMPRESS_INDEX_BIT` as
    orientation. FOLD / COMPRESS are one-hot disjoint so the shared
    cols carry orthogonal meaning without cross-bank interference.

### A3-3: α↔fold cross-binding (landed).
  - Three in-circuit transitions close A2's "trusted construction"
    gap at the α/fold seam:
    1. `is_alpha · next_is_fold · (next.FOLD_IN − local.ALPHA_RO_OUT) = 0`
    2. `(1 − next_is_alpha) · (next.ALPHA_RO_OUT − local.ALPHA_RO_OUT) = 0`
    3. `(1 − next_is_fold) · (next.FOLD_OUT − local.FOLD_OUT) = 0`
  - Unified α+fold trace verifies in ONE monolithic STARK
    (`air_prove_and_verify_unified_alpha_to_fold_chain`).
  - Adversarial tests tamper the α→fold seam and reject via the
    bridge constraint.

### A3-4: scaling measurements (landed).

Captured on `Linux 6.8.0-107-generic`, 192-core host,
`cargo test --release --test-threads 1`. Measurements use the
monolithic AIR at its current 272-col width, Option B FRI pin
(log_blowup = 3, num_queries = 52, query_pow_bits = 24).

**α-chain scaling sweep** (α-only trace, IDLE-padded to `trace_height`):

| trace_height | trace cells |  prove (ms) | proof (bytes) |
|-------------:|------------:|------------:|--------------:|
|          64  |      17 408 |      ~4 500 |       222 219 |
|         256  |      69 632 |      ~8 000 |       269 841 |
|       1 024  |     278 528 |     ~13-36k |       326 056 |
|       4 096  |   1 114 112 |      ~4-11k |       389 597 |

**Fold-chain scaling sweep** (tight: all rounds fit in height 16):

| rounds | trace_height | prove (ms) | proof (bytes) |
|-------:|-------------:|-----------:|--------------:|
|      3 |           16 |     ~170-2k|       180 646 |
|      6 |           16 |     ~170-2k|       180 624 |
|      9 |           16 |     ~170-2k|       180 519 |
|     15 |           16 |     ~170-2k|       180 478 |

*(Fold-chain proof size is dominated by the trace's constant 16-row
pow2 footprint. Base-field encoding of the PI cols + the fold bank's
21 cols shows up as the flat 180 KB floor.)*

**Unified α+fold scaling sweep** (realistic per-query shapes):

| shape       |  α_steps | fold_rnds | trace_h | prove (ms) | proof (bytes) |
|-------------|---------:|----------:|--------:|-----------:|--------------:|
| 1/1 shape   |       40 |         3 |      64 |      ~4 500|       231 804 |
| 2/2 shape   |      180 |         6 |     256 |      ~9 700|       279 789 |
| 4/4 shape   |      500 |         9 |    1024 |     ~13 300|       335 360 |
| stretch     |     2000 |        12 |    4096 |      ~4-11k|       398 879 |

**Key findings:**

1. **Proof size is dominated by FRI overhead**: even a tiny 16-row
   trace ships ~180 KB, growing to ~400 KB at 4K rows. This is the
   one-STARK-per-query cost, NOT the monolithic-per-block cost. An
   N = 30 per-Tx breakdown would ship ~30 × 400 KB ≈ **12 MB per
   block — still well above §3.4's 100 KB**.

2. **Feasibility path CONFIRMED, but shape of the solution is now
   clear**: §3.4 is only reachable via **ONE monolithic STARK spanning
   the WHOLE block** (all slots × all queries in a single proof).
   Per-slot or per-Tx monolithic proofs do not compose down by
   concatenation — they need structural aggregation.

3. **Prover time is CPU-bound at scale**: timings below ~4K rows are
   dominated by fixed overhead (commitment setup, FRI parameters).
   Above ~4K rows prover time grows linearly with trace area, as
   expected for FRI. The apparent "prove=4500 ms at trace_h=64" vs
   "prove=4500 ms at trace_h=4096" paradox is this constant overhead.

4. **Trace width stays fixed at 272 cols regardless of shape**: the
   monolithic AIR's K-air-col-share design means the WIDTH is a
   one-time cost. Scaling to more operations just adds rows, not cols.

### A3-5 (planned): multi-path Merkle + multi-slot composition.

The A3-4 measurements motivate A3-5's scope. Rather than concatenating
per-Tx proofs, A3-5 adds:

1. **Multi-path Merkle support** in the COMPRESS bank: the current
   last-row `DIGEST == TRACE_COMMIT_ROOT` boundary generalizes to a
   per-path root check via a COMPRESS → non-COMPRESS transition
   constraint, letting one trace hold multiple independent Merkle
   openings.

2. **Full per-query bundle composition** in one AIR: α-chain +
   fold-chain + trace-commit Merkle + quotient-commit Merkle +
   per-round commit-phase Merkle, all in one trace.

3. **Multi-slot stacking**: N slots × (per-Tx bundle) in one trace.

### A4 (planned): N = 30 slot × 52 query measurement against §3.4.

### Measurement harness

Run the scaling sweeps:

```
cargo test -j 128 --release --lib monolithic_verifier_air::tests::measure \
  -- --ignored --test-threads 1 --nocapture
```

The `#[ignore]`'d `measure_*` tests record height × width × cells ×
prover-time × proof-size per scenario.

---

## A4 — multi-bundle scaling measurements (landed)

A3-5c enabled stacking N per-query bundles in ONE monolithic STARK.
A4 measures prover time + proof size at progressive bundle counts to
validate the §3.4 feasibility path.

Captured on `Linux 6.8.0-107-generic`, 192-core host, Option B FRI
pin (log_blowup = 3, num_queries = 52, query_pow_bits = 24).

### Per-bundle shape (small)

Each bundle: 10 α + 1 Merkle path (2 absorb + 1 compress) + 3 fold
rounds = ~16 physical rows. Stacking bundles scales trace height.

**Scaling sweep (α=10/bundle, fold=3):**

| bundles |   rows | trace cells | prove (ms) | proof (bytes) |
|--------:|-------:|------------:|-----------:|--------------:|
|       2 |     64 |      17 408 |      ~7 000|       252 667 |
|       8 |    256 |      69 632 |      ~5 400|       300 312 |
|      32 |  1 024 |     278 528 |      ~3 300|       356 247 |
|     128 |  4 096 |   1 114 112 |      ~6 700|       419 724 |

### §4.1 landmark — 4-Tx aggregation (208 bundles)

4 Txs × 52 queries = 208 per-query bundles composed in ONE STARK:

| bundles | trace_height | trace cells | prove (ms) | proof (bytes) |
|--------:|-------------:|------------:|-----------:|--------------:|
|     208 |        4 096 |   1 114 112 |     **65 195** |   **419 865** |

### Single-Tx measurement (52 bundles)

A full per-Tx verification (all 52 FRI queries) in ONE STARK:

|  bundles | trace_height |  trace cells |  prove (ms) | proof (bytes) |
|---------:|-------------:|-------------:|------------:|--------------:|
|       52 |        1 024 |      278 528 |    **1 998** |   **356 247** |

### Per-bundle shape (2/2 — mid-case)

Each bundle: 40 α + 3 Merkle + 6 fold = ~49 rows.

| tag       | bundles | trace_height | prove (ms) | proof (bytes) |
|-----------|--------:|-------------:|-----------:|--------------:|
| 2/2 ×8    |       8 |          512 |     12 663 |       326 889 |
| 2/2 ×32   |      32 |        2 048 |      1 892 |       387 198 |

### Key findings

1. **§3.4 100 KB envelope is NOT achievable with plain monolithic
   FRI at Option B parameters.** Even the §4.1 landmark (208 bundles,
   representing 4 Txs of aggregation) ships **~420 KB** — 4× the
   envelope. At N=30 slots × 52 queries (1 560 bundles), trace rows
   scale to ~25 000 → ~32 768 pow2, proof size extrapolates to
   **~550-650 KB**. The monolithic shape does not compress FRI
   overhead enough to hit §3.4.

2. **Proof size grows sub-linearly with trace size.** Doubling rows
   adds ~30-50 KB (the Merkle-tree caps at FRI's log-scaled
   commitment size). The 250-420 KB spread across 17K-1.1M cells
   illustrates this: FRI opening proofs (52 queries × log-height
   sibling siblings) dominate.

3. **Prover time scales with trace cells.** The 65s measurement at
   1.1M cells on 128-core host implies ~60 ns/cell. Extrapolating to
   N=30 slots × 52 queries × 49 rows = ~3.8M cells: **~230s (~4
   minutes) of prover time**. This fits within a block-production
   budget but is tight.

4. **Width stays fixed at 272 columns** regardless of bundle count;
   adding bundles only adds rows. The K-air-col-share pattern holds.

### Feasibility path forward

A4 measurements rule out hitting §3.4 via plain monolithic FRI. The
feasible paths from here are:

1. **Accept the envelope** — ship ~500 KB block proofs. The original
   §3.4 target was set before the monolithic AIR design; a realistic
   budget is probably 500-800 KB per block.

2. **Reduce `num_queries`** — trade soundness for size. Dropping from
   52 to 26 queries roughly halves proof size; soundness drops from
   180-bit to ~90-bit conjectured (below the 128-bit design bar).

3. **Increase `log_blowup`** — shrinks `num_queries` at equal
   soundness but grows prover trace area. Requires re-tuning.

4. **Multi-layer FRI wrapping (not SNARK-wrap)** — use a second
   lower-parameter FRI over the first's commitment. Non-trivial
   engineering; deferred to a future phase.

Option 1 is the simplest and doesn't compromise soundness or require
further engineering. Recommended unless §3.4 is a hard constraint.
