# Uno Aggregation — Feasibility Path Decision

**Date:** 2026-04-27
**Status:** Decision — work under way (A3-PRE scaffolding).

## Context

Phase A2 (see `doc/uno-aggregation-design.md` §4.1 and
`doc/uno-aggregation-metrics.md`) landed a PoC in-circuit FRI
verifier as **orchestrated independent STARKs** — 6 + `num_rounds`
proofs per query, each verifying one sub-operation (α-reduction,
fold, leaf-hash, compression, commit-phase Merkle × N).

This works end-to-end on real 1/1 Transfer proofs (9-STARK bundle at
1/1, 12 at 2/2, 15 at 4/4 — verified by `full_query_verifier_accepts_all_chains_1_1_query_0`),
but the **proof size and prover time scale badly**:

- Naive extrapolation to N=30 slots × 52 queries × ~10 STARK/query =
  **~15,000 STARK proofs per block** at ~25 KB each = ~390 MB block
  proof. Well above the **§3.4 ≤100 KB envelope**.

The question for A3+ is how to collapse the orchestration into a
single proof that meets §3.4.

## Options considered

### Option 1 — Monolithic VerifierAir with K-air-col-share

Encode every sub-operation in ONE AIR trace via row-loop + shared
columns (Poseidon2 block, extension-mult lane, etc.). Selectors gate
which constraint bank each row activates. Same pattern as
`transfer_air`'s multi-claim AIR (claim 1/anchor, claim 2/spend Cm,
claim 3/IvkCm, claim 4/Nf, claim 5/u64, claim 6/output Cm, claim 7/ivk,
claim 8/balance, claim 9/range).

**Column budget** (estimate): ~250 cols per row.
- ~40 framing (selectors + threaded state + public-input proxies)
- 180 shared Poseidon2-w8 block
- ~30 extension-mult lane + misc

**Trace height** (per per-Tx STARK verification): ~21,000 rows
(52 queries × ~400 ops per query with heavy sharing).
**Cells per per-Tx verification: ~5M**.

**For N=30 aggregation**: 30 × 5M ≈ 150M cells. At log_blowup=3,
FRI trace domain is ~1.2B cells ≈ 10 GB memory. Large but
tractable with streaming + memory-mapped commits.

Prover time estimate: ~30-60 min on 128-core machine at N=30. Tight
but within collator-side budget.

### Option 2 — STARK recursion / PCD

Each query's 6+N inner STARKs get wrapped by an outer STARK that
verifies them (using our existing verifier-as-AIR from A2). The
outer STARK's proof ships on-chain at ~100 KB.

**Problem**: the outer STARK STILL needs to encode the verifier-AIR
for each of the 15000 sub-proofs. The outer trace is THE SAME size
as Option 1's monolithic trace — the recursion doesn't save work,
it just adds a layer of indirection.

PCD (proof-carrying data) could amortize by recursing 2-3 levels
deep, but each additional level adds a verifier-AIR worth of rows.
Given our sub-STARKs are already small, the recursion overhead
exceeds the savings.

**Verdict**: recursion helps when inner proofs are very large AND
few; our use case has many small inner proofs, inverted for recursion.

### Option 3 — SNARK-wrap the outer STARK

Use a small-field SNARK (e.g., Groth16, Plonky2) to wrap the final
STARK, shrinking to ~1 KB.

**Blocker**: violates **§0.2 (PQ-native)** — Groth16 and most small
SNARKs require a trusted setup, and their pairing curves are
Shor-breakable. Rejected per the original v1 invariants.

### Option 4 — Bigger FRI blowup + fewer queries

Reduce `num_queries` aggressively (e.g., from 52 to 16) to shrink the
trace. Blocks at §2.1 Option B's 180-bit soundness floor.

**Blocker**: would drop below the 128-bit soundness design bar
unless blowup is raised dramatically, which costs proof size
elsewhere. The §2.1 Option B pin is already the soundness/size
frontier.

## DECISION: Option 1 (Monolithic VerifierAir + K-air-col-share)

### Rationale

1. **Proven pattern**: `transfer_air` already uses K-air-col-share
   for its 9 claims sharing two Poseidon2 blocks (w8 for claims 3/4,
   w16 for claims 2/6). The aggregator's verifier-AIR is structurally
   identical but at larger scale.

2. **No soundness compromise**: the monolithic AIR's constraints are
   literally the same as A2's orchestrated sub-AIRs, just with
   in-circuit cross-bindings instead of bundle-level.

3. **Closes the A2 cross-binding gap**: the "trusted by construction"
   boundaries between α, fold, and Merkle sub-AIRs become
   `builder.assert_eq` on shared public-input columns. Soundness
   goes from PoC-grade to production-grade.

4. **Leverages all A2 work**: each sub-AIR's constraint derivations
   (degree analysis, Poseidon2 bindings, α-combine arithmetic,
   fold-row identity) port directly as constraint banks in the
   unified AIR. No redesign needed.

5. **Feasible at N=30**: trace area estimate (~150M cells) sits at
   the frontier of what Plonky3 handles today on 128-core hardware.
   Within the A4 benchmarking window.

### Trade-offs accepted

- **Audit complexity**: one big AIR is harder to review than 10
  small ones. Mitigation: the monolithic AIR is a syntactic fusion
  of the A2 sub-AIRs that are already independently audited.
- **Column width growth**: 250 cols per row is larger than any
  existing Uno AIR. Mitigation: Plonky3's FRI is linear in trace
  width, and 250 cols sits well within the published comfort zone
  for the stack.
- **Memory pressure at N=30**: ~10 GB FRI tree. Mitigation:
  `TwoAdicFriPcs` supports streaming commits; prover-side memory
  can be controlled via `CARGO_TARGET_MEMLIMIT`-style knobs.

## Implementation plan (A3)

Incremental rollout, each step runnable + testable:

### A3-PRE (this commit): scaffolding

- Create `src/monolithic_verifier_air.rs` with column-layout constants
  + selector bank + empty `Air<AB>` skeleton.
- Pin the layout so follow-up sub-phases can reference stable offsets.
- Dummy trace builder + checker that produce a trivial valid trace
  (single IDLE row) to prove the scaffolding compiles.

### A3-1: ABSORB + COMPRESS banks migration

- Port `leaf_hash_air` (ABSORB rows) and `compression_path_air` (COMPRESS
  rows) into the monolithic AIR. Both use the shared P2 block, gated
  by KIND selectors.
- End-to-end test: one Merkle path (leaf → root) verifies via ONE
  STARK proof on the monolithic AIR, replacing the two STARKs
  `leaf_hash + compression_path` produced.

### A3-2: FOLD + ALPHA banks migration

- Port `fold_air` (FOLD rows) and `alpha_reduction_air` (ALPHA rows)
  into the monolithic AIR with a shared extension-mult lane.
- End-to-end test: α-reduction → fold chain verifies via ONE STARK,
  replacing the two STARKs from A2's d-6.

### A3-3: Cross-bindings ✅

Landed: three in-circuit constraints close A2's "trusted-by-construction"
gap at the α/fold seam:

1. Direct α→FOLD bridge: `is_alpha · next_is_fold · (next.FOLD_IN −
   local.ALPHA_RO_OUT) = 0` threads ρ_final in-circuit from the last
   ALPHA row to the first FOLD row.
2. ALPHA_RO_OUT persistence on non-α transitions propagates ρ_final
   through FOLD + IDLE rows to the last-row boundary
   `ALPHA_RO_OUT == FINAL_RO`.
3. FOLD_OUT persistence on non-fold transitions propagates the fold
   chain's terminal value to `FOLD_OUT == FINAL_FOLDED`.

(The ABSORB→COMPRESS leaf-digest bridge was already closed in A3-1.)

Acceptance test (`air_prove_and_verify_unified_alpha_to_fold_chain`):
one STARK proof verifies a trace that runs α-reduction followed by
fold, with the α output seeding the fold input through in-circuit
constraints. Adversarial test
`air_rejects_unified_tampered_alpha_to_fold_bridge` tampers the first
fold row's FOLD_IN — the bridge constraint fires and the proof
rejects. Two additional adversarial tests cover α-chain tampering and
non-α persistence violation.

### A3-4: Scaling measurements (landed — partial)

Landed: four `#[ignore]`'d measurement tests in
`monolithic_verifier_air.rs::tests::measure_*` that record prover
time and proof size at realistic scales. See
`doc/uno-aggregation-metrics.md` §A3-4 for the full numeric table.

**Empirical finding**: at realistic per-query shapes (α_steps ≈ 500,
fold_rounds = 9, trace_height ≈ 1024), one monolithic-AIR STARK per
query ships ~335 KB. Scaled naively to N = 30 slots × 52 queries,
this lands at ~12 MB/block — still orders of magnitude above §3.4's
100 KB envelope.

**Shape of the §3.4-compliant solution is now clear**: one monolithic
STARK must span the WHOLE block (all slots × all queries in a single
proof). Per-slot or per-Tx monolithic proofs don't compose down by
concatenation.

**Deferred to A3-5** (the per-Tx bundle + multi-slot work was
originally scoped as part of A3-4 but requires structural changes to
the COMPRESS bank — see A3-5 below).

### A3-5a: Multi-path Merkle in the COMPRESS bank (landed)

Generalized the A3-1 one-path-per-trace boundary to support arbitrarily
many independent Merkle openings in a single monolithic trace:

- **Removed**: A3-1's unconditional TRACE_COMMIT_ROOT persistence
  (which locked the trace into a single root).
- **Added**: TRACE_COMMIT_ROOT persists WITHIN a COMPRESS run via
  `is_compress · next_is_compress · (next.TCR − local.TCR) = 0`.
- **Added**: Per-path root check at each COMPRESS → non-COMPRESS
  transition: `is_compress · (1 − next_is_compress) · (DIGEST − TCR)
  = 0`. Fires once per path, at the path's terminal row.
- **Gated**: The last-row root boundary is now `is_compress · (DIGEST
  − TCR)`, a no-op on IDLE-padded last rows.

Acceptance tests (`air_prove_and_verify_two_paths_same_tree` and
`air_prove_and_verify_two_paths_different_roots`): two independent
Merkle openings — from the same tree, and from different trees with
distinct roots — verify in ONE monolithic STARK.

Adversarial tests: swapping per-path roots rejects at the per-path
check; TCR drift within a compression run rejects at the in-run
persistence constraint.

### A3-5b: Full per-query bundle composition (landed)

Composes α-reduction chain + N independent Merkle paths + FRI fold
chain into ONE monolithic STARK via
`build_alpha_merkle_fold_bundle_trace`.

Key result: **no new constraints were required**. A3-3's non-α
`ALPHA_RO_OUT` persistence and non-fold `FOLD_OUT` persistence thread
ρ_final from the last ALPHA row through all Merkle rows into the
last pre-fold row's `FOLD_OUT`. The A3-2 FOLD threading transition
(`next_is_fold · (next.FOLD_IN − local.FOLD_OUT) = 0`) then reads
that `FOLD_OUT` into first-FOLD's `FOLD_IN`, seeding the fold chain
with ρ_final in-circuit.

Acceptance tests:
- `air_prove_and_verify_bundle_alpha_1merkle_fold` — bundle with 1
  Merkle path (e.g. trace-commit only).
- `air_prove_and_verify_bundle_alpha_2merkle_fold` — bundle with 2
  paths carrying different roots (mirrors the trace-commit + quot-
  commit pair in one per-query bundle).

Adversarial tests:
- `air_rejects_bundle_tampered_merkle_sibling` — per-path check fires.
- `air_rejects_bundle_tampered_alpha` — DIFF_QUOT/RO cascade rejects.
- `air_rejects_bundle_tampered_fold_sibling` — fold orientation fires.

### A3-5c: Multi-bundle stacking (landed)

Stacks N per-query bundles in one trace via
`build_multi_bundle_trace`. Each bundle carries its OWN α challenge,
α_steps, Merkle roots, ρ_final, and FINAL_FOLDED — the three
constraint relaxations and three new transitions below let PI proxies
change across bundle boundaries while preserving soundness within
each bundle.

**Constraint changes:**

1. PI-proxy persistence (A3-2, originally unconditional across all
   transitions) is now gated by `1 − bundle_start`:
   ```
   (1 − bundle_start) · (next.PI − local.PI) = 0
   bundle_start = (1 − local_is_alpha) · next_is_alpha
   ```
   PI proxies persist within bundles; free at bundle boundaries.

2. Non-fold `FOLD_OUT` persistence (A3-3) now also skips bundle
   boundaries: `(1 − next_is_fold) · (1 − next_is_alpha) · diff = 0`.
   Lets FOLD_OUT reset on non-α → α transitions.

3. ALPHA threading (A3-2, originally fired on all → α transitions)
   now fires only on α → α: `is_alpha · next_is_alpha · diff = 0`.
   Bundle-seed check takes over at non-α → α transitions.

**Added constraints (all degree 3):**

1. `bundle_start · (local.ALPHA_RO_OUT − local.FINAL_RO) = 0`
   Previous bundle's α chain closed.

2. `bundle_start · (local.FOLD_OUT − local.FINAL_FOLDED) = 0`
   Previous bundle's fold chain closed.

3. `bundle_start · (next.ALPHA_POW_IN − next.INITIAL_ALPHA_POW) = 0`
   New bundle's α chain seeded.

4. `bundle_start · (next.ALPHA_RO_IN − next.INITIAL_RO) = 0`
   New bundle's RO chain seeded.

**Tests (5 new):**

Positive:
- `air_prove_and_verify_two_bundles_different_alpha` — two bundles
  with different α challenges, different Merkle trees, different
  ρ_final, and different final_folded in ONE STARK.

Adversarial:
- `air_rejects_two_bundles_tampered_final_ro_mid_bundle` — FINAL_RO
  drift within a bundle rejects via A3-5c PI persistence.
- `air_rejects_bundle_boundary_bad_alpha_pow_seed` — forged
  ALPHA_POW_IN at bundle boundary rejects via seed check (c).
- `air_rejects_bundle_boundary_bad_final_folded_close` — forged
  FOLD_OUT on prev bundle's last FOLD rejects (fold identity cascade
  + close check).

Regression:
- `a3_3_and_a3_5b_still_verify_after_a3_5c` — A3-3 unified trace +
  A3-5b single-bundle still pass under relaxed persistence.

This completes the original §4.1 "4-Tx aggregation" foundation at
small scale (demonstrated with N=2). Scaling to N=4 slots × 52
queries each (208 bundles per trace) is a mechanical repetition
unblocked by A3-5c's constraint machinery.

### A4: Multi-bundle scaling measurements against §3.4 (landed)

A4 measured the A3-5c multi-bundle shape at progressive scales; full
numbers in `doc/uno-aggregation-metrics.md` §A4.

**Headline numbers:**

| shape                             | prove   | proof size |
|-----------------------------------|---------|------------|
| 1 Tx = 52 bundles                 | ~2 s    | **356 KB** |
| 4 Txs = 208 bundles (§4.1 mark)   | ~65 s   | **420 KB** |
| N=30 extrapolation (1 560 bundles)| ~4 min  | ~550-650 KB|

**Decision**: §3.4's 100 KB envelope is **NOT achievable** with the
plain monolithic FRI at Option B parameters. Even the §4.1 landmark
(4-Tx aggregation) ships ~420 KB — 4× over envelope. This is driven
by FRI opening-proof overhead (52 queries × log-height siblings per
query × ~10 bytes/sibling), which scales with log(trace_height) not
trace size itself, and cannot be compressed further without soundness
loss.

**Forward path**: §4.3 fallback — accept a realistic block-proof
budget of ~500-800 KB, OR reduce `num_queries` below 52 (drops
soundness below the 128-bit design bar).

The monolithic-AIR design itself is sound and complete across the A3
series — all cross-binding gaps closed, all bank constraints
composable, multi-bundle stacking works. What A4 showed is that the
§3.4 envelope was set before the monolithic design existed; a
realistic budget given the FRI shape is 500-800 KB.

### A5+ (planned): wire format + validator integration

Assumes accepted block-proof budget (~500-800 KB via §4.3 fallback).
A5 formalizes the proof wire format; A6+ wires validators and wallets
to consume monolithic-AIR proofs end-to-end.

## Open questions (not blocking A3)

1. **Periodic columns** vs **shared P2 blocks**: Plonky3 supports
   periodic columns for constant tables that repeat every N rows.
   Could reduce round-constant cost if the aggregator has a regular
   selector pattern. Orthogonal optimization; revisit at A3-4
   measurement.

2. **LogUp lookups**: `doc/uno-air-optimization-log.md` C7 documents
   why we can't use LogUp under uni-stark today. If that changes
   upstream (batch-stark migration — `doc/uno-p2-path-research.md`
   Path iii), range-check cost drops ~3×. Out of scope for A3 but
   mentioned for future A6+ polish.

3. **Column packing** via `Algebra<F>::Packing`: not used yet in any
   Uno AIR. Could double throughput on x86 with AVX-512. Revisit
   at A4 if prover time is the bottleneck.

## Summary

**Go**: Option 1 (Monolithic VerifierAir with K-air-col-share).
**Start**: A3-PRE scaffolding (this commit).
**Deadline gate**: A4 30-Tx measurement against §3.4 ≤100 KB.
**Fallback**: §4.3 pre-launch options if A4 misses envelope.
