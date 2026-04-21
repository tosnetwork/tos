# Monolithic VerifierAir — Security Invariants (Audit Handoff)

> **v2 research scope.** Per the v1 pivot in
> `doc/uno-aggregation-design.md` §-1 (2026-04-21), UNO v1 launches
> **without** the monolithic VerifierAir this document specifies.
> The AIR code in `uno/plonky3-ffi/src/monolithic_verifier_air.rs`
> stays in-tree as frozen v2 research infrastructure; it is NOT on
> the v1 critical path. Schedule the third-party audit described
> below for v2 (when triggers in §-1 of the design doc light up),
> not v1. v1 audit scope is the per-Tx Transfer AIR already
> specified in the legacy plonky3-ffi modules.

**Source under review:** `uno/plonky3-ffi/src/monolithic_verifier_air.rs`
(5 359 lines at time of writing).
**Design rationale:** `doc/uno-aggregation-path-decision.md`.
**Phase breakdown:** `doc/uno-aggregation-design.md` §4.1.2, §4.1.3.
**Measurements:** `doc/uno-aggregation-metrics.md` §A3-4, §A4.

This document is the single handoff point for a third-party audit of
`MonolithicVerifierAirV1`. It lists what the AIR attests in-circuit,
which cross-binding gaps each sub-phase closed, what is deliberately
out of scope, and a pointed checklist the auditor can use as a gate.

---

## 1. Purpose

`MonolithicVerifierAirV1` is a **single Plonky3 AIR** that replaces
Phase A2's orchestrated bundle of 6+N per-query STARKs with ONE
constraint system. It attests that:

1. A set of Merkle leaves hash correctly via Poseidon2-w8
   (`PaddingFreeSponge<8, 4, 4>`) and the resulting leaf digest opens
   to a claimed root through a sequence of binary compressions.
2. A FRI commit-phase fold chain (binary Lagrange interpolation at a
   verifier-drawn challenge β) correctly reduces a running folded
   value across `num_commit_phase_rounds` rounds.
3. An α-batched quotient-combination chain computes
   `ρ_final = Σ αⁱ · (P(z) − P(x)) / (z − x)` over a sequence of
   polynomial openings.
4. Multiple such per-query "bundles" (α chain → Merkle paths →
   fold chain) can be stacked inside the same trace, each bundle
   carrying its own α, its own ρ_final, and its own expected
   final-folded value — and every bundle's seams are bound
   in-circuit so a malicious prover cannot mix values across bundles.
5. The aggregated proof is cryptographically bound to a declared
   block-level `BlockPublicInputs` (chain_id, block_seqno,
   anchor_seqno, n_transfers, tx_pi_merkle_root) via eight
   Goldilocks public-value columns.

It does **not** attest:

* Per-Tx ECDSA/Dilithium signatures — validator-side, off-AIR.
* Anchor-window membership — validator-side, off-AIR.
* Mempool pre-filter rules — off-AIR.
* Block header well-formedness (serialization, gas, fees) — off-AIR.
* The correctness of the **per-Tx Transfer AIR** itself. This AIR
  only verifies the FRI-level STARK proof chain produced by running
  `uno/plonky3-ffi/src/fri_verify.rs` over that Transfer AIR's
  commitment.

The AIR's soundness anchor is the Plonky3 uni-stark formulation at
`log_blowup = 3, num_queries = 52, query_pow_bits = 24` (Option B).

---

## 2. Column layout (normative)

Total width: `col::WIDTH = P2_BLOCK + POSEIDON2_COLS_PER_INSTANCE`
(180 for the Poseidon2 witness block → **272 columns**; pinned at
A3-PRE, asserted by `tests::column_layout_is_stable` at
`monolithic_verifier_air.rs:3055`).

| # | Group | Offset (symbolic) | Width | Purpose | Shared? |
|---|-------|-------------------|-------|---------|---------|
| 1 | Selectors (`KIND` one-hot) | `KIND0 … KIND_END` | 5 | One per row, disjoint: `ABSORB / COMPRESS / FOLD / ALPHA / IDLE` | — |
| 2 | ABSORB block | `ABSORB_BLOCK0 … ABSORB_BLOCK_END` | 4 (= RATE) | Per-row absorbed chunk | — |
| 3 | ABSORB block-len | `ABSORB_BLOCK_LEN` + `BLOCK_LEN_FLAG0…FLAG_END` | 1 + 5 | Weighted-sum-decoded one-hot over `{0,1,2,3,4}` | — |
| 4 | ABSORB first/last flags | `ABSORB_IS_FIRST`, `ABSORB_IS_LAST` | 2 | Absorb-chain boundary markers | — |
| 5 | COMPRESS current/sibling | `COMPRESS_CURRENT0…END`, `COMPRESS_SIBLING0…END` | 4 + 4 | Merkle step digests | **SIBLING[0..2] shared → FRI SIBLING** |
| 6 | COMPRESS index bit | `COMPRESS_INDEX_BIT` | 1 | Low bit of domain index | **shared → FRI INDEX_BIT** |
| 7 | Shared sponge/P2 I/O | `STATE_IN0…END`, `STATE_OUT0…END` | 8 + 8 | `STATE_OUT = P2(STATE_IN)` on ABSORB/COMPRESS; **STATE_IN[0..4] repurposed as FOLD PAIR_LEFT/RIGHT** on FOLD rows | **yes (K-air-col-share)** |
| 8 | Shared DIGEST | `DIGEST0…END` | 4 | STATE_OUT[0..4] on last ABSORB / every COMPRESS | yes |
| 9 | FOLD bank | `FOLD_BETA0…END`, `FOLD_S`, `FOLD_INV_2S`, `FOLD_IN0…END`, `FOLD_OUT0…END` | 2+1+1+2+2 | β, domain-coset s, witness inverse, folded-eval IN/OUT | — |
| 10 | ALPHA bank | `ALPHA_CHALLENGE0…END`, `ALPHA_POW_IN0/OUT0`, `ALPHA_P_AT_X`, `ALPHA_P_AT_Z0…`, `ALPHA_Z0…`, `ALPHA_X`, `ALPHA_QUOT_INV0…`, `ALPHA_DIFF_QUOT0…`, `ALPHA_RO_IN0/OUT0` | 21 | α-reduction step witness | — |
| 11 | PI-proxy cols (bundle-scoped) | `TRACE_COMMIT_ROOT0…END`, `QUOT_COMMIT_ROOT0…END`, `INITIAL_ALPHA_POW0…END`, `INITIAL_RO0…END`, `FINAL_FOLDED0…END`, `INITIAL_FOLDED0…END`, `FINAL_RO0…END` | 4+4+2+2+2+2+2 | Per-bundle seed/closure values; persist within a bundle, free to change at bundle boundaries | — |
| 12 | Block-PI (A6-1.6) | `BLOCK_PI_CHAIN_ID`, `BLOCK_PI_BLOCK_SEQNO`, `BLOCK_PI_ANCHOR_SEQNO`, `BLOCK_PI_N_TRANSFERS`, `BLOCK_PI_ROOT0…END` | 8 | **Block-level, not bundle-scoped**; bound to `builder.public_values()[0..8]` on row 0, unconditionally persisted elsewhere | — |
| 13 | Shared Poseidon2-w8 block | `P2_BLOCK … WIDTH` | 180 | `generate_trace_rows::<Goldilocks, …, 8, …>`; populated on every row, row-gated binding to STATE_IN / STATE_OUT | **yes (all hash rows bind it; other rows carry zero-input witness)** |

Column-share (K-air-col-share) is safe because the row-KIND selectors
are one-hot disjoint: any constraint from bank X is multiplied by
`is_X`, which is zero on non-X rows, so the shared column carries
orthogonal meaning across banks without cross-bank interference.

---

## 3. Constraint banks

The `impl<AB> Air<AB> for MonolithicVerifierAirV1 { fn eval(…) }`
body (`monolithic_verifier_air.rs:2356`) is organised bank-by-bank.
Each bank is row-gated; any constraint outside the bank's KIND
trivially vanishes.

### 3.1 KIND one-hot selector (L2375-L2381)

* **Claim.** Every row has exactly one active KIND; each KIND flag is
  boolean.
* **Formulae.** `kind[k] · (kind[k] − 1) = 0` (per k); `Σ kind[k] = 1`.
* **Degree.** 2.

### 3.2 ABSORB bank (A3-1; L2384-L2445)

* **Claim.** One PaddingFreeSponge absorb block for a leaf hash.
* **Gated by.** `is_absorb`.
* **Key constraints.**
  * `ABSORB_IS_FIRST`, `ABSORB_IS_LAST` boolean; both zero on
    non-ABSORB rows.
  * `BLOCK_LEN_FLAG[k]` boolean + one-hot + weighted-sum match
    `ABSORB_BLOCK_LEN`.
  * ABSORB ⇒ `BLOCK_LEN ≥ 1`; IDLE ⇒ `BLOCK_LEN = 0`; non-last
    ABSORB ⇒ `BLOCK_LEN = RATE`.
  * First-row rule: `STATE_IN[i] = cond_block_use[i] · BLOCK[i]` for
    `i<RATE`, zero for `i≥RATE` (capacity seeded to 0).
  * Last row equality: `DIGEST[0..4] = STATE_OUT[0..4]`.
* **Degree.** ≤ 3 (row-kind gate × polynomial).

### 3.3 COMPRESS bank (A3-1; L2448-L2472)

* **Claim.** One binary Merkle compression step.
* **Gated by.** `is_compress`.
* **Key constraints.**
  * `COMPRESS_INDEX_BIT` boolean.
  * `STATE_IN[0..4] = (1−bit)·CURRENT + bit·SIBLING`;
    `STATE_IN[4..8] = bit·CURRENT + (1−bit)·SIBLING`
    (orientation-correct concatenation of `[LEFT ∥ RIGHT]`).
  * `DIGEST = STATE_OUT[0..4]`.
* **Degree.** ≤ 3.

### 3.4 Shared Poseidon2-w8 sub-AIR (L2478-L2492)

* **Claim.** On any row where `hash_row := is_absorb + is_compress`,
  `STATE_OUT = P2(STATE_IN)` and the Poseidon2-w8 witness in
  `P2_BLOCK…WIDTH` is consistent with the generated Poseidon2 round
  trace.
* **Formulae.** `eval_poseidon2(builder, p2_local)` — the imported
  Plonky3 Poseidon2 constraint set, plus framing equalities
  `p2.inputs = STATE_IN` and `p2.post[0..8] = STATE_OUT` gated by
  `hash_row`.
* **Degree.** ≤ 7 (Poseidon2 S-box is `x⁷`). This is the dominating
  degree in the AIR; with `log_blowup = 3` the quotient degree budget
  is `2^3 = 8`, so 7 fits by one. `max_constraint_degree = None`
  (auto-compute — L2344).

### 3.5 FOLD bank (A3-2; L2632-L2707)

* **Claim.** One FRI fold round — binary Lagrange interpolation at β.
* **Gated by.** `is_fold`.
* **Key constraints.**
  * Shared `COMPRESS_INDEX_BIT` reasserted boolean under `is_fold`.
  * `STATE_IN[0..2] = (1−bit)·FOLD_IN + bit·SIBLING`;
    `STATE_IN[2..4] = bit·FOLD_IN + (1−bit)·SIBLING`.
  * INV_2S witness: `2·S·INV_2S = 1`.
  * Fold identity per extension limb
    `folded_i · 2s = s·(pl_i+pr_i) + β·(pl−pr)` (with the
    binomial-extension twist `W = 7`).
* **Degree.** ≤ 3 under the `is_fold` gate.

### 3.6 ALPHA bank (A3-2; L2710-L2778)

* **Claim.** One α-batched quotient-combination step.
* **Gated by.** `is_alpha`.
* **Key constraints.**
  * `QUOT_INV · (Z − X) = 1` (extension).
  * `DIFF_QUOT = (P_AT_Z − P_AT_X) · QUOT_INV`.
  * `ALPHA_POW_OUT = ALPHA_POW_IN · ALPHA`.
  * `RO_OUT = RO_IN + ALPHA_POW_IN · DIFF_QUOT`.
* **Degree.** ≤ 3 (extension multiplication × is_alpha gate).

### 3.7 IDLE

* **Claim.** No-op padding.
* **Effect.** On IDLE rows all bank gates are 0 → banks silent. The
  IDLE persistence constraint in §4 unconditionally carries the
  shared-state + PI-proxy columns across IDLE transitions.

### Row-kind disjointness

Because `Σ kind[k] = 1` and each `kind[k]·(kind[k]−1)=0`, the five
KINDs are mutually exclusive per row. Every bank constraint is gated
by a KIND factor (or derived product); any column value on a row
outside the bank's KIND is constrained only by the persistence /
cross-binding rules in §4, not the bank's arithmetic.

---

## 4. Cross-bindings (invariants that span banks)

This is the load-bearing audit surface. Each invariant listed here
closes a gap that A2's per-query orchestration held only "by
construction" (outside the STARK). Every entry: formal constraint,
what it prevents, sub-phase + provenance.

For the degree analysis: the design budget is **3 under
`log_blowup = 3`** (auto-quotient degree ≤ 8). Poseidon2's S-box
reaches degree 7, which is the one bank that eats into the budget;
every cross-binding below is engineered to stay at degree ≤ 3.

### I-1 — A3-1 leaf-digest bridge (ABSORB → COMPRESS)

* **Constraint** (L2543-L2551):
  `is_last · next_is_compress · (next.COMPRESS_CURRENT − local.STATE_OUT[0..4]) = 0`.
* **Prevents.** A malicious prover forging a "leaf hash" whose
  output does not match the first Merkle compression's `CURRENT`.
  This was A2's **construction gap #1**.
* **Provenance.** Phase A3-1; commit `749d40f26`.

### I-2 — A3-1 COMPRESS → COMPRESS digest threading

* **Constraint** (L2553-L2562):
  `is_compress · next_is_compress · (next.COMPRESS_CURRENT − local.DIGEST) = 0`.
* **Prevents.** Forging a Merkle path where an intermediate digest
  disagrees with the next step's input.
* **Provenance.** Phase A3-1.

### I-3 — A3-2 FOLD threading

* **Constraint** (L2787-L2791):
  `next_is_fold · (next.FOLD_IN − local.FOLD_OUT) = 0`.
* **Prevents.** Breaking fold-chain continuity — running two fold
  rounds whose outputs/inputs disagree.
* **Provenance.** Phase A3-2; commit `ade311647`.

### I-4 — A3-2 ALPHA threading (within a bundle)

* **Constraints** (L2802-L2815, with A3-5c gate):
  * `is_alpha · next_is_alpha · (next.ALPHA_POW_IN − local.ALPHA_POW_OUT) = 0`
  * `is_alpha · next_is_alpha · (next.ALPHA_RO_IN  − local.ALPHA_RO_OUT) = 0`
* **Prevents.** An intra-bundle α-chain that re-seeds its running
  `α^k` or `ρ` between adjacent α rows.
* **Provenance.** Phase A3-2, tightened in A3-5c to require `is_alpha`
  on the local side (so the bundle-seed check in I-12 can take over
  at bundle boundaries). Commit `30bbfc449`.

### I-5 — A3-3 direct α → FOLD bridge (FOLD_IN from ALPHA_RO_OUT)

* **Constraint** (L2859-L2866):
  `is_alpha · next_is_fold · (next.FOLD_IN − local.ALPHA_RO_OUT) = 0`.
* **Prevents.** A malicious prover seeding the fold chain with a
  value unrelated to the α chain's ρ_final. This was A2's
  **construction gap #2** — the α↔fold seam. Before A3-3, an
  aggregator could have two internally-consistent chains whose
  junction was trusted off-AIR.
* **Provenance.** Phase A3-3; commit `5a746851e`.

### I-6 — A3-3 non-α ALPHA_RO_OUT persistence

* **Constraint** (L2870-L2876):
  `(1 − next_is_alpha) · (next.ALPHA_RO_OUT − local.ALPHA_RO_OUT) = 0`.
* **Prevents.** `ALPHA_RO_OUT` drifting after the α chain ends but
  before the fold bridge (or the last-row boundary) reads it. Lets
  ρ_final thread through intervening Merkle / IDLE rows without
  leaving `is_alpha` gates.
* **Provenance.** Phase A3-3.

### I-7 — A3-3 non-fold FOLD_OUT persistence (gated by next-is-α in A3-5c)

* **Constraint** (L2891-L2899):
  `(1 − next_is_fold) · (1 − next_is_alpha) · (next.FOLD_OUT − local.FOLD_OUT) = 0`.
* **Prevents.** `FOLD_OUT` drifting through non-fold rows between the
  last FOLD row of a bundle and either (i) its `bundle_start` closure
  check, or (ii) the last-row boundary. The `(1 − next_is_alpha)`
  factor was added in A3-5c so FOLD_OUT is **free to reset at a
  bundle boundary** (non-α → α) but cannot drift elsewhere.
* **Provenance.** Phase A3-3, refined in A3-5c.

### I-8 — A3-5a in-run TRACE_COMMIT_ROOT persistence

* **Constraint** (L2509-L2517):
  `is_compress · next_is_compress · (next.TRACE_COMMIT_ROOT − local.TRACE_COMMIT_ROOT) = 0`.
* **Prevents.** The expected root drifting **within** one Merkle
  compression run — i.e. a prover claiming path steps for two
  different roots inside the same path.
* **Provenance.** Phase A3-5a; commit `75f77fa9f`.

### I-9 — A3-5a per-path root check at COMPRESS → non-COMPRESS

* **Constraint** (L2530-L2538):
  `is_compress · (1 − next_is_compress) · (local.DIGEST − local.TRACE_COMMIT_ROOT) = 0`.
* **Complement (when the trace's last row is itself COMPRESS)**
  (L2622-L2629):
  `last_is_compress · (DIGEST − TRACE_COMMIT_ROOT) = 0`.
* **Prevents.** Concluding a Merkle path with a digest that does not
  equal the claimed expected root. Replaces A3-1's one-root-per-trace
  boundary, enabling arbitrarily many independent paths each with
  their own root in one trace.
* **Provenance.** Phase A3-5a.

### I-10 — A3-5c bundle-boundary α closure

* **Constraint** (L2919-L2923):
  `bundle_start · (local.ALPHA_RO_OUT − local.FINAL_RO) = 0`,
  where `bundle_start := (1 − local_is_alpha) · next_is_alpha`.
* **Prevents.** A prover ending a bundle's α chain at a value other
  than its declared `FINAL_RO`. Without this check, the next
  bundle's α chain could be seeded independently of the declared
  ρ_final.
* **Provenance.** Phase A3-5c; commit `30bbfc449`.

### I-11 — A3-5c bundle-boundary fold closure

* **Constraint** (L2925-L2928):
  `bundle_start · (local.FOLD_OUT − local.FINAL_FOLDED) = 0`.
* **Prevents.** A bundle's fold chain closing at a different
  final-folded value than the one the proof declares.
* **Provenance.** Phase A3-5c.

### I-12 — A3-5c bundle-boundary α seed

* **Constraint** (L2930-L2933):
  `bundle_start · (next.ALPHA_POW_IN − next.INITIAL_ALPHA_POW) = 0`.
* **Prevents.** A new bundle starting its α chain from an arbitrary
  `α_pow`; the seed must match the declared `INITIAL_ALPHA_POW`.
* **Provenance.** Phase A3-5c.

### I-13 — A3-5c bundle-boundary RO seed

* **Constraint** (L2935-L2938):
  `bundle_start · (next.ALPHA_RO_IN − next.INITIAL_RO) = 0`.
* **Prevents.** A new bundle starting its α-batched running sum from
  an arbitrary value instead of `INITIAL_RO`.
* **Provenance.** Phase A3-5c.

### I-14 — A3-5c PI-proxy persistence (bundle-scoped)

* **Constraint** (L2831-L2835):
  `(1 − bundle_start) · (next.PI − local.PI) = 0` applied to every
  column in `[INITIAL_ALPHA_POW0 … FINAL_RO_END)`.
* **Prevents.** PI proxies (`INITIAL_ALPHA_POW`, `INITIAL_RO`,
  `FINAL_FOLDED`, `INITIAL_FOLDED`, `FINAL_RO`) drifting **within**
  a bundle. Combined with I-10..I-13 and row-0 boundaries, each
  bundle has a single set of PI proxies from start to close.
* **Note.** `TRACE_COMMIT_ROOT` / `QUOT_COMMIT_ROOT` are covered by
  the separate A3-5a in-run persistence (I-8) + the wider IDLE
  persistence (`STATE_IN0 … P2_BLOCK` at L2568-L2573), which carries
  them through IDLE padding.
* **Provenance.** Phase A3-5c.

### I-15 — A6-1.6 block-level PI binding

* **Status at time of writing.** **LANDED.** The source declares
  `fn num_public_values(&self) -> usize { col::NUM_BLOCK_PI_ELEMS }`
  (= 8) at L2336-L2341.
* **Constraints.**
  * **Row-0 pin** (L2996-L3008): for `i in 0..8`,
    `when_first_row: (local.BLOCK_PI[i] − public_values[i]) = 0`.
  * **Unconditional persistence** (L2954-L2958):
    for every column `c` in `BLOCK_PI_CHAIN_ID … BLOCK_PI_ROOT_END`,
    `trans: (next.c − local.c) = 0` — **no gating factor**, so these
    fire on every transition (including bundle boundaries and IDLE
    transitions).
* **Prevents.** A prover forging a valid-looking aggregated STARK
  whose declared public-inputs tuple
  `(chain_id, block_seqno, anchor_seqno, n_transfers, tx_pi_merkle_root)`
  does not match what the trace encoded on row 0. This binds the
  aggregated block proof to its block identity cryptographically.
* **Provenance.** Phase A6-1.6 (landed concurrently with this
  document). The eight-element encoding is produced by
  `aggregator::block_public_inputs_to_field_elements`.

### IDLE persistence envelope (support for I-3..I-7, I-14, I-15)

`next_is_idle · (next.c − local.c) = 0` for every column `c` in
`STATE_IN0 … P2_BLOCK` (L2568-L2573). This blanket rule makes the
IDLE row a transparent carrier of the shared state, so the above
threading invariants continue to hold across IDLE-padded regions
without dedicated gates per bank.

### Row-0 and last-row boundary conditions

* FOLD row-0 (`when_first_row`, L2971-L2975):
  `is_fold · (FOLD_IN − INITIAL_FOLDED) = 0`.
* ALPHA row-0 (L2979-L2987):
  `is_alpha · (ALPHA_POW_IN − INITIAL_ALPHA_POW) = 0` and
  `is_alpha · (ALPHA_RO_IN − INITIAL_RO) = 0`.
* BLOCK_PI row-0 (L3003-L3008): as in I-15.
* Last-row boundary for FOLD / ALPHA (L3022-L3031):
  `FOLD_OUT = FINAL_FOLDED`, `ALPHA_RO_OUT = FINAL_RO`.
* Last-row boundary for COMPRESS (L2622-L2629): if the trace's
  final row is COMPRESS, `DIGEST = TRACE_COMMIT_ROOT`.

---

## 5. Known gaps

### 5.1 PI binding status (A6-1.6)

**Status: LANDED.** At the time this document was written,
`MonolithicVerifierAirV1::num_public_values()` returns
`col::NUM_BLOCK_PI_ELEMS = 8` (L2336-L2341). The `BLOCK_PI_*`
columns (L219-L226) are wired with:

1. An unconditional persistence rule (L2954-L2958).
2. A `when_first_row` pin against `builder.public_values()[0..8]`
   (L2996-L3008).
3. A host-side encoding
   `aggregator::block_public_inputs_to_field_elements`
   producing the 8-element field tuple.

If the audit vendor observes `num_public_values = 0` in a future
build, I-15 is regressed and the block-identity binding reverts to
"trusted by caller".

### 5.2 "Trusted by construction" residuals

The source still describes two items as consumed off-AIR:

* **β and α challenges as PI.** The AIR takes `FOLD_BETA` and
  `ALPHA_CHALLENGE` as **trace columns**. A real FRI verifier must
  derive these from a Fiat-Shamir challenger. The A2 prototype had a
  `challenger_air`; the monolithic AIR does **not** re-prove the
  Fiat-Shamir transcript — the caller is responsible for binding
  these values to the challenger's transcript before constructing
  the trace. See `doc/uno-aggregation-metrics.md` §A2 "Known gaps".
* **Per-query domain indices / `x`.** Similarly, the
  `COMPRESS_INDEX_BIT` sequence and `ALPHA_X` values are witness
  inputs, not re-derived in-circuit from a commitment root. The
  caller must supply indices drawn from the challenger.

Both are **deliberate scope cuts**: the A3 decision (see
`doc/uno-aggregation-path-decision.md` §Rationale) deferred
challenger in-circuit binding beyond A3-5c. Any future phase that
re-enables a `challenger_air`-equivalent sub-bank must preserve the
column-layout pinning enforced by `tests::column_layout_is_stable`.

### 5.3 TODO / trusted-by comments present in source

A full `grep` for `TODO`, `trusted by`, and `FIXME` in
`monolithic_verifier_air.rs` turns up only doc-comments describing
closed A2 gaps (see header `//! Status` at L44-L54 and A3-3 preamble
at L2837-L2857). No active "TODO/trusted by" markers remain in
constraint code.

---

## 6. Test coverage

Total `#[test]`-annotated functions in `monolithic_verifier_air.rs`:
**48** (via `grep -c '^\s*#\[test\]'`).

Of these, 8 are `#[ignore]`'d measurement benches (not in the default
CI run; executed via `cargo test … -- --ignored`). The remaining 40
are default-run correctness tests — 14 positive, 13 adversarial, 13
layout/scaffold/regression; the table below maps every test to the
invariants it exercises.

### 6.1 Scaffold / layout (not tied to a specific invariant)

| Test (line) | Purpose |
|------|---------|
| `column_layout_is_stable` (3055) | Pins `col::WIDTH` and key offsets. |
| `trivial_trace_builds_any_pow2_height` (3069) | Trace builder shape gate. |
| `trivial_trace_rejects_non_pow2` (3077) | Trace builder error path. |
| `air_prove_and_verify_trivial_idle_trace` (3086) | A3-PRE scaffold round-trip (all-IDLE). |
| `air_rejects_broken_kind_onehot` (3100) | KIND one-hot (§3.1). |
| `print_column_layout` (3125) | Diagnostic. |

### 6.2 Positive + adversarial correctness (40 tests)

Each row is either P (positive) or A (adversarial). "Invariant(s)"
cites the §4 entries primarily exercised.

| Test (line) | Kind | Invariant(s) |
|------|:--:|---|
| `air_prove_and_verify_leaf_to_root_width_8_leaf_0` (3195) | P | I-1, I-2, I-9 |
| `air_prove_and_verify_leaf_to_root_all_tiny_leaves` (3213) | P | I-1, I-2, I-9 |
| `air_rejects_tampered_wide_leaf` (3232) | A | ABSORB bank (§3.2) + I-1 |
| `air_rejects_wrong_expected_root` (3260) | A | I-9 |
| `air_rejects_forged_bridge_between_absorb_and_compress` (3295) | A | **I-1** (A3-1 bridge) |
| `air_prove_and_verify_alpha_chain_3_steps` (3381) | P | §3.6 + I-4 + row-0/last-row boundaries |
| `air_prove_and_verify_alpha_chain_single_step` (3408) | P | §3.6 + row-0/last-row boundaries |
| `air_rejects_alpha_chain_wrong_final_ro` (3435) | A | Last-row boundary `ALPHA_RO_OUT = FINAL_RO` |
| `air_rejects_alpha_chain_tampered_p_at_x` (3469) | A | §3.6 (DIFF_QUOT cascade) |
| `air_prove_and_verify_fold_chain_3_rounds` (3504) | P | §3.5 + I-3 + row-0/last-row boundaries |
| `air_prove_and_verify_fold_chain_bit_orientation_cases` (3542) | P | §3.5 PAIR_LEFT/RIGHT orientation |
| `air_rejects_fold_chain_wrong_final_folded` (3570) | A | Last-row boundary `FOLD_OUT = FINAL_FOLDED` |
| `air_rejects_fold_chain_tampered_sibling` (3602) | A | §3.5 fold identity |
| `air_rejects_fold_chain_broken_inv_2s_witness` (3645) | A | §3.5 INV_2S witness |
| `a3_1_leaf_to_root_still_verifies_after_a3_2` (3681) | P/Reg | I-1..I-2 regression under A3-2 rules |
| `air_prove_and_verify_unified_alpha_to_fold_chain` (3708) | P | **I-5** (α→FOLD bridge), I-6, I-7 |
| `air_rejects_unified_tampered_alpha_to_fold_bridge` (3756) | A | **I-5** |
| `air_rejects_unified_tampered_alpha_chain` (3806) | A | §3.6 + I-6 |
| `air_rejects_unified_tampered_alpha_ro_out_on_fold_row` (3853) | A | **I-6** |
| `a3_1_and_a3_2_still_verify_after_a3_3` (3908) | P/Reg | Regression across A3-1/A3-2 shapes |
| `air_prove_and_verify_two_paths_same_tree` (4218) | P | **I-8**, **I-9** |
| `air_prove_and_verify_two_paths_different_roots` (4256) | P | **I-8**, **I-9** |
| `air_rejects_multi_path_with_swapped_root` (4319) | A | **I-9** |
| `air_rejects_multi_path_tcr_drifts_mid_run` (4405) | A | **I-8** |
| `air_prove_and_verify_bundle_alpha_1merkle_fold` (4451) | P | Bundle: I-1..I-9 composed |
| `air_prove_and_verify_bundle_alpha_2merkle_fold` (4508) | P | Bundle with 2 paths (trace+quot commit shape) |
| `air_rejects_bundle_tampered_merkle_sibling` (4579) | A | I-9 inside a bundle |
| `air_rejects_bundle_tampered_alpha` (4638) | A | §3.6 cascade inside a bundle |
| `air_rejects_bundle_tampered_fold_sibling` (4692) | A | §3.5 inside a bundle |
| `air_prove_and_verify_two_bundles_different_alpha` (4772) | P | **I-10..I-14** multi-bundle stacking |
| `air_rejects_two_bundles_tampered_final_ro_mid_bundle` (4852) | A | **I-14** PI persistence |
| `air_rejects_bundle_boundary_bad_alpha_pow_seed` (4917) | A | **I-12** |
| `air_rejects_bundle_boundary_bad_final_folded_close` (4990) | A | **I-11** |
| `a3_3_and_a3_5b_still_verify_after_a3_5c` (5069) | P/Reg | Full regression under A3-5c's gated rules |

**Counts.**
* Positive (including regression): **22** (including 6 scaffold/layout).
* Adversarial: **13**.
* Ignored measurements: **8**.
* Total `#[test]`: 48 (22 + 13 + 8 = 43; balance of 5 are the
  scaffold tests `column_layout_is_stable`,
  `trivial_trace_builds_any_pow2_height`,
  `trivial_trace_rejects_non_pow2`, `air_prove_and_verify_trivial_idle_trace`,
  `air_rejects_broken_kind_onehot`, `print_column_layout`).

### 6.3 Scaling measurements (#[ignore]'d)

These tests are not run by default; they populate the numeric tables
in `doc/uno-aggregation-metrics.md`. Most-recently-captured numbers
(cross-referenced from the metrics doc):

| Test (line) | Shape | Trace height | Prove (ms) | Proof (bytes) |
|-------------|-------|-------------:|-----------:|--------------:|
| `measure_unified_alpha_fold_realistic_scale` (4040) | 4/4 shape | 1 024 | ~13 300 | 335 360 |
| `measure_alpha_chain_scaling_sweep` (4080) | α-only sweep | 64 / 256 / 1 024 / 4 096 | ~4 500 / ~8 000 / ~13–36 k / ~4–11 k | 222 219 … 389 597 |
| `measure_fold_chain_scaling_sweep` (4117) | fold-only | constant 16 | ~170–2 000 | 180 478 … 180 646 |
| `measure_unified_alpha_fold_scaling_sweep` (4163) | α + fold 1/1 … stretch | 64 … 4 096 | ~4 500 … ~4–11 k | 231 804 … 398 879 |
| `measure_multi_bundle_one_tx_52q` (5309) | 1 Tx = 52 bundles | 1 024 | **1 998** | **356 247** |
| `measure_multi_bundle_n4_208bundles` (5320) | §4.1 landmark — 4 Txs = 208 bundles | 4 096 | **65 195** | **419 865** |
| `measure_multi_bundle_scaling_sweep` (5331) | 2 … 128 bundles | 64 … 4 096 | ~3 300 … ~7 000 | 252 667 … 419 724 |
| `measure_multi_bundle_2_2_shape_per_bundle` (5350) | 2/2 bundles ×8/×32 | 512 / 2 048 | 12 663 / 1 892 | 326 889 / 387 198 |

See `doc/uno-aggregation-metrics.md` §A3-4 + §A4 for full tables
and the N=30 extrapolation (~550–650 KB / ~4 min) that drove the
§4.3 fallback decision.

---

## 7. Out-of-scope

This AIR does **not** attest — and the audit should treat the
following as verified elsewhere (or not at all, where noted):

1. **Per-Tx signatures** (ECDSA / Dilithium). Validators check
   these off-AIR during `§4.3` block verification.
2. **Anchor window membership** for Transfer inputs. Likewise
   validator-side, against `AnchorState`.
3. **Mempool pre-filter rules** (gas, size caps,
   duplicate-nullifier rejection). Pre-AIR.
4. **Block header well-formedness** — serialization, parent-hash,
   gas accounting, fee math. Handled by the workchain's native
   block validator, not this AIR.
5. **Fiat-Shamir transcript derivation** of `α` and `β`. See §5.2
   — the AIR takes these as witness columns; the caller must
   bind them to a real challenger outside this AIR. A future
   phase may re-integrate a `challenger_air`-style sub-bank.
6. **The per-Tx Transfer AIR's own constraints.** This AIR only
   verifies the FRI proof stream; the Transfer AIR has its own
   audit surface (`uno/plonky3-ffi/src/transfer_air.rs`).
7. **Poseidon2-w8 round constants and linear-layer matrices.**
   Imported from Plonky3 upstream
   (`p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_8_*`,
   `GenericPoseidon2LinearLayersGoldilocks`). Consider these a
   cryptographic dependency outside this document's scope.

---

## 8. Suggested audit queries

The following pointed questions are designed as the audit's
pass/fail checklist. Each references concrete line numbers in
`uno/plonky3-ffi/src/monolithic_verifier_air.rs`.

1. **Confirm that** KIND one-hot plus the per-bank `is_X` gating
   yields strict row-kind disjointness and that **no** constraint in
   any bank (§3.2–§3.6) fires on a row outside its KIND (L2375-L2381
   and each bank's `is_X ·` prefix).

2. **Confirm that** the leaf-digest bridge (I-1, L2543-L2551) fires
   at **every** transition from a `IS_LAST` ABSORB row to a COMPRESS
   row — including edge cases where a single-block absorb row is
   immediately followed by a compress, and where multi-block absorbs
   terminate exactly at `ABSORB_IS_LAST`.

3. **Confirm that** A3-5a's in-run TCR persistence (I-8) and the
   per-path root check (I-9) together make it impossible to end a
   Merkle run at a digest different from the path's declared root,
   whether the trace's terminal row is a COMPRESS or an IDLE (L2509-L2538
   and the `when_last_row` boundary at L2622-L2629).

4. **Confirm that** A3-3's α→FOLD bridge (I-5) is unavoidable: any
   trace path where a FOLD row succeeds an ALPHA row must satisfy
   `next.FOLD_IN = local.ALPHA_RO_OUT`. Trace the interaction with
   I-4 (the α→α threading was narrowed in A3-5c so it does not
   preempt I-5).

5. **Confirm that** the `bundle_start := (1 − local_is_alpha) ·
   next_is_alpha` predicate (L2829) correctly triggers at **every**
   non-α → α transition (including IDLE → α, FOLD → α,
   COMPRESS → α, ABSORB → α) and at **no** other transition.

6. **Confirm that** bundle-boundary closure (I-10, I-11) combined
   with PI persistence (I-14) forces each bundle's `(INITIAL_*,
   FINAL_*)` tuple to match its intra-bundle α / fold chain output.
   In particular, verify the degree-3 budget: `bundle_start` is
   degree 2; the diff is degree 1; total 3 (L2917-L2918).

7. **Confirm that** A6-1.6 block-PI persistence (I-15) is
   **unconditional** — no KIND gating, no `bundle_start` gating —
   and that the 8 public-value pins in `when_first_row` (L3003-L3008)
   propagate to every row via that persistence. `num_public_values`
   must return 8 (L2336-L2341).

8. **Confirm that** the shared Poseidon2-w8 witness block
   (`P2_BLOCK … WIDTH`) is constrained only on hash rows
   (`is_absorb + is_compress`, L2481-L2492), and that on FOLD /
   ALPHA / IDLE rows the `p2_local` evaluation is **decoupled**
   from the framing columns (no cross-contamination via STATE_IN
   shared with PAIR_LEFT/RIGHT on FOLD).

9. **Confirm that** degree-3 is preserved globally except for the
   Poseidon2 S-box (degree 7), and that with `log_blowup = 3` the
   quotient-domain budget (auto-computed by `max_constraint_degree
   = None`) accommodates both.

10. **Confirm that** the **out-of-scope** items in §7 — particularly
    β/α challenge derivation, domain indices, and the per-Tx
    Transfer AIR — are actually covered elsewhere in the audit
    scope; the monolithic AIR's soundness story **assumes** these.

---

*Document written against the `uno` branch at the time of the
monolithic-AIR A3 series completion (A3-PRE through A3-5c) and
A6-1.6 PI binding landing. Last-commit landmarks: `30bbfc449`
(A3-5c), `f472e4ad1` (A4), `5a9d942a3` (A5 part 1).*
