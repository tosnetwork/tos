# Uno Transfer AIR — Optimization Experiment Log

This document is the canonical record of every AIR column-reduction and
proof-size optimization experiment run on the Uno Transfer AIR
(`uno/plonky3-ffi/src/transfer_air.rs`) during P.2. Its purpose is:

1. **Preserve the reasoning behind negative results** so future
   contributors don't re-investigate strategies already proven non-viable.
2. **Record the load-bearing constraints** discovered empirically that
   constrain all future AIR work.
3. **Enumerate the remaining paths** with a clear picture of what each
   buys and what it doesn't.

If you are about to optimize the Transfer AIR, read this document first.
If your idea is not already in the "remaining paths" section, check
whether it matches one of the already-rejected strategies below before
investing a cryptographer-week.

---

## 1. Current state (as-of commit `dd0383b69`, 2026-04-20)

Measured by `cargo bench --bench shape_matrix` on a representative
8-core x86 host (Ryzen 7950X-class, Linux, release build, single-thread):

| Shape | Cols  | PI bytes | Prove ms | Verify ms | Proof bytes |
|-------|------:|---------:|---------:|----------:|------------:|
| 1/1   |   917 |      200 |       62 |        29 |   1,198,931 |
| 1/2   |   987 |      272 |       78 |        31 |   1,223,642 |
| 2/2   | 1,305 |      336 |       79 |        38 |   1,500,317 |
| 2/3   | 1,375 |      408 |      124 |        40 |   1,536,344 |
| 3/3   | 1,693 |      472 |      100 |        49 |   1,835,246 |
| 4/4   | 2,081 |      608 |      196 |       109 |   2,131,583 |

**§3.4 production envelope goal**: ~52 KB typical / ~100 KB worst, verify ≤ 20 ms single-thread.

**Distance at worst case (4/4)**: proof is 22.4× over envelope; verify is 5.5× over.
**Distance at common case (1/2)**: proof is 12× over envelope; verify is 1.5× over.

The worst case is the bottleneck; the common case is already close.

Reproduce:

```bash
cd uno/plonky3-ffi
cargo bench --bench shape_matrix
```

---

## 2. Experiment chronology

Each row records one attempt, its agent tag, the commit (or "reverted" /
"no-commit"), and the one-line outcome. Full details follow the table.

| # | Agent tag                 | Commit        | Strategy                                     | Outcome                                                                                    |
|---|---------------------------|---------------|----------------------------------------------|--------------------------------------------------------------------------------------------|
| 1 | K-air-col-share           | `05bb3197a`   | (a) Merkle-level row-loop (w=8, 32 rows)     | ✅ 4/4 cols 27,837 → 5,553 (−80 %); proof 33 MB → 6.46 MB; verify 790 → 148 ms             |
| 2 | K-air-col-step2           | `8e763c38d`   | (b) claim-2 / claim-6 wide Poseidon2 reuse + (c) claim-3 / claim-4 narrow reuse | ✅ 4/4 cols 5,553 → 2,081 (additional −62.5 %); proof 6.46 MB → 2.22 MB; verify 148 → 111 ms |
| 3 | K-air-col-step3           | no commit     | (e) tight shape alloc; (f) trace-height tuning | ❌ Neither clears 15 % threshold. Trace-height tuning yields 2–4 % proof shrink only.      |
| 4 | K-air-scheduler           | no commit     | Cross-instance Poseidon2 row-doubling        | ❌ Math proof: at `num_queries=128`, adding 180 cols costs +184 KB, halving trace saves only 12 KB. Net **grow** ~8 %. |
| 5 | K-air-bench               | `6cad7c347`   | Shape-matrix benchmark harness               | ✅ Reproducible 6-shape measurements; basis for all future deltas.                         |
| 6 | K-fri-analysis            | `dd0383b69`   | Sweep 15 FRI configurations                  | ✅ Best sweep data-point is 5.5× over envelope; identified 3 frontier configs + 3 hard findings. |
| 7 | K-air-fold-outputs        | no commit     | Row-cycle OUTPUT_PROXY_COLS into a global shared block | ❌ Works functionally (all tests pass) but yields only −3.19 % proof shrink at 4/4 vs −10 % predicted by C1. **Finding: C1's "~1 KB per col" upper bound overstates reality by 3×; actual empirical rate is ~325 B/col on this AIR.** Ruled out row-loop-proxy as a path to §3.4 envelope. |

---

## 3. Detailed experiment records

### Experiment 1 — Merkle-level row loop (K-air-col-share, step 1)

**Hypothesis**: at 4/4, 32 per-spend Merkle-level Poseidon2-w8 instances × 4 spends = 128 independent column blocks dominate the AIR width. Fold all of them onto a single shared w=8 column block iterated across 32 trace rows with one-hot row selectors and a running-digest column.

**Implementation**: `GS_ROW_SEL[0..32]` one-hot bank driven by a shift-register constraint; `S_CURRENT` column bound to `leaf` on row 0, advanced by each row's P2 output on rows 0..30, asserted equal to the anchor PI on the last row. Position low-to-high bit order matches C++ `commitment-tree.{h,cpp}` append-walk.

**Result**: ✅ Landed. At 4/4: cols 27,837 → 5,553 (**−80.05 %**). Proof 33 MB → 6.46 MB (−80.8 %). Verify 790 → 148 ms (−81.3 %). All 43 Rust lib tests pass; public-input golden byte-identical.

**Why it worked**: at this scale the per-Poseidon2 column cost dominates the per-row selector + running-digest overhead. Row-loop pattern amortizes 32 column blocks onto trace-row space, which was previously all padding.

---

### Experiment 2 — Wide + narrow Poseidon2 sharing (K-air-col-step2, step 2)

**Hypothesis**: after step 1, the remaining per-spend work includes one claim-3 `ivk_commitment` Poseidon2-w8 absorb, one claim-4 `nf` Poseidon2-w8 absorb, and one claim-2 `cm` Poseidon2-w16 absorb. Each output has one claim-6 `cm` Poseidon2-w16 absorb. Fold all the claim-3+claim-4 w=8 instances onto one shared block (8 rows: 4 spends × 2 claims) and all claim-2+claim-6 w=16 instances onto another (8 rows: 4 spends + 4 outputs). Ride the existing `GS_ROW_SEL` bank from step 1.

**Implementation**: Row-gated `sel_r · (input − expected) == 0` and `sel_r · (output[0] − expected) == 0` for each (claim, sub-instance) pair. No new selector columns beyond the step-1 bank.

**Result**: ✅ Landed. At 4/4: cols 5,553 → **2,081** (additional −62.5 %). Proof 6.46 MB → 2.22 MB (−65.6 %). Verify 148 → 111 ms (−25 %). At 1/1: cols 1,413 → 917 (−35 %). Public-input golden byte-identical.

**Cumulative versus pre-step-1 baseline**: 27,837 → 2,081 cols (**−92.5 %**).

**Why it worked**: same amortization principle as step 1, applied to the remaining per-claim Poseidon2 blocks. Step 2 is the last "easy" win on column count.

---

### Experiment 3 — Sub-shape folding + trace-height tuning (K-air-col-step3, step 3)

**Hypothesis (e) — tight shape alloc**: if the AIR's `air_width(S, O)` is currently allocating worst-case columns regardless of the actual `(S, O)`, a 1-spend/2-output transfer is carrying proxy columns for unused spends. Make the allocation tight per shape.

**Finding (e)**: the AIR is *already* tight. `air_width(n_s, n_o) = GLOBAL_COLS + n_s · per_spend_cols() + n_o · per_output_cols()` with GLOBAL_COLS=529, per_spend=318, per_output=70. At 1/1 this gives 917; at 1/2 → 987; at 4/4 → 2,081. No over-allocation to remove. **Strategy (e) does not apply.**

**Hypothesis (f) — trace-height shrink**: trace is currently 64 rows but rows 8..63 are pure padding (only Merkle rows 0..31 and Cm/IvkCm/Nf rows 0..7 carry bound data). Shrink `LOG_TRACE_HEIGHT` from 6 to 5 (64 → 32 rows).

**Implementation (f)**: moved anchor binding from `when_last_row(S_CURRENT)` to `when_last_row(merkle.P2.output[0])` to survive without row 32's transition. Rebuilt, all 45 lib tests pass.

**Result (f)**: ❌ Not kept. At 4/4: cols 2,081 → 2,081 (unchanged; only log-H changed); proof 2.22 MB → 2.17 MB (**−2.1 %**); verify 63 ms → 94 ms on agent host (noise). At 1/2: proof 1.25 MB → 1.20 MB (**−3.7 %**). **Fails the 15 % threshold.** Reverted.

**Root cause**: proof bytes are dominated by `num_queries=128 × column-count × per-query leaf values`. Trimming `log(H)` from 6 to 5 shortens Merkle auth paths by 1 level × 6 siblings × 32 B × 3 batches = ~576 B per query, times 128 queries = ~73 KB saved — a tiny fraction of 2.22 MB. **Column count is untouched, so proof size barely moves.**

**Also investigated — trace height *expansion* (64 → 128 or 256)**: conceptually lets you fold more Poseidon2 instances into fewer columns. Arithmetic: at height=128 with one more Merkle collapse, width 4/4 would drop 2,081 → 1,541 (−26 %), but cell count grows 133k → 197k (+48 %). Net proof size would increase, not decrease. **Dead-end.**

---

### Experiment 4 — Cross-instance Poseidon2 row-doubling (K-air-scheduler)

**Hypothesis**: run two Poseidon2-w8 sub-instances per row (e.g. claim-3 of spend i plus claim-4 of spend i) so that 8 logical rows collapse to 4 physical rows. Combined with halving trace height (64 → 32) this could shrink log-H by 1 while doubling per-row width — hopefully net-beneficial.

**Feasibility math (done before coding)**:

Current 4/4 proof decomposition at `num_queries=128`:

```
leaf term       = 128 × 2,081 cols × 8 B  ≈ 2.12 MB  (95 % of proof)
Merkle-path term = 128 × 6 × 32 B × 3 batches  ≈ 73 KB   ( 5 % of proof)
------------------------------------------------------
total                                         ≈ 2.22 MB
```

**Option A** — row-doubling WITHOUT trace-height change (one extra w=8 block):
- `+180 cols`. At 4/4: 2,081 → 2,261 cols.
- Leaf term grows `+8.7 %` (+184 KB). Path term unchanged.
- **Predicted: proof GROWS ~8 %.** Reject.

**Option B** — row-doubling AND halve trace height (64 → 32):
- Width `2,081 → 2,261`; `log(H)` 6 → 5.
- Leaf term: `+184 KB`. Path term: `−17 %` of 73 KB = `−12 KB`.
- **Predicted: proof GROWS ~7.7 %.** Reject.

**Result**: ❌ **No commit.** The predicted growth is enough to falsify the hypothesis at the math stage; building a prototype only to measure a confirmed regression would be wasted effort.

**Load-bearing finding**: **at Plonky3/Goldilocks with `num_queries=128` and 8-byte field elements, Transfer AIR proof size is leaf-bound, not path-bound.** Any optimization whose cost is additional columns and whose payoff is smaller `log(H)` is net-negative at this parameterization. To get a real proof shrink we need *fewer columns* (and column-sharing is exhausted per Experiment 3) or *fewer queries* (which means FRI parameter change — see Experiment 6).

---

### Experiment 5 — Shape-matrix benchmark harness (K-air-bench)

**Hypothesis**: ad-hoc one-shot measurements in commit messages are not reproducible and don't cover the 6-shape envelope. Build a standard harness.

**Implementation**: hand-rolled `std::time::Instant` best-of-5 harness at `uno/plonky3-ffi/benches/shape_matrix.rs`, registered via `[[bench]] harness=false`. No criterion dep. Emits Markdown table for direct copy-paste into commit messages and into this doc.

**Result**: ✅ Landed (commit `6cad7c347`). 197 lines, zero dependency weight. See §1 of this doc for the baseline table.

**How to reproduce**: `cd uno/plonky3-ffi && cargo bench --bench shape_matrix`. Runs in ~15 s on an 8-core host. Results are release-build, best-of-5, single-thread.

---

### Experiment 6 — FRI parameter sweep (K-fri-analysis)

**Hypothesis**: §2.1 pins `(log_blowup=2, num_queries=128, pow_bits=16)`. The underlying decision was theoretical; is there a configuration that buys significant proof shrink without crossing the soundness floor for a payment-chain-grade L1?

**Implementation**: `uno/plonky3-ffi/benches/fri_param_sweep.rs` sweeps 15 configurations across `log_blowup ∈ {1, 2, 3, 4}`, `num_queries ∈ {28, 52, 84, 128, 200}`, `pow_bits ∈ {0, 16, 24}`. For each, records prove ms, verify ms, proof bytes, and the ethSTARK conjectured + proven soundness bits.

**Result**: ✅ Landed at `dd0383b69`. Full sweep in `doc/uno-fri-param-analysis.md`. Three frontier configurations identified:

| Option           | (log_blowup, num_queries, pow_bits) | Proof bytes            | Verify ms | Conjectured / Proven bits |
|------------------|-------------------------------------|-----------------------:|----------:|---------------------------|
| §2.1 pin         | (2, 128, 16)                        | 2,290,134              | 55.7      | 272 / 144                 |
| A. Budget        | (2, 84, 16)                         | 1,524,376 (−33 %)      | 37.7      | 184 / 100                 |
| B. Memory        | (3, 52, 24)                         | 984,019 (−57 %)        | 24.7      | 180 / 102                 |
| C. Aspirational  | (3, 28, 24)                         | 558,940 (**−76 %**)    | 14.7      | 108 / 66                  |

**Three hard findings from the sweep**:

1. **`log_blowup=1` is AIR-structurally incompatible.** The Transfer AIR's quotient polynomial has degree ≥ 3, which requires `blowup ≥ 4`. At `log_blowup=1` the prover produces a proof but the verifier rejects with `OodEvaluationMismatch`. This strengthens §2.1's rejection of the `(1, 200)` alternative from *"same soundness, +50 % size"* to *"cannot produce a verifying proof at all"*.

2. **`pow_bits=24` is a pathological sweet spot.** 22× prove time for only +8 soundness bits. `pow_bits=16` is the empirical optimum for this AIR; `pow_bits=0` is a tempting shortcut that fails the proven-soundness floor.

3. **`num_queries` is the only real proof-size lever.** Proof bytes are approximately linear in `num_queries` and approximately *constant* across `log_blowup` at fixed `num_queries`. Changing `log_blowup` shifts the prove/verify/soundness triangle but not the proof-size line.

**Distance to §3.4 envelope**: best sweep data-point (Option C, 559 KB) is **5.5× over** the ~100 KB worst-case envelope. The current pin is 22.4× over. **FRI retuning cannot close the gap alone** — it closes 3 of 22 factors. The remaining 5.5× requires AIR-structural work.

---

### Experiment 7 — Row-cycle OUTPUT_PROXY_COLS into a shared block (K-air-fold-outputs)

**Hypothesis**: each output currently carries a private 70-col block
(6 scalars + 64 value-bits) that is constant across all 64 trace rows.
But each output's values are only read on one specific row (row 4+j
for claims 6 + 7). Fold the 4-output replication into a single shared
70-col block in `GLOBAL_COLS` that cycles through outputs by row:
on row 4+j, the shared block holds output-j's values. Add a
1-col `G_OUT_VALUE_ACCUM` running sum so the claim-8 balance check
can still be evaluated on a single (last) row. Net column change at
4/4: `4 × 70 − (70 + 1) = 209` cols removed.

**C1 prediction**: 209 cols × ~1 KB/col ≈ **214 KB shrink (−10 %)** at 4/4.

**Implementation** (prototyped on branch `uno-air-fold-outputs`,
discarded at the user's direction):
- Added `G_OUT_SHARED[0..70]` + `G_OUT_VALUE_ACCUM` to `GLOBAL_COLS`.
- Set `per_output_cols() = 0`. `air_width(n_s, n_o)` no longer has
  an `n_outputs` term.
- Row-gated claim-6 PI binding + claim-7 bit-decomp on row 4+j via
  `GS_ROW_SEL[4+j]` (same idiom as the shared wide-Cm block bindings).
- Accumulator transition: `accum[r+1] − accum[r] − Σ_j GS_ROW_SEL[4+j]·value_shared == 0`
  (degree 2, well within the max-degree-7 budget).
- Balance check moved from `when_first_row` to `when_last_row`:
  `Σ spend_value − accum − fee == 0`.
- Boundary: `accum[0] == 0`.
- Removed the "output proxies constant across rows" transition loop
  (the shared block legitimately varies now).
- Prover trace: fills shared block with output-j's values on row 4+j,
  zeros elsewhere; accumulator populated per-row.

**Result**: ❌ **Not committed.** All 43 Rust tests pass; public-input
golden byte-identical; verify +9 % faster at 4/4 (57 → 52 ms). But
proof-size shrink is far under C1's prediction:

| shape | cols before | cols after | Δ cols | proof before | proof after | Δ % proof |
|-------|------------:|-----------:|-------:|-------------:|------------:|----------:|
| 1/1   |         917 |        918 |     +1 |   1,198,931  |  1,199,578  |  +0.05 %  |
| 1/2   |         987 |        918 |    −69 |   1,223,642  |  1,198,588  |   −2.05 % |
| 2/2   |       1,305 |      1,236 |    −69 |   1,500,317  |  1,482,582  |   −1.18 % |
| 2/3   |       1,375 |      1,236 |   −139 |   1,536,344  |  1,491,160  |   −2.94 % |
| 3/3   |       1,693 |      1,554 |   −139 |   1,835,246  |  1,788,770  |   −2.53 % |
| **4/4** |   **2,081** |  **1,872** | **−209** | **2,131,583** | **2,063,512** | **−3.19 %** |

**Empirical rate: 68,071 B / 209 cols ≈ 325 B per column reduction** —
about **1/3 of C1's ~1 KB/col upper bound**.

**Why the prediction was wrong**: C1's model counted one term —
`num_queries × col_count × 8 B/field` — for the per-query leaf opening.
That term is real but it's not the only cost of shrinking col_count.
Plonky3 commits multiple matrices (trace + quotient chunks +
preprocessed) into one mixed Merkle tree; reducing trace column count
only saves proportionally on the trace leaf, not the quotient or
preprocessed leaves, and the per-query Merkle-path overhead is roughly
invariant to trace width under mixed commitment. So col reduction does
shrink proof, but at ~325 B per column, not ~1 KB.

**Consequence for Method B (also fold SPEND_PROXY non-Merkle scalars)**:
B would remove another ~216 cols (8 scalars + 64 value-bits per spend × 3
redundant copies). At the new 325 B/col rate that's ≈70 KB extra,
bringing A + B total to ~140 KB ≈ 6.5 % at 4/4 — **still below the 8 %
threshold** and with much higher implementation complexity (spend
proxies entangle with Merkle rows 0..31). **Row-loop-proxy via
column-count reduction is not the path to §3.4.**

**Decision**: code discarded; finding recorded here + in §4 C1
re-calibration below. Future contributors should not re-run this
experiment; they should instead target (a) claim-structure redesign
that reduces *semantic* column count (not just replication), or (b)
the FRI parameter renegotiation surfaced by K-fri-analysis.

---

## 4. Load-bearing constraints

Every future optimization attempt must respect these constraints, which
were established empirically across the experiments above:

**C1. Proof size is leaf-dominated at `num_queries=128`, but per-column
savings are ~325 B, not the theoretical ~1 KB.** The simple model
"adding a column costs `num_queries × 8 B = 1 KB`" is an **upper bound**
that overstates real savings by ~3×. The empirical rate measured by
experiment 7 is **325 B per column of trace-width reduction** at the
current FRI pin. This is because Plonky3 uses a mixed Merkle commitment
over (preprocessed + trace + quotient) matrices — shrinking trace cols
only proportionally shrinks the trace leaf, not the quotient/preprocessed
leaves or the per-query Merkle-path overhead.

**Practical implication**: an optimization needs to remove **~250 cols
at 4/4 to shave 8 %**, or ~625 cols to shave 20 %. The current 4/4
total is 2,081 cols. Shrinking `log(trace_height)` still saves only
kilobytes (experiment 3); row-doubling schemes that add cols are still
net-negative (experiment 4). (From K-air-scheduler + K-air-fold-outputs.)

**C2. Column-sharing via row-looping is exhausted.** Steps 1 + 2 took
cumulative −92.5 % at 4/4; step 3 could not find another sharing
that clears a 15 % threshold. The shared column blocks
(`shared w=16 Cm/OutCm`, `shared w=8 IvkCm/Nf`, `shared w=8 Merkle`)
are already atomic Poseidon2 witness-column widths that cannot shrink
below one block. Row-cycling the remaining proxy blocks
(`OUTPUT_PROXY_COLS`, `SPEND_PROXY_COLS` non-Merkle part) yields at most
~6–7 % combined (experiment 7), below any reasonable threshold.
(From K-air-col-step3 + K-air-fold-outputs.)

**C3. Trace-height expansion is net-negative for proof size.** At
height=128 with one more Merkle collapse, cells grow faster than cols
shrink. (From K-air-col-step3.)

**C4. `log_blowup=1` is not an option for this AIR.** Quotient degree ≥ 3
mandates blowup ≥ 4. (From K-fri-analysis.)

**C5. `num_queries` is the only FRI knob that moves proof size
substantially.** Do not spend agent time optimizing `log_blowup` or
`pow_bits` in isolation. (From K-fri-analysis.)

**C6. The 4/4 shape is a test-matrix boundary, not a common case.**
Real transactions are 1-spend / 2-output. At 1/2 we're 12× over the
envelope (not 22×) and verify is 31 ms (not 109 ms). A proof-size
improvement that benefits 4/4 should benefit 1/2 proportionally; if it
only helps 4/4 it may be less important than it looks. (From K-air-bench.)

---

## 5. Remaining paths

The ~22× gap to §3.4 envelope at 4/4 can be closed by exactly one of:

### Path 1 — FRI parameter renegotiation (partial; decision-ready)

**Reduces the gap by up to 4×** (22× → 5.5×) via §2.1 re-vote to a
frontier configuration in K-fri-analysis. Does NOT require any code
rewrite beyond `build_config()`; all three frontier configs already
have measured soundness bits. Requires a deliberate design-doc vote
and audit-vendor sign-off because §2.1 is consensus-binding.

**Who decides this**: the team + the eventual audit vendor. The doc is
ready (`doc/uno-fri-param-analysis.md`); the code change is a one-liner
in `prover.rs::build_config` once a new pin is agreed.

### Path 2 — Structural AIR rewrite (semantic column reduction)

**Needed to close the remaining 5.5×** (frontier config to envelope).
Experiment 7 established that row-cycling *replicated* proxy columns
buys at most ~6–7 % total — not enough. What's needed is reducing the
**semantic** column count of the AIR, meaning: fewer distinct witness
fields and intermediate values per (spend, output), not fewer copies
of the same fields.

Candidate directions (all still unexplored; each is a research-grade
cryptographer task, not an agent-sized edit):

- **Claim fusion** — combining claim-2 (`cm = Poseidon2(d, pk_d, …, value, rcm)`)
  and claim-3 (`ivk_commitment = Poseidon2(ivk, d)`) into one composite
  Poseidon2 absorb. Saves one per-spend Poseidon2-w8 instance if the
  resulting 8-field claim can be expressed as a single absorb.
- **Value-range-check via lookup** — the 64-bit value range check
  currently costs 64 cols/spend + 64 cols/output for bit
  decomposition. Plonky3 supports **lookup arguments**; migrating
  range-check to a precomputed `[0, 2^16)` lookup (4 × 16-bit limbs
  per value) drops 64 → 4 cols per field, saving ~60 cols × 8 =
  ~480 cols at 4/4, which at 325 B/col ≈ **−156 KB (−7.5 %)**.
  Primary candidate for the next K-batch agent.
- **Nullifier derivation reformulation** — claim-4 currently absorbs
  `(nk, cm, pos)` via a full Poseidon2-w8. Some protocols fold nk
  directly into cm via a different algebraic structure; a research
  task to check whether this is compatible with the hash-chain
  ownership proof.
- **Merkle-path verification via STIR / WHIR** — swap the classical
  FRI-on-columns Merkle opening for a STIR-style verifier that gives
  sub-linear query cost. This is v2 / research horizon.

Expected win per direction is on the order of 5–15 % individually;
stacking them all optimistically gets to another ~30 % on top of
Path 1's 76 %. Even so, the combination may still not reach the
100 KB envelope at 4/4 — in which case §3.4 becomes a v1-vs-v2
scope question (ship at a larger envelope or defer until research
matures).

### Path 3 — Proof-system change (out of scope for v1)

Plonky3 → a different system (Plonky2, STARK with smaller queries,
eSTARK, etc.) could close the gap entirely. Rejected for v1 per
§16 decision #2 (Plonky3 over Goldilocks, PQ-native, no trusted setup).
Could revisit for v2 if the §3.4 envelope proves infeasible on the
current system.

---

## 6. How to use this document when resuming work

1. **Read §1** — know the current numbers.
2. **Scan §2 chronology** — check if your idea matches a rejected strategy.
3. **Read §4 constraints** — especially C1, C2, C5.
4. **Propose the experiment**:
   - Under which constraint does it fit?
   - What's the feasibility-math prediction (cols Δ × ~1 KB + log-H Δ × ~12 KB)?
   - If the math predicts <10 % shrink, it's not worth a cryptographer-week.
5. **If the math clears the threshold**, run the K-air-bench harness
   before + after and commit the measured table.
6. **Update §2 of this doc** with the result — positive or negative. Negative
   results are just as valuable, because C1–C6 are themselves negative
   results from prior work.

---

## 7. Reference: commits and artifacts

- `05bb3197a` — K-air-col-share (step 1 landed)
- `8e763c38d` — K-air-col-step2 (step 2 landed)
- K-air-col-step3 (step 3, no-commit negative result)
- K-air-scheduler (negative result, record in §13 P.2 of `doc/uno-workchain.md`)
- `6cad7c347` — K-air-bench (shape-matrix harness landed)
- `dd0383b69` — K-fri-analysis (parameter sweep + frontier-config doc landed)
- K-air-fold-outputs (experiment 7, no-commit; C1 re-calibration finding)
- Primary sources:
    - `uno/plonky3-ffi/src/transfer_air.rs` — the AIR itself
    - `uno/plonky3-ffi/src/prover.rs::build_config` — FRI configuration
    - `uno/plonky3-ffi/benches/shape_matrix.rs` — current-state benchmark
    - `uno/plonky3-ffi/benches/fri_param_sweep.rs` — FRI sweep benchmark
    - `doc/uno-fri-param-analysis.md` — full FRI decision matrix
    - `doc/uno-workchain.md` §13 P.2 — roadmap status
