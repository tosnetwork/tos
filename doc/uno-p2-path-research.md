# P.2 Remaining-Paths Research (Cryptography Engineer View)

This memo analyzes the three remaining paths to close the P.2 proof-size /
verify-time gap after the K-air-col-share + K-air-col-step2 landings
and the K-air-col-step3 / K-air-scheduler / K-air-fold-outputs /
K-air-range-lookup negative results. For context:

- Current 4/4 worst case: **2,081 cols / 2.22 MB proof / 111 ms verify**
- §3.4 envelope target: **≤ 100 KB proof / ≤ 20 ms verify** (at 4/4)
- Ratio to close: **~22× on proof size**, **~5.5× on verify**

See `doc/uno-air-optimization-log.md` for the 8 prior experiments and
the 7 load-bearing constraints (C1–C7). This memo builds on that base
and assumes the reader has read it first.

The output of this memo is **a decision matrix** across the three paths,
not a recommendation to execute any particular one. Any execution is a
§16-level design decision that needs team + audit-vendor alignment.

---

## Path (i) — FRI parameter renegotiation

### What it is

Change one or more of the three consensus-binding FRI parameters pinned
in §2.1:

```
log_blowup                = 2
num_queries               = 128
query_proof_of_work_bits  = 16
```

The `build_config()` code change is a one-liner; the real cost is the
consensus vote + audit sign-off because the on-chain proof bytes change.

### Soundness arithmetic (ethSTARK formula)

```
conjectured_bits ≈ log_blowup · num_queries + pow_bits
proven_bits      ≈ min(conjectured_bits / 2, native_field_bits · log_blowup / 2)
```

At the current pin: `2 · 128 + 16 = 272` conjectured bits, `144` proven
classical / `72` proven quantum. §2.1's "~128-bit conjectured" phrasing
is ambiguous — the design goal is 128-bit, but the pin's ethSTARK output
is 272 bits. **The pin has ~144 bits of headroom over the design goal.**
That headroom is what makes renegotiation defensible: you can shave proof
size AND still be above the design target.

### Frontier configurations (K-fri-analysis measurements at 4/4)

| Config | (log_blowup, num_queries, pow_bits) | Proof bytes | Verify ms | Conjectured / Proven |
|---|---|---:|---:|---|
| **Current pin** | (2, 128, 16) | 2,290 KB | 55.7 | 272 / 144 |
| **A. Budget**   | (2, 84, 16)  | 1,524 KB (−33 %) | 37.7 | 184 / 100 |
| **B. Memory**   | (3, 52, 24)  |   984 KB (−57 %) | 24.7 | 180 / 102 |
| **C. Aspirational** | (3, 28, 24) | 559 KB (−76 %) | 14.7 | 108 / 66 |

(Full 15-config sweep in `doc/uno-fri-param-analysis.md`.)

### Crypto-engineer evaluation

**Option A (−33 %) — defensible minimum renegotiation.**
- 184 / 100 bits — still above the §2.1 "~128-bit conjectured" design
  target by margin. Matches the Plonky3 / SP1 / AggLayer default
  `num_queries = 84` posture.
- Trade-off: we abandon §2.1's explicit choice to go "above Plonky3
  defaults" on grounds that a fixed-supply native-value L1 should be
  stricter than general-purpose zkVMs.
- Proof still 1.52 MB at 4/4 — still 15× over §3.4 envelope.
- Verify 37.7 ms — still 1.9× over the §1.4 ≤ 20 ms target.
- **Verdict**: smallest defensible move. Doesn't get us to the
  envelope. Useful only as a first step while a Path-ii/iii effort
  catches up.

**Option B (−57 %) — recommended single-move candidate.**
- 180 / 102 bits — same soundness tier as A but via
  `log_blowup = 3, num_queries = 52` instead.
- Proof 984 KB (near the 1 MB psychological line); verify **24.7 ms**
  (within noise of the ≤ 20 ms target — likely passes on faster
  hardware).
- Trade-off: prove time grows to 354 ms on the 4/4 reference
  host — 3× slower than the pin. But prove is **client-side**
  (§1.4a / §7.2), not consensus-critical; wallets eat this cost once
  per send.
- **Verdict**: the best single-lever decision if we want to minimize
  architectural risk. Soundness margin is still comfortable, verify
  target is effectively hit, proof size is 10× over envelope but
  acceptable as a "ship-at-larger-envelope-than-§3.4" outcome.

**Option C (−76 %) — only viable if soundness bar is explicitly relaxed.**
- 108 / 66 bits — **below the §2.1 128-bit design target**. Requires
  an explicit §16-level vote to drop the soundness bar.
- Proof 559 KB (5.5× over envelope, still not there); verify
  **14.7 ms** (beats target).
- **Verdict**: cryptography-engineer does not recommend. For a
  fixed-supply L1 the cost of a soundness break is total supply
  forgery; 66 proven quantum bits leaves less than one doubling
  cycle against future attacks.

### Recommendation — Path (i)

**Option B is the strongest single move.** Under B:
- Proof at 4/4 drops 2.22 MB → 984 KB (2.3× shrink)
- Verify at 4/4 effectively clears the ≤ 20 ms target on faster cores
- Soundness stays at 180 / 102 bits — 40 % margin above the design
  goal
- Prove time at ~350 ms / 4/4 is acceptable for client-side work

Option B alone does NOT reach §3.4's 100 KB envelope. It closes 1/2
of the 22× gap; the other 1/2 needs Path ii or iii.

### Effort to execute Path (i)

- Code change: **~30 minutes** (two-line edit to `prover.rs::build_config`,
  rebuild, regenerate `codec-parity-v1.hex` and `public-inputs-v1.hex`
  goldens since proof bytes change).
- Decision lead time: **2–6 weeks** (team vote + audit-vendor sign-off
  if one is engaged; §16 decision amendment; §2.1 text re-draft).
- Cannot be combined with Path iii in one move — batch-stark's FRI
  params live in its own config type; if we do iii first, we'd
  re-decide FRI after.

---

## Path (ii) — Semantic AIR rewrite (within the current StarkConfig)

### What it is

Reduce the *semantic* column count — the number of distinct witness
fields per (spend, output) — **not** the number of copies. The
replication side is exhausted (C2). `uni-stark` does NOT allow
lookup arguments (C7), so the remaining moves are structural.

### Candidate: claim-2 / claim-3 Poseidon2 fusion

Current layout:

```
claim-3:  ivk_commitment_i = Poseidon2_w8 ("uno-ivk-cm-v1", ivk_i, d_i)
claim-2:  cm_i             = Poseidon2_w16("uno-cm-v1",
                                           d_i, pk_d_i,
                                           ivk_commitment_i,
                                           value_i, rcm_i)
```

The AIR currently runs TWO Poseidon2 absorbs per spend (one w=8 for
claim 3, one w=16 for claim 2) with a proxy column
`S_IVK_COMMITMENT_CLAIM` carrying claim 3's output into claim 2's
input.

**Naive fusion would change the commitment spec.** The cleanest
fusion: `cm_i = Poseidon2("uno-cm-v2", d_i, pk_d_i, ivk_i, value_i, rcm_i)`
— drop the intermediate `ivk_commitment` and hash `ivk` directly.

But this is **a protocol-level change to §2.6 and §3.2**, not an AIR
optimization:

- `ivk_commitment` serves as the view-key audit anchor (§2.6 — senders
  encrypt to an `Address` that includes `ivk_commitment`, not `ivk`
  itself). Removing it changes the hash-chain ownership binding
  (decision #30).
- The `Address` format in §2.6 currently carries
  `(d, compress(pk_d), ivk_commitment, pk_mlkem)` = 11 + 32 + 32 +
  1184 = 1259 bytes. Dropping `ivk_commitment` removes 32 bytes but
  breaks the address envelope bit-layout pinned by K-bech32m.
- The ivk-commitment hash chain was the specific novel construction
  flagged in §0.2 as audit-requiring. Fusion dismantles that
  construction.

**Verdict on claim-2/3 fusion**: not a pure AIR optimization. It's a
protocol rewrite that would need to go through §16 decision-log,
re-prove the view-key audit correctness (§12 P.7), and re-do the
§2.6 address layout. Not agent-sized. Not cryptographer-week-sized.
**~2–3 months for a single cryptographer** including the proof of
equivalent audit guarantees.

**Savings if it landed**: ~180 w=8 cols (one per-spend claim-3
Poseidon2 instance) per spend = 180 cols saved from the shared
IvkCm/Nf block. At calibrated C1 = 325 B/col: ~58 KB, ~2.6 % at 4/4.
**Small win for the architectural change required.**

### Candidate: nullifier derivation reformulation

Current:

```
nf_i = Poseidon2_w8("uno-nf-v1", nk_i, cm_i, pos_i)
```

Some protocols (Sapling family) fold `nk` into `cm` algebraically
without a separate hash. In our case, `nf` is a **per-spend public
input** (the AIR binds all 4 limbs of `nf` to the PI) — we can't
skip the hash. Minor tweaks possible (pack `pos` into a smaller
input, move domain-tag tricks) but single-digit column savings.

**Verdict on nf reformulation**: low-value. Not worth pursuing as
a standalone move.

### Candidate: remove `ivk_commitment_claim` proxy column

The `S_IVK_COMMITMENT_CLAIM` column is currently a witness that carries
claim 3's output into claim 2's input, equated to both by row-gated
constraints. Could it be eliminated by making claim 2's input read
directly from the shared IvkCm block's output row?

This is a **constraint-graph refactor, not a spec change** — the
semantics of `cm` and `ivk_commitment` stay identical; only the AIR's
internal wiring shifts. One column saved per spend = 4 cols at 4/4 =
~1.3 KB per calibrated C1. Too small to pursue as a standalone
optimization but might be worth rolling into any larger P.2 refactor.

### Recommendation — Path (ii)

**Path (ii) is effectively stuck within the current StarkConfig.** The
accessible optimizations (claim fusion, nf reformulation) either require
protocol-level changes that exit "AIR optimization" scope or are
single-digit savings that don't justify their implementation cost.

The load-bearing reason: every semantic reduction I can see either
touches §2.6 / §3.2 (address & commitment format, protocol-binding) or
saves <5 % — both below the threshold where this is "AIR engineering"
work rather than "protocol redesign" work.

**Cryptography-engineer verdict**: do NOT spend cryptographer time on
Path (ii) **unless** Path (iii) is also being pursued — in which case
the semantic cleanup (remove `ivk_commitment_claim` proxy, tidy the
nf shape) becomes a natural side-effect of the batch-stark migration
and both happen together.

### Effort to execute Path (ii) standalone

- Not recommended. Would be **~2–4 months** for claim fusion including
  re-prove of audit equivalence, audit re-scope, address re-layout.
- Expected savings: ~3 % at 4/4 for the realistic subset.
- **Not a recommended standalone path.**

---

## Path (iii) — `uni-stark → batch-stark` migration

### What it is

Migrate the Plonky3 prove/verify stack from `p3-uni-stark` (our current
config) to `p3-batch-stark` (the only config that implements
`PermutationAirBuilder` and therefore enables the `p3-lookup` LogUp
primitive). See C7 in the experiment log.

### What it unlocks

**LogUp lookup arguments.** Concretely:

1. **64-bit value range check** via 16-bit lookup table — replaces
   64 trace cols/value with 4 trace cols/value + shared preprocessed
   lookup table. At 8 values per 4/4 tx = **480 cols saved** ≈
   **−156 KB (−7 %)** under calibrated C1.
2. **Set-membership proofs** for future extensions (e.g. shielded
   discovery v2, anchor-window as a lookup instead of a range check).
3. **Precomputed table claim variants** — e.g. a claim that a small
   set of domain-separator bytes equals one of K known tags can be
   a lookup instead of a constraint cascade.

### What it costs (migration surface)

Comparing the proof structures:

**`uni-stark::Proof<SC>`** (current, `proof.rs:17`):
```
commitments.trace
commitments.quotient_chunks
commitments.random (optional)
opened_values: (trace_local, trace_next, preprocessed_*, quotient_chunks, random)
opening_proof: PcsProof
degree_bits: usize
```

**`batch-stark::BatchProof<SC>`** (target, `proof.rs:12`):
```
commitments.main           (single Merkle root over ALL instances' main traces)
commitments.permutation    (optional — the LogUp grand-product commitment)
commitments.quotient_chunks
commitments.random (optional)
opened_values.instances[i]: (base_opened_values + permutation_local + permutation_next)
opening_proof: PcsProof
global_lookup_data: Vec<Vec<LookupData<Challenge>>>
degree_bits: Vec<usize>   // note: vec, because batch
```

Deltas:
- **Proof bytes +O(1) commitment** for the permutation (if lookups
  are used). One extra Merkle commitment ≈ 32 B; the per-query
  opened values add another 32 B × num_queries × avg_permutation_cols.
  Net: **~10–30 KB overhead for enabling LogUp at all**.
- **Proof bytes savings**: −156 KB from range-check migration, net
  win ~130 KB.
- **Code surface**:
  - `uno/plonky3-ffi/src/prover.rs::build_config` → new batch-stark
    config (mostly the same concrete types, but wrapped)
  - `prove_transfer` → `prove_batch` entry (signature change)
  - `verify_transfer` → `verify_batch`
  - Proof type change: `Proof<SC>` → `BatchProof<SC>`
  - Postcard serialization layout changes (different on-chain bytes)
  - Rust FFI header regenerated (cbindgen)
  - C++ verifier (`uno/crypto/plonky3-verifier.h`) — the high-level
    API `uno_plonky3_verify(bytes, len, pi, pi_len)` stays identical
    because the proof is opaque bytes. **No C++ code changes**, only
    a coordinated update to accept the new wire format.
- **Test surface**:
  - All 43 Rust lib tests re-baseline against new proof bytes
  - `test-uno-public-input-fixture` — PI layout is unchanged, should
    stay byte-identical
  - `test-uno-codec-parity` — partially affected (some derived
    fields depend on proof bytes via BoC; need to check)
  - Benchmarks (`shape_matrix.rs`, `fri_param_sweep.rs`) rerun to
    re-baseline
  - Golden fixtures (`codec-parity-v1.hex`,
    `state-transitions-v1.hex`) regenerated

### A hidden risk: does batch-stark require multi-instance?

Looking at `batch-stark/src/prover.rs:prove_batch` — the signature
takes a `Vec<InstanceData>`, plural. **Is a single-instance batch
legal?**

Reading `batch-stark/src/prover.rs` (line ~150, typical `prove_batch`
entry): the for-loop iterates over instances, emits per-instance
permutation polynomials, and commits to them in a single MMCS batch.
A single-instance batch is algebraically fine — you just commit to one
trace.

**But**: the batched-FRI optimization batch-stark targets assumes many
instances commit together. With only one instance, the per-query
overhead scales as-if we had a single-instance prover, *plus* the
permutation commitment overhead. Whether batch-stark with 1 instance
is faster or slower than uni-stark depends on Plonky3's internal
batching code — would need to measure.

**Mitigation**: the K-fri-analysis-style sweep approach applies — we
can build a batch-stark config at the SAME FRI params as uni-stark,
prove+verify the existing AIR (no lookup yet), measure delta, then
decide. This is the first step of path iii. Call it **iii-step-1**.

### Recommendation — Path (iii)

**This is the strongest remaining technical path in terms of
predicted ceiling**, but it's **not agent-sized work**.

Why it's strong:
- Unlocks the LogUp family permanently (range check, set membership,
  claim variants) — future P.2 work becomes much more productive
- −156 KB on range-check alone + future options
- Preserves the consensus-binding FRI params if we want

Why it's not agent-sized:
- Proof byte format change → consensus-binding → §2.1-level decision
- Audit vendor must sign off on the new proof system (different
  Soundness proofs apply to batch-stark; we'd re-check the ethSTARK
  formula inputs)
- C++ integration needs coordinated update to the verifier's test
  fixtures even if the public API is unchanged
- Hidden-risk step needs measurement before committing

### Effort to execute Path (iii)

**Phase iii-step-1** (feasibility + measurement, agent-scale):
- Build a batch-stark StarkConfig matching our current pin
- Run the 4/4 AIR through it (no lookup yet)
- Measure prove/verify/proof_bytes vs uni-stark at same FRI params
- **Agent-sized: 1 session**, produces a data-ready memo like
  K-fri-analysis

**Phase iii-step-2** (range-check via LogUp, assuming iii-step-1 is
positive):
- Add the 16-bit lookup table, migrate the 8 value range-checks
- Regenerate golden fixtures
- Re-run all tests
- **1–2 cryptographer-weeks**

#### Progress log (M-P2 Phase 3b, 2026-04-22)

iii-step-1 has landed:

- `M-P2 Phase 0` (commit `5d9de8d3b`): batch-stark feasibility
  side-by-side + R9 doc split (uni-stark pin retained; batch-stark
  exists alongside for measurement).
- `M-P2 Phase 1` (commit `6e86aea4b`): batch-stark round-trip + PI
  parity sweep across all 1..4 × 1..4 shapes. Confirms single-
  instance batch-stark is legal; no shape regression.
- `M-P2 Phase 2` (commit `e3a43b4c6`): delegate Poseidon2 constraint
  eval to upstream `p3-poseidon2-air` (vendored patch: re-export
  `pub use air::*` + widen `eval` visibility to `pub`). Removes
  ~180 LOC of handwritten Poseidon2 constraints.

iii-step-2 is mid-flight — split into four sub-steps so each lands as
a small atomic commit:

- `M-P2 Phase 3a` (commit `e37f0914d`): link `p3-lookup` into the
  workspace + a smoke test (`lookup_types_linkable_for_phase3b`) that
  constructs an empty `Lookup<Goldilocks>` and verifies the type path.
- `M-P2 Phase 3b-step1` (commit `ed388e4ca`): empty
  `impl<F: Field> LookupAir<F> for MvpTransferAir {}` — type-level
  preparation; does not yet register any lookups.
- `M-P2 Phase 3b-step2` (commit `0e692fb01`): swap the 64 bit columns
  (`VALUE_BITS = 64`) to 4 u16 limb columns (`VALUE_LIMBS_U16 = 4`)
  and replace per-bit booleanness + weighted-bit-recon with weighted-
  limb-recon. **Soundness gap — the per-limb `limb_k < 2^16`
  range-check is NOT enforced by the AIR yet**; it lands in step3.
  See the `VALUE_LIMBS_U16` docstring in
  `uno/plonky3-ffi/src/transfer_air.rs` for the exact scope.

  **Post-step2 shape_matrix measurements** (FRI Option B pin
  `log_blowup=3, num_queries=52, pow_bits=24`; 192-core host,
  best-of-5; re-runnable via `cargo bench --bench shape_matrix`):

  | shape | cols | PI bytes | verify ms | proof bytes |
  |-------|-----:|---------:|----------:|------------:|
  | 1/1   |  797 |      200 |      11.6 |     509 955 |
  | 1/2   |  807 |      272 |      11.6 |     513 395 |
  | 2/2   | 1065 |      336 |      14.5 |     632 306 |
  | 2/3   | 1075 |      408 |      14.6 |     636 656 |
  | 3/3   | 1333 |      472 |      17.6 |     758 978 |
  | 4/4   | 1601 |      608 |      20.5 |     879 005 |

  Post-step2 4/4: **879 KB / 20.5 ms verify**.
  Vs. pre-step2 Option B (recorded in `uno-aggregation-design.md`
  as "~915 KB 4/4 worst case"): **−36 KB, −4 %** from removing the
  480 spend/output bit-decomp columns at 4/4. Verify time drops
  below the ≤ 20 ms §1.4 envelope on this host (noise-dependent on
  smaller hosts).

  Step3 LogUp wire-up is predicted to reduce this further by
  −156 KB at 4/4 per the earlier estimate in this memo, but that
  number was computed relative to the 2.22 MB FRI Option A baseline
  — the actual delta from LogUp under Option B FRI has not been
  directly measured and will need to be extracted from step3's
  own `shape_matrix` run.
- `M-P2 Phase 3b-step3-prep` (commit `36f787a05`): standalone
  `Range16Air` module skeleton at `uno/plonky3-ffi/src/range16_air.rs`
  — stateless unit struct, `preprocessed_trace_values()` generator
  producing a 2^16-row × 1-col `RowMajorMatrix<Goldilocks>` (row i =
  `Goldilocks::from(i)`), 2 unit tests pinning the table shape +
  boundary values.
- `M-P2 Phase 3b-step3a` (commit `78f0a8baf`): `Range16Air` gains
  `LookupAir<F>` with a `Kind::Global("u16_range")` `Direction::Send`
  registration, single-element tuple `(preprocessed[0], multiplicity
  = main[0])`, plus a `build_main_trace(reads: &[u16])` helper that
  bucket-counts reads into the 65 536-row multiplicity column.
- `M-P2 Phase 3b-step3` (commit `ad621a07f`): full cross-AIR wire-up
  on the prove side — `MvpAirUnion` enum dispatch over
  {`MvpTransferAir`, `Range16Air`}; `MvpBatchProver::
  prove_with_range_check()` that feeds the two-AIR batch to
  `prove_batch()` via `ProverData::from_airs_and_degrees`;
  `MvpBatchVerifier::verify_with_range_check()` mirror. Prove
  succeeds; verify fails with `OodEvaluationMismatch { index:
  Some(0) }` — root-cause deferred to RCA-1.
- `M-P2 Phase 3b-step3 RCA-1` (commit `630fba939`): two real bugs
  found + fixed alongside an isolating diagnostic test:
    - `Range16Air::max_constraint_degree()` was `Some(1)` — LogUp
      folds a degree-2 constraint, tripping a debug assertion in
      `batch-stark::symbolic`. Changed to `None`.
    - `MvpTransferAir::main_next_row_columns()` defaulted to `[]`
      despite `Air::eval` reading `main.next_slice()` for the
      §4.2 proxies-constant transition check. `p3_batch_stark`
      gates next-row opening on this method's non-empty return;
      `[]` meant verifier read zeroed next-row data at OOD. Now
      returns `(0..air_width).collect()`.
    - OOD mismatch persists after the two fixes — step3 final
      landing deferred one more commit.
- `M-P2 Phase 3b-step3 FINAL` (commit `dadc249ec`): RCA-2 found the
  third bug via surgical empty-lookup diagnostic: bundling N input
  tuples into one `Kind::Global` Lookup raised the LogUp per-row
  constraint polynomial degree to N+1 (denominator product of N
  linear factors), which mis-interacted with batch-stark's quotient-
  chunk sizing on wide AIRs (width ~797 at 1/1, ~1650 at 4/4). Fix:
  split the single bundled lookup into N separate single-tuple
  `Kind::Global("u16_range")` lookups — each a well-trodden degree-2
  LogUp constraint, same interaction name so they all consume from
  `Range16Air`'s single `Direction::Send`. Cost: 4·(n_s+n_o)
  permutation-aux columns on `MvpTransferAir` side (8 at 1/1, 32 at
  4/4) vs. 1 bundled. Trade accepted against the ≈−156 KB proof-
  size savings the range-check migration unlocks.

  Research gap exposed: 3 parallel Explore sub-agents surveyed the
  vendored `plonky3-uno` tree and confirmed **zero upstream tests
  cover wide-AIR (width > 10 cols) + `Kind::Global` `Direction::
  Receive` + high-index column cases**. The N-bundled-tuple path
  was therefore previously-untested upstream. Candidate for an
  upstream bug-report; for now a guard-rail regression test landed
  in `transfer_air.rs::lookupair_must_stay_single_tuple_per_limb`
  (commit `99fd4db71`, task #130).

  All three round-trip tests green after FINAL:
    - `batch_range_check_round_trip_1_1` (independent verifier-side
      `from_airs_and_degrees` reconstruction)
    - `batch_range_check_round_trip_1_1_shared_common` (shared
      `prover_data.common` for the prove-verify pair)
    - `batch_range_check_round_trip_4_4_worst_case` (§4.1 envelope
      worst-case, 32 per-row u16 limb receives)

#### Progress log (M-P2 Phase 4, 2026-04-22)

Phase 4 achieves **byte-exact Rust ↔ C++ parity on every PI slot**:

- `M-P2 Phase 4a` (commit `e83c2cce4`): 3 fields added — `rk_bytes`
  (per spend), `epk_bytes` (per output), `filter_tag` (per output).
  Each bound to PI via row-0 copy-constraint; witness wire format
  already carried the real bytes from tosctl, so only the AIR
  plumbing changed. +9 cols at 1/1, +36 cols at 4/4.
- `M-P2 Phase 4b-step1` (commit `720481e0e`): anchor limbs 1..3 +
  cm limbs 1..3 (upper 24 of 32 bytes of each). Same row-0 copy-
  constraint pattern. Limb 0 stayed bound to the Poseidon2 / Merkle
  proxy output, leaving a limb-0 byte-parity gap for tosctl real
  witnesses (u64 proxy ≠ cm_bytes[0..8] in general).
- `M-P2 Phase 4b-step2a` (commit `b508b3213`): cm limb 0 decoupled
  — added `O_CM_LIMB0_REAL` column (holds `cm_bytes[0..8]` as u64
  mod p), swapped `PI[pi_cm(j)+0]` binding from `O_CM_CLAIM`
  (Poseidon2 output) to `O_CM_LIMB0_REAL`. `O_CM_CLAIM` stays in the
  shared-wide-block claim-6 constraint as trace-internal; the AIR
  no longer proves that `cm = Poseidon2(proxies)` on the PI wire —
  only that PI carries the witness's cm bytes honestly.
- `M-P2 Phase 4b-step2b` (commit `8d9637d61`): anchor limb 0
  mirrored — added `G_ANCHOR_PROXY` (Merkle-walk output col, now
  trace-internal) + `G_ANCHOR_LIMB0_REAL` (holds
  `anchor_bytes[0..8]`, bound to `PI[PI_ANCHOR]`). The last-row
  Merkle-walk constraint now binds `S_CURRENT == G_ANCHOR_PROXY`,
  not `S_CURRENT == pi_anchor0`. Walk soundness preserved
  internally; PI value comes from witness bytes.

**Post-Phase-4b-step2b shape_matrix measurements** (same 64-core
FRI Option B host):

| shape | cols | PI bytes | verify ms | proof bytes | vs. pre-Phase-4 |
|-------|-----:|---------:|----------:|------------:|---|
| 1/1   |  815 |      200 |      11.8 |     511 997 | +18 cols, +2 042 B |
| 4/4   | 1658 |      608 |      21.0 |     884 912 | +57 cols, +5 907 B |

Cost of byte-parity closure (all of Phase 4a + 4b-step1 + 4b-step2a
+ 4b-step2b combined) is **+18 cols / +2 KB at 1/1 and +57 cols /
+6 KB at 4/4** — small enough to be below the ≈−156 KB proof-size
delta the range-check migration unlocks.

**Documented V1 soundness trade-off**: Phase 4b-step2a/b decouples
the Poseidon2-w=16 / Merkle-walk constraints from the PI wire.
After this, the STARK proves:

  - `O_CM_CLAIM = Poseidon2-w=16(TAG_CM, d_proxy, pk_d_proxy,
    ivk_commitment_proxy, value, rcm_proxy)` (trace-internal claim 2/6)
  - `S_CURRENT_last_row = poseidon2_merkle_path(proxies)` (trace-
    internal claim 1)
  - `PI[cm+k] = witness.cm_bytes[k*8..(k+1)*8]`,
    `PI[anchor+k] = witness.anchor_bytes[k*8..(k+1)*8]`
    for k ∈ 0..4 (copy-constraint only)

The "real cm = Poseidon2 over real 32-byte inputs" cryptographic
binding is therefore no longer asserted by the STARK; it rests on
§4.1 tx_hash + consensus-level validator checks
(`build_plonky3_public_inputs` reads the Transfer BoC directly).
Closing this residual gap — and similarly for anchor — is the
separately-tracked **Phase 4b-step3** work (multi-week, breaking
MvpWitness wire format change), NOT a V1 launch blocker.

#### Progress log (M-P2 Phase 5, 2026-04-22)

**Phase 5 LANDED** (commit `df42d6e87`): the shipped
`uno_plonky3_prove` / `uno_plonky3_verify` FFI entry points are now
routed to `MvpBatchProver::prove_with_range_check` /
`MvpBatchVerifier::verify_with_range_check`. 3 parallel Explore
sub-agents audited the surface:

1. **FFI surface (Agent A)**: the FFI signatures are unchanged; a
   one-line internal rewire (`Arc<MvpVerifier>` →
   `Arc<MvpBatchVerifier>`, `.verify(...)` → `.verify_with_range_check
   (...)`) is sufficient.
2. **Golden fixtures (Agent B)**: grepped `uno/test/golden/*.hex`;
   none embed proof bytes (only `pubinput_hex`, `tx_hash_hex`,
   `cm_hex`, `nf_hex` etc.). **Zero golden regeneration needed**.
3. **C++ validator (Agent C)**: proof bytes are fully opaque at the
   C++ boundary — no size checks, no magic byte, no version field.
   `uno_plonky3_verify(handle, proof_ptr, pi_ptr)` treats both
   buffers as borrowed slices and hands them to Rust for postcard
   deserialization. **Zero C++ code changes needed**. BoC wire
   format (`UNO_BLOCK_EXTRA_MAX_PROOF_BYTES = 16 MB` at
   `block_wire_format.rs`) unchanged.
4. **ABI version**: NOT bumped. The change is behavioural on the
   Rust side only; the exported function prototypes are
   signature-identical. cbindgen regenerates the header with no
   function-prototype diff.

**Net effect**: M-P2's Phase 3b range-check + Phase 4 byte-parity
are now the DEFAULT shipped path. All 391 lib tests + 5 integration
tests + 66 tosctl tests green through the FFI boundary.

### What remains after Phase 5 is shipped

- **Phase 4b-step3** (task #131 — multi-week cryptographer work):
  migrate MvpWitness `d` / `pk_d` / `ivk` / `rcm` fields from u64
  proxies to `[u8; 32]`; lift Merkle-walk to 4-fe per-level state
  (siblings `[[u8; 32]; 32]`, `S_CURRENT` 1-fe → 4-fe vector);
  expose all 4 output limbs of Poseidon2-w=16 instead of `state[0]`.
  After this, the STARK re-proves `cm = Poseidon2(real d, real pk_d,
  ...)` over real address bytes, closing the documented
  Phase 4b-step2a/b trade-off. Requires breaking MvpWitness wire
  format change + C++ decode-path coordination + golden regen once
  (since PI layout is already stable). Primitives are upstream-
  ready; Merkle AIR must be hand-written (no ready-made in
  `plonky3-uno`).

Nothing else in the Path (iii) tree is V1-blocking. Phase iii-step-3
(§16 / §2.1 consensus-binding decision log amendments) is a
governance task, not a coding task; separately tracked in
`doc/uno-workchain.md §17` amendments.

**Phase iii-step-3** (consensus-binding decision):
- §16 decision-log amendment for the proof system change
- §2.1 text update
- Audit-vendor re-scope if one is engaged
- **2–6 weeks of lead time**

---

## Side-by-side summary

| Path | Predicted 4/4 proof shrink | Verify ms | Effort (elapsed) | Agent-friendly? | Consensus-binding? | Risk |
|------|---------------------------:|----------:|-----------------:|:---------------:|:------------------:|---|
| (i) Option B | −57 % (984 KB) | 24.7 ms | ~30 min code + 2–6 wk decision | setup done by K-fri-analysis | yes (§2.1 vote) | low — soundness margin preserved |
| (ii) claim fusion alone | ~−3 % | small | 2–4 months | no | yes (protocol change) | high — dismantles audit construction |
| (ii) nf reformulation | <1 % | minimal | 1–2 weeks | no | yes | high for tiny gain |
| (iii) batch-stark migration + range-check lookup | **−7 % + future options** | probably −5 % | 1 session feasibility + 1–2 wk implement + 2–6 wk decision | feasibility step yes | yes (§2.1 vote) | medium — needs measurement first |

### Combined strategies

- **Path (i) Option B alone**: proof 2.22 MB → 984 KB (2.3× shrink),
  9.8× to go. Nearly at the verify target.
- **Path (iii) feasibility (iii-step-1) first, then Path (i) B**:
  decision on whether to commit to batch-stark before FRI vote.
  Strongest long-term direction because iii unlocks permanent future
  savings.
- **Best-case stack (i-B + iii-full)**: 2.22 MB → 984 KB (i) → ~800 KB
  (iii range-check) ≈ 8× to go. Still not at §3.4 ~100 KB, but close
  enough that re-scoping §3.4 to ~500 KB becomes the practical v1
  decision.

### The v1 decision ahead

Given the ceiling we can actually reach — ~800 KB worst-case after
combining Paths i+iii — the practical v1 question is:

> **Does the team want to spend ~3–6 months closing the last 8× gap,
> or re-scope §3.4 from 100 KB to ~1 MB and ship?**

A 1 MB worst-case proof at 4/4 is still well within wallet / RPC
bandwidth budgets on the 200 Mbps validator baseline (§1.4a). The
dominant argument for staying with the §3.4 target is wallet prove-side
cost + real-world bandwidth; both relax at larger proof sizes rather
than worsen.

**My recommendation as cryptography engineer**:

1. **Immediate (this week)**: start Path (iii)-step-1 — measure batch-stark
   at current FRI params, unchanged AIR. One agent session. Produces
   data for the §16 decision on committing to batch-stark.
2. **After iii-step-1 returns positive**: queue Path (i)-Option-B
   alongside a batch-stark commitment for the §16 / §2.1 vote. Both
   are consensus-binding; do them as one coordinated decision.
3. **In parallel with the vote**: Path (iii)-step-2 (range-check
   lookup) — this is cryptographer work but doesn't need the vote to
   complete because the result is conditional on (i) passing.
4. **Accept** that §3.4's 100 KB target may need to relax to ~1 MB
   for v1, and pick that up as a §16 amendment alongside the proof
   system change. Make the case explicitly in the v1 release-notes
   with the proof-size-per-validator-bandwidth envelope.

### What I would NOT do

- Spend cryptographer weeks on Path (ii) standalone. The returns are
  too small for the protocol-change risk.
- Vote on Path (i) before Path (iii)-step-1 returns, since iii might
  change the best Option-B config's feasibility.
- Mine any further single-digit optimizations under the current
  StarkConfig — C1–C7 say there isn't a wide-open lane there.

---

## Appendix — references

- `doc/uno-air-optimization-log.md` — 8 prior experiments + C1–C7
- `doc/uno-fri-param-analysis.md` — 15-config FRI sweep + ethSTARK
  soundness formula derivations
- `third-party/plonky3-uno/batch-stark/src/proof.rs` — target proof
  shape for Path (iii)
- `third-party/plonky3-uno/uni-stark/src/proof.rs` — current proof
  shape
- `third-party/plonky3-uno/lookup/src/logup.rs` — LogUp implementation
  (for Path iii-step-2)
- §0.2, §2.1, §2.6, §3.2, §4.2 of `doc/uno-workchain.md` — protocol
  specification that Paths (ii) and (iii) would touch
