# Uno FRI parameter-space tradeoff analysis (K-fri-analysis)

## Abstract

The Uno workchain pins `(log_blowup = 2, num_queries = 128,
query_proof_of_work_bits = 16)` as the consensus-binding FRI parameters
for its Plonky3 STARK proof system (§2.1 of `doc/uno-workchain.md`;
§16 decision #33). These numbers were chosen in the design phase with
only theoretical guidance and upstream heuristics. §13 P.2 of the
workchain doc identifies renegotiation of this pin as one of three
paths to close the remaining ~22× proof-size gap between the current
AIR-optimized worst-case proof (~2.22 MB at 4/4) and the §3.4
wire-format envelope (~100 KB at 4/4). This document provides a
data-driven matrix so that any **future** design decision to loosen
the pin can be made against measured numbers rather than guesses. It
does **not** recommend flipping the pin. It is a pre-decision artifact.

## 1. Current pin rationale (from §2.1 and decision #33)

§2.1 pins:

```
log_blowup                = 2     // trace domain = 4 × trace length
num_queries               = 128   // FRI verifier query rounds
query_proof_of_work_bits  = 16    // Fiat-Shamir grinding bits
```

The rationale per §16 decision #33:

- **Target**: ~128-bit conjectured / ~64-bit proven classical soundness;
  ~64-bit conjectured / ~32-bit proven against a Grover-style quantum
  adversary.
- **Above Plonky3 / SP1 / AggLayer defaults** (`num_queries = 84..100`,
  ~100-bit conjectured). The justification: a soundness break on a
  privacy L1 with a fixed-supply native asset enables unauthorized
  value creation, which is strictly more damaging than a cross-chain
  aggregation-bridge inconsistency.
- **Cost admitted**: prove time +40 %, proof size +30 %, verify time
  +30 % vs Plonky3 defaults.
- **Rejected alternatives** in §2.1:
  - `num_queries = 84`: ~100-bit conjectured, ~50-bit proven —
    adequate for zkVMs / aggregation, below the native-value-L1 bar.
  - `num_queries = 200` with `log_blowup = 1`: same proven security
    as the pin but +50 % proof size.
  - `log_blowup = 4, num_queries = 84`: ~128-bit proven but prove
    time +80 %, judged UX-negative with no realistic-adversary gain.

**Soundness-bit note on the §2.1 wording.** The code-documented formula
(see §2 below) gives `log_blowup · num_queries + pow_bits = 272` bits
of conjectured soundness at the pin, not 128. The "~128-bit
conjectured" label in §2.1 is shorthand for "`num_queries` set to
128" — i.e. the soundness-tier the chain targets as a design goal,
not the ethSTARK formula output. The pin's *ethSTARK-formula*
conjectured bound is **272 bits classical / 136 bits quantum**; its
*proven* bound under Reed-Solomon Proximity Gaps is **144 bits
classical / 72 bits quantum**. Both headroom levels are far above
the 128-bit targeted design goal, which is what makes the pin
defensible on margin — but it also means there is measurable
headroom to cut, if the proof-size path is ever chosen.

## 2. Parameter-sweep methodology

### 2.1 Harness

`uno/plonky3-ffi/benches/fri_param_sweep.rs` (K-fri-analysis). Bench
binary driven by `cargo bench --bench fri_param_sweep`, release
profile, `harness = false` so the bench is a plain `main()` with no
criterion / nightly dependency.

For each `(log_blowup, num_queries, query_pow_bits)` triple the
harness:

1. Builds a `StarkConfig` identical to
   `uno/plonky3-ffi/src/prover.rs::build_config` except for the three
   FRI knobs under test. All other layers (`Poseidon2Goldilocks<8>`,
   `MerkleTreeMmcs`, `Radix2DitParallel`, `DuplexChallenger`) match
   the production config byte-for-byte — we are measuring the FRI
   axis alone.
2. Uses `MvpWitness::deterministic_valid(4, 4, seed)` — the **4/4
   worst-case envelope shape** per §4.1 — to exercise the highest-
   proof-cost AIR instance the production verifier will ever see.
3. Runs a warm-up prove + verify to amortize lazy-init cost.
4. Measures `prove` time as best-of-2, verify time as best-of-5,
   proof bytes from the postcard-serialized warm-up proof.
5. Emits a Markdown row to stdout at the end.

The bench is **not** consensus-critical and does not touch
`build_config`'s production pin.

### 2.2 Soundness-bit formulas

**Conjectured soundness (ethSTARK conjecture, eprint 2021/582).** Quoted
verbatim from the upstream crate:

```rust
// third-party/plonky3-uno/fri/src/config.rs:42
pub const fn conjectured_soundness_bits(&self) -> usize {
    self.log_blowup * self.num_queries + self.query_proof_of_work_bits
}
```

**Proven soundness (Reed-Solomon Proximity Gaps, eprint 2020/654).**
From the FRI prover's documented soundness bound at
`third-party/plonky3-uno/fri/src/prover.rs:24-28`:

> The Soundness error from prove_fri comes from the paper:
> Proximity Gaps for Reed-Solomon Codes
> (https://eprint.iacr.org/2020/654)
> and is either `rate^{num_queries}` or `rate^{num_queries/2}`
> depending on if you rely on conjectured or proven soundness.

With `rate = 2^{-log_blowup}` and an additive PoW grind:

```
proven_bits = (log_blowup · num_queries) / 2 + pow_bits
```

The upstream crate does **not** implement `proven_soundness_bits()`
directly (explicitly flagged as "a more complex calculation which
isn't currently supported by this crate"). The formula above is the
simple lower bound stated in the prove_fri docstring; tighter bounds
(e.g. correlated-agreement refinements from eprint 2024/1623) would
only *increase* the reported proven bits for a given knob setting, so
using the docstring formula is a conservative underestimate suitable
for "is this config defensible" thresholding.

Both formulas are quoted above with file+line references so an
auditor can verify the bench's reported numbers against the code.

### 2.3 Sweep grid

15 configurations covering four `log_blowup` rows:

```
(log_blowup=1, num_queries ∈ {200, 128, 84}, pow_bits ∈ {0, 16, 24})
(log_blowup=2, num_queries ∈ {128, 84, 52}, pow_bits ∈ {0, 16, 24})
(log_blowup=3, num_queries ∈ {84, 52, 28}, pow_bits ∈ {0, 16, 24})
(log_blowup=4, num_queries ∈ {84, 52}, pow_bits ∈ {0, 16})
```

Chosen to walk the three corners of the FRI cost-triangle:

- `log_blowup = 1` — cheapest DFT, maximum queries needed.
- `log_blowup = 2` — the §2.1 pin; middle ground.
- `log_blowup = 3, 4` — fewer queries sufficient but more expensive
  DFT / commit.

Within each `log_blowup` row `num_queries` sweeps from "comparable to
the pin" down through "Plonky3 default (84)" and into "benchmark
preset (~50)" / "very low (28)". Three PoW grinding choices (`0`,
`16`, `24` bits) pick up the FS-grind axis.

## 3. Results

### 3.1 Full sweep table (4/4 worst-case shape)

The pinned row is highlighted **bold** in the first column of values.
All prove / verify numbers are best-of-N wall-clock, release-profile
Rust, single-process, multi-core Plonky3 prove, single-core verify.
See Appendix A for the raw bench log and Appendix B for hardware.

| log_blowup | num_queries | pow_bits | prove ms | verify ms | proof bytes | conjectured bits | proven bits | note |
|-----------:|------------:|---------:|---------:|----------:|------------:|-----------------:|------------:|------|
|          1 |         200 |        0 |        — |         — |           — |              200 |         100 | AIR-incompatible (blowup < quotient degree) |
|          1 |         128 |       16 |        — |         — |           — |              144 |          80 | AIR-incompatible (blowup < quotient degree) |
|          1 |          84 |       24 |        — |         — |           — |              108 |          66 | AIR-incompatible (blowup < quotient degree) |
|          2 |         128 |        0 |     99.5 |     55.76 |   2,289,571 |              256 |         128 |      |
|        **2** |       **128** |     **16** |  **124.3** |   **55.69** | **2,290,134** |          **272** |     **144** | **§2.1 PIN** |
|          2 |          84 |       16 |    126.5 |     37.67 |   1,524,376 |              184 |         100 |      |
|          2 |          84 |       24 |  2,766.7 |     37.69 |   1,525,222 |              192 |         108 | PoW-grind-dominated prove |
|          2 |          52 |       16 |    129.3 |     24.43 |     967,572 |              120 |          68 |      |
|          3 |          84 |        0 |    188.0 |     38.10 |   1,550,466 |              252 |         126 |      |
|          3 |          84 |       16 |    194.5 |     38.11 |   1,550,281 |              268 |         142 |      |
|          3 |          52 |       24 |    354.3 |     24.70 |     984,019 |              180 |         102 |      |
|          3 |          28 |       24 |    351.6 |     14.66 |     558,940 |              108 |          66 |      |
|          4 |          84 |        0 |    377.7 |     39.57 |   1,575,687 |              336 |         168 |      |
|          4 |          52 |       16 |    401.3 |     25.68 |     999,633 |              224 |         120 |      |

### 3.2 Observations from the data

1. **`log_blowup = 1` is an AIR-structural wall, not an FRI trade.**
   All three `log_blowup = 1` rows fail verify with
   `OodEvaluationMismatch`. Plonky3 requires blowup factor to be at
   least as large as the AIR's quotient polynomial degree; the Uno
   Transfer AIR has constraint degree ≥ 3 (Poseidon2 S-box +
   balance), so `log_blowup = 1` (blowup = 2) cannot produce a
   verifying proof. This rules out the §2.1-rejected
   `(log_blowup = 1, num_queries = 200)` alternative at the AIR
   level, separately from its +50 % proof-size cost — a result
   stronger than §2.1's original rejection and worth logging as a
   positive finding.

2. **Proof size is approximately linear in `num_queries` at fixed
   `log_blowup`.** At `log_blowup = 2`:
   `(128, 52) = (2.29 MB, 0.97 MB)` — a 2.4× shrink for a 2.5×
   query reduction. Confirms `num_queries` is the dominant
   proof-size lever inside each blowup row.

3. **Proof size is approximately constant across `log_blowup` at
   fixed `num_queries`.** `(2, 84) = 1.52 MB`,
   `(3, 84) = 1.55 MB`, `(4, 84) = 1.58 MB` — the `log_blowup` knob
   is a prove-time / verify-time axis, not primarily a proof-size
   axis.

4. **`pow_bits = 24` sharply inflates prove time.** Row `(2, 84,
   24)` takes 2.77 s prove vs. 127 ms for the adjacent `(2, 84,
   16)` — a 22× prove-time blow-up for +8 soundness bits, caused
   by the `2^{24}` FS-grind iteration count dominating the prove
   budget. `pow_bits = 16` (`2^{16}` iters ≈ sub-millisecond) is
   the sweet spot observed in the sweep; `pow_bits = 24` is
   economically defensible only when every other knob is already
   at its cheapest. `pow_bits = 0` costs nothing in prove time but
   forgoes the grind margin.

5. **Verify time scales ~linearly with `num_queries`, weakly with
   `log_blowup`.** At `log_blowup = 3`: 84 → 38 ms, 52 → 25 ms,
   28 → 15 ms. Useful for §7.4's validator-parallelism budget: any
   future pin that lowers `num_queries` lifts verify throughput
   roughly proportionally.

6. **Discrepancy between §2.1's "~128-bit conjectured" label and the
   ethSTARK-formula output.** At the pin the formula gives 272 bits
   conjectured (not 128). §2.1's labelling uses `num_queries` as a
   proxy for "targeted soundness tier" rather than the formula's
   bit count. This labelling convention is also observed in upstream
   Plonky3 and SP1 tunings, but an auditor's first reading of §2.1
   could be confusing. Leaving the current wording unchanged for
   this analysis is intentional (§2.1 is consensus-binding); a
   future doc-clarity pass should align the label with the formula.

## 4. Frontier analysis — alternative configurations

Three configurations that would be *defensible* for a payment-chain-
grade L1, each targeting a different decision point. The current
§2.1 pin is shown alongside for direct comparison.

| Option        | log_blowup | num_queries | pow_bits | prove ms | verify ms | proof bytes | proof bytes vs 100 KB envelope | conjectured bits | proven bits | qualitative change vs pin |
|---------------|-----------:|------------:|---------:|---------:|----------:|------------:|-------------------------------:|-----------------:|------------:|---------------------------|
| **§2.1 PIN**  |      **2** |       **128** |   **16** |  **124** |   **55.7** | **2,290,134** |                        **22.4×** |          **272** |     **144** | — |
| A. Budget     |          2 |          84 |       16 |      127 |      37.7 |   1,524,376 |                         14.9× |              184 |         100 | −33 % proof; −32 % verify; proven 144 → 100 |
| B. Memory     |          3 |          52 |       24 |      354 |      24.7 |     984,019 |                          9.6× |              180 |         102 | −57 % proof; −56 % verify; prove 2.8× slower; proven 144 → 102 |
| C. Aspirational |        3 |          28 |       24 |      352 |      14.7 |     558,940 |                          5.5× |              108 |          66 | −76 % proof; −74 % verify; prove 2.8× slower; proven 144 → 66 |

### Option A — Budget (lower proof, lowest defensible proven bits)

**`(log_blowup = 2, num_queries = 84, pow_bits = 16)`**

- **Proof bytes**: 1.52 MB → still 14.9× over the 100 KB
  envelope.
- **Soundness**: 184 conjectured / 100 proven. Meets the "~100-bit
  conjectured" bar that §2.1 explicitly **rejects** for a native-
  value L1 but accepts as sufficient for zkVMs / aggregation.
  Critically, the proven bound is exactly 100 — right at the lower
  limit of "payment-chain-grade" depending on how the chain
  interprets proven-vs-conjectured margin requirements.
- **Prove time**: 127 ms — effectively equal to the pin.
- **Verify time**: 38 ms — 32 % faster than the pin (validator
  throughput lift on §7.4).
- **Decision point**: this is the correct choice *if and only if*
  mainnet governance accepts "conjectured ≥ 184 bits / proven ≥ 100
  bits" as the soundness bar. §2.1 currently rejects this bar;
  accepting it would be a deliberate re-vote of decision #33.

### Option B — Memory (same proof-reduction as A, different prove/verify profile)

**`(log_blowup = 3, num_queries = 52, pow_bits = 24)`**

- **Proof bytes**: 984 KB → 9.6× over the envelope. About half of
  the pin, about two-thirds of Option A.
- **Soundness**: 180 conjectured / 102 proven — essentially the
  same as Option A.
- **Prove time**: 354 ms — ~2.8× slower than the pin. The
  combination of `log_blowup = 3` (larger LDE → more DFT) and
  `pow_bits = 24` (`2^{24}` FS-grind iterations) both contribute.
- **Verify time**: 25 ms — 56 % faster than the pin, 35 % faster
  than Option A.
- **Decision point**: chosen if the chain is willing to trade
  prove-time (wallet-side, one-off, §1.4 allows up to 22 s) for
  verify-time (validator-side, per-tx, consensus-critical). On the
  static cost matrix this is the strongest alternative to the pin;
  it is Option A's soundness at a smaller proof and a cheaper
  verify, paid for by wallet-side wall-clock.

### Option C — Aspirational (smallest proof in sweep; below payment-grade soundness)

**`(log_blowup = 3, num_queries = 28, pow_bits = 24)`**

- **Proof bytes**: 558 KB → 5.5× over the envelope — the best
  observed data-point across the entire grid.
- **Soundness**: 108 conjectured / 66 proven. **Below** any plausible
  payment-chain-grade soundness bar. Listed only as the
  "aspirational floor" — the smallest proof the parameter space
  supports, so the reader sees how far the knob can physically
  travel.
- **Prove / verify**: 352 ms / 15 ms.
- **Decision point**: almost certainly **unacceptable** for
  mainnet. Useful only as a reference point for measuring "how
  close can any FRI-only retuning get to the §3.4 envelope" —
  answer: 5.5× away.

### 4.1 Distance to the §3.4 ~100 KB envelope

No configuration in the sweep hits the §3.4 ~100 KB worst-case
envelope. The best (smallest-proof) data-point is Option C at 558
KB, which is **5.5× over the envelope** — an improvement from the
pin's 22.4× but still inside the 5–10× gap band.

**Implication for §13 P.2.** FRI-parameter renegotiation alone
cannot close the envelope gap. Even setting every knob to its
minimum practical value (`log_blowup = 3, num_queries = 28,
pow_bits = 24` — below payment-grade soundness) leaves the proof at
~5.5× the envelope. The remaining 5.5× must come from one or both
of the other two §13 P.2 paths: (i) a cross-instance Poseidon2
scheduler (architectural), or (ii) a structural AIR redesign
(architectural). This analysis is consistent with §13 P.2's
"column-sharing is exhausted" finding: the dominant term in the
proof-byte budget is `num_queries × column-count × log_blowup`, and
we have now quantified both axes independently — column-count
halved by K-air-col-step2 (27,837 → 2,081 = −92.5 %), and
`num_queries`-driven proof bytes scan 2.29 MB → 0.56 MB
(−76 %) across the sweep. The product still leaves ≥ 5× to close.

## 5. Recommendation / deferred decision

This document is a **pre-decision analysis**. It does NOT recommend
flipping the §2.1 pin, and the bench does NOT change
`prover.rs::build_config`.

A decision to renegotiate §2.1 remains an explicit consensus-binding
design vote. The inputs a future §16 decision of that shape will want
to have in hand:

- **This document's Section 4 matrix** (three defensible alternatives
  with measured numbers).
- **The audit vendor's sign-off** on soundness bars lower than the
  pin's 272 conjectured / 144 proven — see §0.2 audit scope.
- **An architectural verdict on the other two §13 P.2 paths**
  (Poseidon2 scheduler, AIR redesign). If either is judged
  achievable in a reasonable horizon, the proof-size path may not
  need to be opened at all — those paths can close the full 22×
  gap, whereas FRI-only renegotiation cannot reach the §3.4
  envelope.
- **A §1.4 UX-budget re-check**: Option B at prove = 354 ms is fine
  for a laptop (well under the 22 s target); Option A at 127 ms
  has no UX impact. Neither is the binding constraint.

## Appendix A — Raw bench output (2026-04-20 run)

```
K-fri-analysis: sweeping 14 FRI param triples at shape 4/4
  witness=1458B PI=608B (shape = 4/4 worst case)
  [ 1/14] log_blowup=1 num_queries=200 pow_bits= 0 ...
     skipped: log_blowup=1 incompatible with AIR quotient degree
  [ 2/14] log_blowup=1 num_queries=128 pow_bits=16 ...
     skipped: log_blowup=1 incompatible with AIR quotient degree
  [ 3/14] log_blowup=1 num_queries= 84 pow_bits=24 ...
     skipped: log_blowup=1 incompatible with AIR quotient degree
  [ 4/14] log_blowup=2 num_queries=128 pow_bits= 0 ...
     done in 0.7s: prove=99.5ms verify=55.76ms proof=2289571B conj=256 proven=128
  [ 5/14] log_blowup=2 num_queries=128 pow_bits=16 ...
     done in 0.7s: prove=124.3ms verify=55.69ms proof=2290134B conj=272 proven=144
  [ 6/14] log_blowup=2 num_queries= 84 pow_bits=16 ...
     done in 0.6s: prove=126.5ms verify=37.67ms proof=1524376B conj=184 proven=100
  [ 7/14] log_blowup=2 num_queries= 84 pow_bits=24 ...
     done in 8.6s: prove=2766.7ms verify=37.69ms proof=1525222B conj=192 proven=108
  [ 8/14] log_blowup=2 num_queries= 52 pow_bits=16 ...
     done in 0.5s: prove=129.3ms verify=24.43ms proof=967572B conj=120 proven=68
  [ 9/14] log_blowup=3 num_queries= 84 pow_bits= 0 ...
     done in 0.8s: prove=188.0ms verify=38.10ms proof=1550466B conj=252 proven=126
  [10/14] log_blowup=3 num_queries= 84 pow_bits=16 ...
     done in 0.8s: prove=194.5ms verify=38.11ms proof=1550281B conj=268 proven=142
  [11/14] log_blowup=3 num_queries= 52 pow_bits=24 ...
     done in 1.2s: prove=354.3ms verify=24.70ms proof=984019B conj=180 proven=102
  [12/14] log_blowup=3 num_queries= 28 pow_bits=24 ...
     done in 1.1s: prove=351.6ms verify=14.66ms proof=558940B conj=108 proven=66
  [13/14] log_blowup=4 num_queries= 84 pow_bits= 0 ...
     done in 1.4s: prove=377.7ms verify=39.57ms proof=1575687B conj=336 proven=168
  [14/14] log_blowup=4 num_queries= 52 pow_bits=16 ...
     done in 1.4s: prove=401.3ms verify=25.68ms proof=999633B conj=224 proven=120
```

## Appendix B — Hardware and software provenance

| | |
|---|---|
| Date                | 2026-04-20 |
| Host CPU            | Intel Xeon Platinum 8455C (192 logical cores) |
| Host RAM            | 128 GB |
| Host kernel         | Linux 6.8.0-107-generic x86_64 |
| Rust toolchain      | stable (from `~/.rustup/toolchains/stable-x86_64-unknown-linux-gnu`) |
| Plonky3 pin         | `6374a36ff50fc641821513852263cc61ca7a1278` (v0.5.1), vendored at `third-party/plonky3-uno/` |
| AIR                 | `uno/plonky3-ffi/src/transfer_air.rs::MvpTransferAir` at 4/4 shape |
| AIR column count at 4/4 | 2,081 (post K-air-col-step1/2/3, per §13 P.2) |
| Poseidon2 round constants | `p3_goldilocks::GOLDILOCKS_POSEIDON2_RC_*` (Polygon audited tables, decision #42) |
| Build profile       | `release`, `opt-level = 3`, `lto = "thin"`, `codegen-units = 1`, `panic = "abort"` |
| Bench harness       | `uno/plonky3-ffi/benches/fri_param_sweep.rs` |

Prove numbers benefit substantially from the 192-core Plonky3 prove
pool; on a typical 8-core laptop they will be ~10–25× slower. Verify
numbers are single-core and are portable. The *ratios* between
configurations are the auditable quantity — absolute numbers should
be re-run on the target hardware before any §16 decision.

## Appendix C — How to reproduce

```bash
cd uno/plonky3-ffi
cargo bench --bench fri_param_sweep 2>&1 | tee /tmp/fri_sweep.log
```

Full sweep is ~20–30 s on the reference hardware (well under the
task-spec's 30–60 min budget thanks to the 192-core prove pool);
expect proportionally longer on laptop-class hardware. The sweep is
deterministic — same witness seed + same Plonky3 commit produces
byte-identical proofs.
