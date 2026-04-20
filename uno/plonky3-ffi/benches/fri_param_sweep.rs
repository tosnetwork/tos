//! FRI parameter-space sweep harness — K-fri-analysis.
//!
//! This harness exists to produce the data table in
//! `doc/uno-fri-param-analysis.md`. It measures the cost of varying the
//! §2.1 FRI parameters (`log_blowup`, `num_queries`, `query_pow_bits`)
//! against the production Transfer AIR at the 4/4 worst-case envelope,
//! so any future decision to renegotiate the consensus-binding pin can
//! be made against measured numbers rather than theoretical guidance.
//!
//! For each sweep point the harness reports:
//!
//!   * prove wall time  — best-of-N, release profile, full prove pipeline
//!   * verify wall time — best-of-N, single-threaded
//!   * proof byte size  — postcard-serialized `Proof<SC>` length
//!   * conjectured soundness bits — `log_blowup · num_queries + pow_bits`
//!     (per `FriParameters::conjectured_soundness_bits`, the ethSTARK
//!     conjecture bound, eprint 2021/582)
//!   * proven soundness bits — `(log_blowup · num_queries) / 2 + pow_bits`
//!     (Reed-Solomon Proximity Gaps, eprint 2020/654, cited in
//!     `third-party/plonky3-uno/fri/src/prover.rs`)
//!
//! The sweep grid is deliberately small (~15 points) — spanning the
//! log_blowup = 1..4 corners at num_queries values that would give
//! approximately comparable conjectured soundness — to keep the full run
//! under an hour on a modern multi-core box.
//!
//! Emits a Markdown table on stdout at the end so the output drops into
//! the analysis document verbatim. A copy of every row is also emitted
//! as it's measured on stderr, so a long-running sweep is still
//! interpretable in real time via `tee`.
//!
//! Run:
//!
//! ```bash
//! cargo bench --bench fri_param_sweep
//! ```
//!
//! `harness = false` in `Cargo.toml` so this file's `main` is the
//! entire bench binary.
//!
//! NOT a consensus-critical path. Does NOT modify `prover.rs::build_config`
//! and does NOT change the §2.1 pin. The output is a decision matrix; the
//! decision to flip the pin (if ever taken) remains a deliberate design
//! vote with audit-vendor sign-off.

use std::time::{Duration, Instant};

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks, default_goldilocks_poseidon2_8};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};

use uno_plonky3_ffi::transfer_air::{MvpTransferAir, MvpWitness};

// ---------------------------------------------------------------------------
// Concrete Plonky3 type stack. Mirrors `uno/plonky3-ffi/src/prover.rs` exactly
// EXCEPT for the FRI parameters, which are swept. Keeping every other layer
// identical (Poseidon2-Goldilocks t=8, same MerkleTreeMmcs, same DFT) is
// essential — we are measuring the FRI-parameter axis alone; anything else
// would contaminate the result.
// ---------------------------------------------------------------------------

type Val = Goldilocks;
type Challenge = BinomialExtensionField<Val, 2>;
type Perm8 = Poseidon2Goldilocks<8>;
type SweepHash = PaddingFreeSponge<Perm8, 8, 4, 4>;
type SweepCompress = TruncatedPermutation<Perm8, 2, 4, 8>;
type SweepValMmcs = MerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    SweepHash,
    SweepCompress,
    2,
    4,
>;
type SweepChallengeMmcs = ExtensionMmcs<Val, Challenge, SweepValMmcs>;
type SweepChallenger = DuplexChallenger<Val, Perm8, 8, 4>;
type SweepDft = Radix2DitParallel<Val>;
type SweepPcs = TwoAdicFriPcs<Val, SweepDft, SweepValMmcs, SweepChallengeMmcs>;
type SweepConfig = StarkConfig<SweepPcs, Challenge, SweepChallenger>;

/// Build a `StarkConfig` with the given FRI parameters. Matches
/// `prover.rs::build_config` byte-for-byte in every layer except FRI.
fn build_sweep_config(
    log_blowup: usize,
    num_queries: usize,
    query_pow_bits: usize,
) -> SweepConfig {
    let perm: Perm8 = default_goldilocks_poseidon2_8();
    let hash = SweepHash::new(perm.clone());
    let compress = SweepCompress::new(perm.clone());
    let val_mmcs = SweepValMmcs::new(hash, compress, 0);
    let challenge_mmcs = SweepChallengeMmcs::new(val_mmcs.clone());
    let dft = SweepDft::default();
    let fri_params = FriParameters {
        log_blowup,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: query_pow_bits,
        mmcs: challenge_mmcs,
    };
    let pcs = SweepPcs::new(dft, val_mmcs, fri_params);
    let challenger = SweepChallenger::new(perm);
    SweepConfig::new(pcs, challenger)
}

// ---------------------------------------------------------------------------
// Soundness-bit formulas
// ---------------------------------------------------------------------------

/// ethSTARK-conjecture soundness bits.
/// Source: `third-party/plonky3-uno/fri/src/config.rs::conjectured_soundness_bits`
/// which cites eprint 2021/582.
fn conjectured_soundness_bits(log_blowup: usize, num_queries: usize, pow_bits: usize) -> usize {
    log_blowup * num_queries + pow_bits
}

/// Proven soundness bits under the Proximity Gaps for RS Codes bound
/// (eprint 2020/654, cited in the docstring of
/// `third-party/plonky3-uno/fri/src/prover.rs::prove_fri`). The proven
/// bound divides the query exponent by 2 relative to the conjectured
/// bound; the PoW grind is additive in both.
fn proven_soundness_bits(log_blowup: usize, num_queries: usize, pow_bits: usize) -> usize {
    (log_blowup * num_queries) / 2 + pow_bits
}

// ---------------------------------------------------------------------------
// Sweep grid
// ---------------------------------------------------------------------------

/// Sweep grid from K-fri-analysis task spec. Each tuple is
/// `(log_blowup, num_queries, query_pow_bits)`.
///
/// Chosen to walk the three corners of the FRI cost-triangle:
///
///   - `log_blowup=1` — maximum number of queries but cheapest DFT
///   - `log_blowup=2` — the §2.1 pin; middle ground
///   - `log_blowup=3, 4` — fewer queries but more expensive DFT/commit
///
/// Within each `log_blowup` row, we sweep `num_queries` from "comparable
/// to the pin" down to "Plonky3 default (84)" and further down to the
/// "Plonky3 benchmark preset (~50)" band, with three PoW grinding
/// choices (`0`, `16`, `24` bits).
///
/// `log_blowup=4` at 4/4 is flagged as possibly OOM at 131 GB; the
/// harness skips gracefully on panic (see `run_one`).
const SWEEP_GRID: &[(usize, usize, usize)] = &[
    // log_blowup = 1
    (1, 200, 0),
    (1, 128, 16),
    (1, 84, 24),
    // log_blowup = 2 — the §2.1 PIN is (2, 128, 16)
    (2, 128, 0),
    (2, 128, 16),
    (2, 84, 16),
    (2, 84, 24),
    (2, 52, 16),
    // log_blowup = 3
    (3, 84, 0),
    (3, 84, 16),
    (3, 52, 24),
    (3, 28, 24),
    // log_blowup = 4 — high-memory corner
    (4, 84, 0),
    (4, 52, 16),
];

/// The 4/4 worst-case shape — this is the highest-proof-cost envelope
/// shape per §4.1 and the only shape that exercises every AIR column
/// the production verifier will ever see. All sweep points measure at
/// this shape; §13 P.2 tracking is against this worst case.
const SHAPE: (usize, usize) = (4, 4);

/// Fixed witness seed so re-running the sweep on the same hardware
/// produces reproducible numbers (same trace → same proof bytes).
const WITNESS_SEED: u64 = 0xF_F1_F1_4A;

/// Samples per phase. Kept low (2) because the prove pipeline at 4/4
/// takes 10s–several minutes per call at `log_blowup=4`; a higher
/// sample count would push the full sweep past an hour for no precision
/// gain. Verify is fast enough for 5 samples.
const PROVE_SAMPLES: usize = 2;
const VERIFY_SAMPLES: usize = 5;

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Row {
    log_blowup: usize,
    num_queries: usize,
    pow_bits: usize,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    conjectured_bits: usize,
    proven_bits: usize,
    note: &'static str,
}

fn duration_ms(d: Duration) -> f64 {
    (d.as_nanos() as f64) / 1_000_000.0
}

fn best_of<F: FnMut()>(n: usize, mut f: F) -> Duration {
    let mut best = Duration::from_secs(u64::MAX / 2);
    for _ in 0..n {
        let t0 = Instant::now();
        f();
        let dt = t0.elapsed();
        if dt < best {
            best = dt;
        }
    }
    best
}

fn run_one(
    witness: &MvpWitness,
    log_blowup: usize,
    num_queries: usize,
    pow_bits: usize,
) -> Option<Row> {
    let (n_s, n_o) = SHAPE;
    let air = MvpTransferAir::new(n_s, n_o);
    let pi = witness.public_inputs();

    let config = build_sweep_config(log_blowup, num_queries, pow_bits);

    // Warm-up prove + verify: amortize any lazy-init cost.
    //
    // NOTE on `log_blowup = 1`: Plonky3's quotient argument requires the
    // blowup factor to be at least as large as the quotient polynomial's
    // degree, which for the Uno Transfer AIR (Poseidon2 S-box + balance
    // constraint) is > 2. With `log_blowup = 1` the prover DOES produce
    // a proof, but verify returns `OodEvaluationMismatch` because the
    // constraint-polynomial quotient no longer divides evenly. This is
    // an AIR-structural limit — not an FRI-parameter trade — and so the
    // sweep cannot measure `log_blowup = 1` on the current AIR. We
    // capture this by detecting the verify error and tagging the row
    // "log_blowup < AIR quotient degree" rather than panicking.
    let trace = witness.generate_trace();
    let warmup_proof = prove(&config, &air, trace, &pi);
    let warmup_proof_bytes =
        postcard::to_allocvec(&warmup_proof).expect("postcard serialize");
    if verify(&config, &air, &warmup_proof, &pi).is_err() {
        // AIR's quotient degree exceeds this blowup. Mark skipped.
        return None;
    }

    // Prove: re-run `PROVE_SAMPLES` times, full pipeline (trace generation
    // included — we regenerate the trace per sample because `prove`
    // consumes it by value, matching the FFI entry point's behavior).
    let prove_best = best_of(PROVE_SAMPLES, || {
        let trace = witness.generate_trace();
        let _ = prove(&config, &air, trace, &pi);
    });

    // Verify: reuse the warm-up proof for pure verifier cost.
    let verify_best = best_of(VERIFY_SAMPLES, || {
        verify(&config, &air, &warmup_proof, &pi)
            .expect("sample verify must succeed");
    });

    Some(Row {
        log_blowup,
        num_queries,
        pow_bits,
        prove_ms: duration_ms(prove_best),
        verify_ms: duration_ms(verify_best),
        proof_bytes: warmup_proof_bytes.len(),
        conjectured_bits: conjectured_soundness_bits(log_blowup, num_queries, pow_bits),
        proven_bits: proven_soundness_bits(log_blowup, num_queries, pow_bits),
        note: "",
    })
}

fn main() {
    eprintln!(
        "K-fri-analysis: sweeping {} FRI param triples at shape {}/{}",
        SWEEP_GRID.len(),
        SHAPE.0,
        SHAPE.1,
    );

    // Build the witness ONCE. Regenerating per point would add ~constant
    // witness-construction cost to every prove call and would not change
    // the trace, so we share it.
    let witness = MvpWitness::deterministic_valid(SHAPE.0, SHAPE.1, WITNESS_SEED);
    let pi_bytes = witness.public_inputs_bytes();
    eprintln!(
        "  witness={}B PI={}B (shape = 4/4 worst case)",
        witness.encode().len(),
        pi_bytes.len(),
    );

    let mut rows: Vec<Row> = Vec::with_capacity(SWEEP_GRID.len());
    for (i, &(log_blowup, num_queries, pow_bits)) in SWEEP_GRID.iter().enumerate() {
        eprintln!(
            "  [{:>2}/{:>2}] log_blowup={} num_queries={:>3} pow_bits={:>2} ...",
            i + 1,
            SWEEP_GRID.len(),
            log_blowup,
            num_queries,
            pow_bits,
        );
        let t0 = Instant::now();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_one(&witness, log_blowup, num_queries, pow_bits)
        })) {
            Ok(Some(row)) => {
                eprintln!(
                    "     done in {:.1}s: prove={:.1}ms verify={:.2}ms proof={}B conj={} proven={}",
                    t0.elapsed().as_secs_f64(),
                    row.prove_ms,
                    row.verify_ms,
                    row.proof_bytes,
                    row.conjectured_bits,
                    row.proven_bits,
                );
                rows.push(row);
            }
            Ok(None) => {
                eprintln!(
                    "     skipped: log_blowup={} incompatible with AIR quotient degree",
                    log_blowup,
                );
                rows.push(Row {
                    log_blowup,
                    num_queries,
                    pow_bits,
                    prove_ms: 0.0,
                    verify_ms: 0.0,
                    proof_bytes: 0,
                    conjectured_bits: conjectured_soundness_bits(
                        log_blowup, num_queries, pow_bits,
                    ),
                    proven_bits: proven_soundness_bits(log_blowup, num_queries, pow_bits),
                    note: "AIR-incompatible (blowup < quotient degree)",
                });
            }
            Err(_) => {
                eprintln!(
                    "     PANIC (probable OOM at log_blowup={} on 4/4) — row will be marked skipped",
                    log_blowup,
                );
                rows.push(Row {
                    log_blowup,
                    num_queries,
                    pow_bits,
                    prove_ms: 0.0,
                    verify_ms: 0.0,
                    proof_bytes: 0,
                    conjectured_bits: conjectured_soundness_bits(
                        log_blowup, num_queries, pow_bits,
                    ),
                    proven_bits: proven_soundness_bits(log_blowup, num_queries, pow_bits),
                    note: "OOM/panic",
                });
            }
        }
    }

    // ---- Emit Markdown table (stdout) -------------------------------------
    println!();
    println!("<!-- K-fri-analysis: generated by benches/fri_param_sweep.rs at shape 4/4 -->");
    println!(
        "| log_blowup | num_queries | pow_bits | prove ms | verify ms | proof bytes | conjectured bits | proven bits | note |"
    );
    println!(
        "|-----------:|------------:|---------:|---------:|----------:|------------:|-----------------:|------------:|------|"
    );
    for r in &rows {
        if r.note.is_empty() {
            println!(
                "| {:>10} | {:>11} | {:>8} | {:>8.1} | {:>9.2} | {:>11} | {:>16} | {:>11} |      |",
                r.log_blowup,
                r.num_queries,
                r.pow_bits,
                r.prove_ms,
                r.verify_ms,
                r.proof_bytes,
                r.conjectured_bits,
                r.proven_bits,
            );
        } else {
            println!(
                "| {:>10} | {:>11} | {:>8} |        — |         — |           — | {:>16} | {:>11} | {} |",
                r.log_blowup,
                r.num_queries,
                r.pow_bits,
                r.conjectured_bits,
                r.proven_bits,
                r.note,
            );
        }
    }
    println!();
    println!("Current §2.1 pin: log_blowup=2, num_queries=128, pow_bits=16 (conjectured {} / proven {} bits)",
        conjectured_soundness_bits(2, 128, 16),
        proven_soundness_bits(2, 128, 16));
}
