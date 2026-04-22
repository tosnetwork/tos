//! Shape-matrix prove/verify benchmark harness — K-air-bench.
//!
//! Standardized measurement tool for the six representative envelope shapes
//! covered by the Uno Transfer AIR. P.2 column-reduction work (K-air-col-*)
//! has historically reported one-off numbers at 4/4 worst case and 1/1;
//! this harness is the reproducible replacement any future P.2 optimization
//! attempt (or the external audit) can re-run to verify status.
//!
//! Measured per shape `(n_spends, n_outputs)`:
//!
//!   * column count         — `transfer_air::air_width(S, O)`
//!   * public-input bytes   — `64 + 64·S + 72·O` (= `air_public_inputs_wire_len`)
//!   * prove wall time      — best of 5 release-profile runs
//!   * verify wall time     — best of 5 release-profile runs, single-threaded
//!   * proof byte size      — postcard-serialized proof length
//!
//! The six shapes cover the envelope extremes:
//!
//! ```text
//!   (1,1)  smallest shape — trace width minimum
//!   (1,2), (2,2), (2,3), (3,3)  intermediate shapes — column-scaling curve
//!   (4,4)  largest shape — P.2 worst case, consensus bound
//! ```
//!
//! Emits a Markdown table on stdout at the end of the run so the output
//! drops straight into commit messages and the §13 roadmap without reflow.
//!
//! Not a consensus-critical path. Uses `std::time::Instant` — that's fine
//! here because the harness is wallet/operator-side only, never called
//! from any FFI or validator entry point.
//!
//! Run (must be release for the numbers to be meaningful):
//!
//! ```bash
//! cargo bench --bench shape_matrix
//! ```
//!
//! `harness = false` is set in Cargo.toml so this file's `main` is the
//! entire bench binary — no `#[bench]` nightly requirement, no criterion
//! dependency on the workspace surface.

use std::time::{Duration, Instant};

use uno_plonky3_ffi::prover::MvpProver;
use uno_plonky3_ffi::transfer_air::{air_public_inputs_wire_len, air_width, MvpWitness};
use uno_plonky3_ffi::verifier::MvpVerifier;
use uno_plonky3_ffi::Plonky3Status;

/// Number of measurement iterations per shape per phase (prove / verify).
/// The reported number is the *minimum* of these samples — the standard
/// "best of N" pattern that filters out scheduling jitter while staying
/// deterministic and short enough to keep the full harness under a minute
/// on a typical dev box at 4/4 worst case.
const SAMPLES: usize = 5;

/// The six envelope shapes this harness measures, in the order they appear
/// in the emitted Markdown table. Chosen to span the (1,1)..(4,4) envelope
/// along both axes without running all 16 combinations (the interior shapes
/// are well-approximated by the diagonal + one off-diagonal point).
const SHAPES: &[(usize, usize)] = &[(1, 1), (1, 2), (2, 2), (2, 3), (3, 3), (4, 4)];

/// One row of the output table.
struct Row {
    shape: (usize, usize),
    cols: usize,
    pi_bytes: usize,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
}

/// Deterministic seed for `MvpWitness::deterministic_valid`. Keeping this
/// fixed per shape means the measured numbers are reproducible run to run
/// on the same machine — useful when bisecting a perf regression.
fn seed_for(shape: (usize, usize)) -> u64 {
    // Pack `(S, O)` into the low nibbles and XOR a magic so two different
    // shapes never collide with the default seed used by the unit tests.
    let (s, o) = shape;
    0xBEEF_0000_0000_0000 ^ ((s as u64) << 8) ^ (o as u64)
}

/// Wall-clock a closure `SAMPLES` times and return the minimum duration.
/// The minimum (not mean) is what matters for "how fast can this go on
/// this hardware" — means are pulled right by scheduler noise and heat.
fn best_of<F: FnMut()>(mut f: F) -> Duration {
    let mut best = Duration::from_secs(u64::MAX / 2);
    for _ in 0..SAMPLES {
        let t0 = Instant::now();
        f();
        let dt = t0.elapsed();
        if dt < best {
            best = dt;
        }
    }
    best
}

fn duration_ms(d: Duration) -> f64 {
    (d.as_nanos() as f64) / 1_000_000.0
}

fn measure_shape(shape: (usize, usize)) -> Row {
    let (n_s, n_o) = shape;
    let prover = MvpProver::new();
    let verifier = MvpVerifier::new();

    // Build the witness once — witness construction is not what we're
    // measuring, and regenerating per sample would inflate prove-side
    // numbers with irrelevant setup cost.
    let witness = MvpWitness::deterministic_valid(n_s, n_o, seed_for(shape));
    let witness_bytes = witness.encode();

    // Warm-up prove + verify: first run amortizes one-time lazy-init
    // costs (Poseidon2 round-constant table materialization, etc.) so
    // they don't skew the "best of SAMPLES" minimum.
    let (proof_bytes, pi_bytes) = prover
        .prove(&witness_bytes)
        .unwrap_or_else(|e| panic!("warmup prove failed for shape {:?}: {:?}", shape, e));
    let status = verifier.verify(&proof_bytes, &pi_bytes);
    assert_eq!(
        status,
        Plonky3Status::Ok,
        "warmup verify failed for shape {:?}: {:?}",
        shape,
        status,
    );

    // Prove phase: re-prove per sample so we measure the full prove
    // pipeline (trace generation included — matches the FFI entry
    // point's behavior).
    let prove_best = best_of(|| {
        let _ = prover
            .prove(&witness_bytes)
            .expect("prove should succeed on deterministic_valid witness");
    });

    // Verify phase: reuse the single warm-up proof/PI pair so we
    // measure pure verifier cost. Single-threaded by virtue of
    // `MvpVerifier::verify` being synchronous; Plonky3's internal
    // Rayon pool only kicks in on proving.
    let verify_best = best_of(|| {
        let status = verifier.verify(&proof_bytes, &pi_bytes);
        assert_eq!(status, Plonky3Status::Ok);
    });

    Row {
        shape,
        cols: air_width(n_s, n_o),
        pi_bytes: air_public_inputs_wire_len(n_s, n_o),
        prove_ms: duration_ms(prove_best),
        verify_ms: duration_ms(verify_best),
        proof_bytes: proof_bytes.len(),
    }
}

fn main() {
    eprintln!(
        "K-air-bench: measuring {} shapes × {} samples (best-of) each phase",
        SHAPES.len(),
        SAMPLES,
    );

    let mut rows: Vec<Row> = Vec::with_capacity(SHAPES.len());
    for &shape in SHAPES {
        eprintln!("  measuring shape {}/{} ...", shape.0, shape.1);
        rows.push(measure_shape(shape));
    }

    // Emit the Markdown table on stdout. Right-align the numeric columns
    // (matches the task spec's `-----:` separator) so wide numbers line up
    // cleanly when pasted into commit messages.
    println!();
    println!("| shape | cols | PI bytes | prove ms | verify ms | proof bytes |");
    println!("|-------|-----:|---------:|---------:|----------:|------------:|");
    for r in &rows {
        println!(
            "| {}/{}   | {:>4} | {:>8} | {:>8.1} | {:>9.1} | {:>11} |",
            r.shape.0, r.shape.1, r.cols, r.pi_bytes, r.prove_ms, r.verify_ms, r.proof_bytes,
        );
    }
    println!();
}
